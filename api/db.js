/**
 * Vercel Serverless Function: /api/db
 * Acts as a secure proxy between the frontend and Supabase.
 * Supabase URL and service key are kept server-side only via env vars.
 *
 * Supported actions (via ?action=...):
 *   GET  ?action=select&table=X&filters={}   → returns rows array
 *   POST ?action=insert&table=X              → body = row object, returns inserted row
 *   POST ?action=update&table=X&key=K&val=V  → body = patch object
 *   POST ?action=upload&bucket=B&path=P      → ADMIN ONLY. body = raw file bytes, header x-content-type
 *   GET  ?action=download&ref=OPAQUE_REF&name=FILENAME  → streams file as download
 *   POST ?action=request-submission          → { accountType, linkToken?, fileName }
 *                                               verifies account + balance server-side,
 *                                               returns a signed direct-to-Supabase upload URL
 *   POST ?action=confirm-submission          → { ticket }
 *                                               atomically decrements balance + inserts the
 *                                               submissions row, only after a real upload happened
 *
 * SECURITY:
 *   - `clients` and `resellers` hold password_hash + PII, so they are
 *     locked down: select/insert/update on them require either
 *       x-admin-token: <valid admin session token>          (full access), or
 *       x-user-token   <valid user session token>            (access to own row only)
 *   - password_hash is stripped from every select response, no matter the table,
 *     as a defense-in-depth measure (credentials should only ever move through /api/auth).
 *   - Account creation, password changes, and admin login all go through /api/auth.
 *   - Submissions can ONLY be created via request-submission + confirm-submission —
 *     direct inserts to the `submissions` table are blocked, and balance/slot checks
 *     + decrements happen server-side with optimistic-concurrency (CAS) protection so
 *     a user can never submit past their balance, even with concurrent requests.
 *   - Raw file uploads (?action=upload) are restricted to admins (used for delivering
 *     finished reports) — student/reseller submissions always go through signed URLs
 *     so large files never pass through the 4.5MB Vercel function body limit.
 */

import crypto from "crypto";
import { verifyToken, signToken, stripSensitive } from "./_lib/crypto.js";

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const SUPABASE_ANON_KEY    = process.env.SUPABASE_ANON_KEY;

const TG_BOT_TOKEN  = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID    = process.env.TELEGRAM_CHAT_ID;
// Optional second destination — a Telegram channel that gets its own,
// shorter new-submission alert. Leave unset and nothing changes for the
// existing chat; the original alert keeps going out exactly as before.
const TG_CHANNEL_ID = process.env.TELEGRAM_CHANNEL_ID;

const SENSITIVE_TABLES = ["clients", "resellers", "workers"];

async function sendTelegramAlert(message, chatId = TG_CHAT_ID) {
  if (!TG_BOT_TOKEN || !chatId) {
    console.error("Telegram alert skipped — TELEGRAM_BOT_TOKEN or a chat/channel ID is not set.");
    return;
  }
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: "HTML" }),
    });
    if (!r.ok) {
      const errBody = await r.text().catch(() => "");
      console.error("Telegram alert failed:", r.status, errBody);
    }
  } catch (e) {
    console.error("Telegram alert failed:", e.message);
  }
}

function sbHeaders(extra = {}) {
  return {
    "apikey":        SUPABASE_SERVICE_KEY,
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "Content-Type":  "application/json",
    ...extra,
  };
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-content-type,x-admin-token,x-user-token,x-worker-token");
}

function isAdmin(req) {
  const token = req.headers["x-admin-token"];
  const payload = token ? verifyToken(token) : null;
  return !!(payload && payload.role === "admin");
}

// Returns the verified { role, id } of the caller, or null
function getUserSession(req) {
  const token = req.headers["x-user-token"];
  const payload = token ? verifyToken(token) : null;
  if (!payload || !["client", "reseller"].includes(payload.role)) return null;
  return payload;
}

// Workers use their own header so a worker token can never accidentally be
// accepted anywhere a client/reseller token is expected, or vice versa.
function getWorkerSession(req) {
  const token = req.headers["x-worker-token"];
  const payload = token ? verifyToken(token) : null;
  if (!payload || payload.role !== "worker") return null;
  return payload;
}

function expectedRoleForTable(table) {
  if (table === "resellers") return "reseller";
  if (table === "workers") return "worker";
  return "client";
}

// ── SUBMISSION FLOW HELPERS ──────────────────────────────

// Resolve which account is submitting, and verify it's real — never trust the browser's claim.
async function resolveSubmitter(req, body) {
  const { accountType, linkToken } = body;

  if (accountType === "client" || accountType === "reseller") {
    const session = getUserSession(req);
    if (!session || session.role !== accountType) return null;
    const table = accountType === "reseller" ? "resellers" : "clients";
    const row = await fetchRow(table, session.id);
    if (!row || row.revoked) return null;
    return { mode: "balance", table, idField: "id", id: row.id, balanceField: "checks_balance", row };
  }

  if (accountType === "linkuser") {
    if (!linkToken) return null;
    const rows = await fetchByField("users", "token", linkToken);
    const row = rows && rows[0];
    if (!row || row.revoked || row.expired) return null;
    if (row.expiry_date && new Date(row.expiry_date) < new Date()) return null;
    return { mode: "slots", table: "users", idField: "id", id: row.id, linkToken, row };
  }

  return null;
}

// Reads the system online/offline flag + admin's custom "back at" time in
// one query, and builds the full sentence shown to users. Used to block new
// submissions server-side — the true enforcement point, since a
// client-side-only check can always be bypassed.
async function getSystemStatus() {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/settings?key=in.(online_status,offline_message)&select=key,value`, { headers: sbHeaders() });
    const rows = await r.json();
    const map = {};
    if (Array.isArray(rows)) for (const row of rows) map[row.key] = row.value;
    const backAt = map.offline_message || "shortly";
    return {
      isOnline: map.online_status !== "false", // defaults to online if never set
      offlineMessage: `We are currently offline. Please wait until we are back at ${backAt}.`,
    };
  } catch {
    return { isOnline: true, offlineMessage: "" }; // a status-check hiccup should never block submissions
  }
}

async function fetchRow(table, id) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}&select=*`, { headers: sbHeaders() });
  const data = await r.json();
  return Array.isArray(data) ? data[0] : null;
}

async function fetchByField(table, field, value) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}?${field}=eq.${encodeURIComponent(value)}&select=*`, { headers: sbHeaders() });
  const data = await r.json();
  return Array.isArray(data) ? data : null;
}

// Reads the admin-controlled price-per-check (KES) from the settings table.
// Defaults to 0 if never set or unparsable — never throws, since a pricing
// hiccup should never block a worker's submission from going through.
async function getPricePerCheck() {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/settings?key=eq.price_per_check&select=value`, { headers: sbHeaders() });
    const rows = await r.json();
    const n = Array.isArray(rows) && rows.length ? Number(rows[0].value) : 0;
    return Number.isFinite(n) ? n : 0;
  } catch { return 0; }
}

// Records one row in submission_events for the admin activity timeline.
// Fire-and-forget by design: a logging hiccup should never block or fail the
// actual claim/release/completion the worker is waiting on.
function logEvent(submissionId, workerId, event) {
  fetch(`${SUPABASE_URL}/rest/v1/submission_events`, {
    method: "POST", headers: sbHeaders({ "Prefer": "return=minimal" }),
    body: JSON.stringify({ submission_id: submissionId, worker_id: workerId, event }),
  }).catch(e => console.error(`logEvent(${event}) failed:`, e.message));
}

// Optimistic-concurrency (compare-and-swap) balance adjustment — safe against
// concurrent requests both succeeding when they shouldn't (e.g. two submissions
// racing on a balance of 1, or a balance going negative from a bad request).
async function atomicAdjustBalance(table, id, field, delta, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const row = await fetchRow(table, id);
    const current = Number(row?.[field]) || 0;
    const next = current + delta;
    if (next < 0) return { ok: false, reason: "insufficient" };
    const url = `${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}&${field}=eq.${current}`;
    const r = await fetch(url, {
      method:  "PATCH",
      headers: sbHeaders({ "Prefer": "return=representation" }),
      body:    JSON.stringify({ [field]: next }),
    });
    const data = await r.json().catch(() => []);
    if (r.ok && Array.isArray(data) && data.length > 0) {
      return { ok: true, newValue: next };
    }
    // 0 rows affected → someone else modified it between read and write; retry
  }
  return { ok: false, reason: "conflict" };
}

async function atomicDecrementBalance(table, id, field, attempts = 3) {
  return atomicAdjustBalance(table, id, field, -1, attempts);
}

// Compare-and-swap claim of a one-time access/top-up code — prevents two
// requests both successfully redeeming the same code.
async function atomicClaimAccessToken(code, usedByResellerId, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const rows = await fetchByField("access_tokens", "code", code);
    const row = rows && rows[0];
    if (!row) return { ok: false, reason: "not_found" };
    if (row.used) return { ok: false, reason: "already_used" };
    const url = `${SUPABASE_URL}/rest/v1/access_tokens?id=eq.${row.id}&used=eq.false`;
    const r = await fetch(url, {
      method:  "PATCH",
      headers: sbHeaders({ "Prefer": "return=representation" }),
      body:    JSON.stringify({ used: true, used_by: usedByResellerId, used_at: new Date().toISOString() }),
    });
    const data = await r.json().catch(() => []);
    if (r.ok && Array.isArray(data) && data.length > 0) {
      return { ok: true, checks: row.checks };
    }
    // someone else claimed it in the meantime — retry read, or fail as already_used
  }
  return { ok: false, reason: "conflict" };
}

// Same idea, but for slots_used/slots_allocated (token-link accounts)
async function atomicIncrementSlotsUsed(table, id, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const row = await fetchRow(table, id);
    const used = Number(row?.slots_used) || 0;
    const cap  = Number(row?.slots_allocated) || 0;
    if (used >= cap) return { ok: false, reason: "insufficient" };
    const url = `${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}&slots_used=eq.${used}`;
    const r = await fetch(url, {
      method:  "PATCH",
      headers: sbHeaders({ "Prefer": "return=representation" }),
      body:    JSON.stringify({ slots_used: used + 1 }),
    });
    const data = await r.json().catch(() => []);
    if (r.ok && Array.isArray(data) && data.length > 0) {
      return { ok: true, newValue: used + 1, exhausted: (used + 1) >= cap };
    }
  }
  return { ok: false, reason: "conflict" };
}

async function createSignedUploadUrl(bucket, path) {
  const r = await fetch(`${SUPABASE_URL}/storage/v1/object/upload/sign/${bucket}/${path}`, {
    method:  "POST",
    headers: sbHeaders(),
    body:    JSON.stringify({}),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.message || data.error || "Could not create upload URL");
  const relativeUrl = data.url || data.signedUrl || data.signedURL;
  if (!relativeUrl) throw new Error("Unexpected response from storage service");
  return relativeUrl.startsWith("http") ? relativeUrl : `${SUPABASE_URL}/storage/v1${relativeUrl}`;
}

async function deleteStorageObject(bucket, path) {
  try {
    await fetch(`${SUPABASE_URL}/storage/v1/object/${bucket}/${path}`, { method: "DELETE", headers: sbHeaders() });
  } catch (e) {
    console.error("Cleanup delete failed:", e.message);
  }
}

function randomId() {
  return crypto.randomBytes(12).toString("hex");
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }

  const { action, table, filters, key, val, bucket, path } = req.query;

  try {
    // ── SELECT ──────────────────────────────────────────
    if (action === "select") {
      const f = filters ? JSON.parse(filters) : {};
      const admin = isAdmin(req);

      if (SENSITIVE_TABLES.includes(table)) {
        if (!admin) {
          const session = getUserSession(req);
          const expectedRole = expectedRoleForTable(table);
          if (!session || session.role !== expectedRole || String(f.id) !== String(session.id)) {
            res.status(403).json({ error: "Forbidden" });
            return;
          }
        }
      } else if (!admin) {
        // Non-sensitive tables still need scoping, or anyone could dump every
        // submission / harvest every reseller-issued link token on the platform.
        const session = getUserSession(req);
        if (table === "submissions") {
          if (f.client_id !== undefined) {
            if (!session || session.role !== "client" || String(session.id) !== String(f.client_id)) { res.status(403).json({ error: "Forbidden" }); return; }
          } else if (f.reseller_id !== undefined) {
            if (!session || session.role !== "reseller" || String(session.id) !== String(f.reseller_id)) { res.status(403).json({ error: "Forbidden" }); return; }
          } else if (f.user_token !== undefined) {
            const rows = await fetchByField("users", "token", f.user_token);
            if (!rows || !rows[0] || rows[0].revoked) { res.status(403).json({ error: "Forbidden" }); return; }
          } else {
            res.status(403).json({ error: "Forbidden" }); return;
          }
        } else if (table === "users") {
          if (f.token !== undefined) {
            // Self-lookup by the link's own token — this token IS the credential, by design.
          } else if (f.created_by !== undefined) {
            if (!session || session.role !== "reseller" || String(session.id) !== String(f.created_by)) { res.status(403).json({ error: "Forbidden" }); return; }
          } else {
            res.status(403).json({ error: "Forbidden" }); return;
          }
        } else if (table === "access_tokens") {
          if (!session || session.role !== "reseller" || f.code === undefined) { res.status(403).json({ error: "Forbidden" }); return; }
        } else if (table === "settings") {
          // Public read — only ever exposes the online/offline status banner.
        } else {
          // Unknown non-sensitive table with no explicit rule — default-deny.
          res.status(403).json({ error: "Forbidden" }); return;
        }
      }

      let url = `${SUPABASE_URL}/rest/v1/${table}?select=*`;
      for (const [k, v] of Object.entries(f)) {
        url += `&${k}=eq.${encodeURIComponent(v)}`;
      }
      const r = await fetch(url, { headers: sbHeaders() });
      const data = await r.json();
      if (!r.ok) { res.status(r.status).json(data); return; }
      res.status(200).json(stripSensitive(data));
      return;
    }

    // ── INSERT ──────────────────────────────────────────
    if (action === "insert") {
      if (SENSITIVE_TABLES.includes(table)) {
        // Account creation (with password hashing) goes through /api/auth instead.
        res.status(403).json({ error: "Use /api/auth to create accounts" });
        return;
      }
      if (table === "submissions") {
        // Submissions must carry a server-verified balance decrement —
        // use request-submission + confirm-submission instead.
        res.status(403).json({ error: "Use request-submission / confirm-submission to create submissions" });
        return;
      }
      if (["users", "access_tokens", "settings"].includes(table) && !isAdmin(req)) {
        // Client links are created via create-client-link (verified balance decrement);
        // access_tokens and settings are admin-managed only.
        res.status(403).json({ error: "Use the appropriate action to create this record" });
        return;
      }

      const body = await readBody(req);
      const r = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
        method:  "POST",
        headers: sbHeaders({ "Prefer": "return=representation" }),
        body:    body,
      });
      const data = await r.json();
      if (!r.ok) { res.status(r.status).json(data); return; }


      res.status(200).json(stripSensitive(data));
      return;
    }

    // ── UPDATE ──────────────────────────────────────────
    if (action === "update") {
      const body = await readBody(req);
      const admin = isAdmin(req);

      if (SENSITIVE_TABLES.includes(table)) {
        if (!admin) {
          const session = getUserSession(req);
          const expectedRole = expectedRoleForTable(table);
          if (!session || session.role !== expectedRole || key !== "id" || String(val) !== String(session.id)) {
            res.status(403).json({ error: "Forbidden" });
            return;
          }
          // Non-admin users may not touch credentials/account-state/balance fields directly —
          // those go through /api/auth (change-password) or the dedicated balance-changing
          // actions (confirm-submission, create-client-link, redeem-topup-token), which apply
          // an atomic, server-verified adjustment instead of trusting a raw client-sent number.
          let patch = {};
          try { patch = JSON.parse(body); } catch { /* ignore */ }
          const blocked = ["password_hash", "revoked", "must_reset_password", "id", "email", "checks_balance"];
          if (Object.keys(patch).some(k => blocked.includes(k))) {
            res.status(403).json({ error: "Use the appropriate action to change this field" });
            return;
          }
        }
      } else if (!admin && ["submissions", "settings", "users", "access_tokens"].includes(table)) {
        // All non-admin writes to these tables now go through dedicated, verified actions:
        // confirm-submission (submissions), create-client-link/revoke-client-link (users),
        // redeem-topup-token (access_tokens). Nothing legitimate reaches this path anymore.
        res.status(403).json({ error: "Use the appropriate action to change this record" });
        return;
      }

      const url = `${SUPABASE_URL}/rest/v1/${table}?${key}=eq.${encodeURIComponent(val)}`;
      const r = await fetch(url, {
        method:  "PATCH",
        headers: sbHeaders({ "Prefer": "return=minimal" }),
        body:    body,
      });
      if (!r.ok) { const e = await r.text(); res.status(r.status).send(e); return; }
      res.status(200).json({ ok: true });
      return;
    }

    // ── MARK LINK EXHAUSTED (self-scoped by token — starts the 48hr grace timer) ──
    if (action === "mark-link-exhausted") {
      const body = JSON.parse(await readBody(req) || "{}");
      const { linkToken } = body;
      if (!linkToken) { res.status(400).json({ error: "Missing token" }); return; }

      const rows = await fetchByField("users", "token", linkToken);
      const row = rows && rows[0];
      if (!row || row.revoked) { res.status(404).json({ error: "Not found" }); return; }

      if ((row.slots_used || 0) >= (row.slots_allocated || 0) && !row.slots_exhausted_at) {
        const now = new Date().toISOString();
        await fetch(`${SUPABASE_URL}/rest/v1/users?id=eq.${row.id}`, {
          method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
          body: JSON.stringify({ slots_exhausted_at: now }),
        });
        res.status(200).json({ ok: true, slots_exhausted_at: now });
        return;
      }
      res.status(200).json({ ok: true, slots_exhausted_at: row.slots_exhausted_at || null });
      return;
    }

    // ── FLAG STALLED — client calls this once a submission has been sitting
    // unprocessed for 10+ minutes, so we can nudge the team on Telegram.
    // Re-validates the 10-minute mark server-side (never trusts the browser's
    // clock) and uses the `notified` column as an atomic, idempotent guard —
    // a PATCH filtered on notified=eq.false means only the first caller to
    // win the race actually sends the alert, no matter how many tabs/devices
    // are polling the same order.
    if (action === "flag-stalled") {
      const body = JSON.parse(await readBody(req) || "{}");
      const { id } = body;
      if (!id) { res.status(400).json({ error: "Missing id" }); return; }

      const row = await fetchRow("submissions", id);
      if (!row) { res.status(404).json({ error: "Submission not found" }); return; }

      // Hard stops — never alert on these
      if (row.status === "done") { res.status(200).json({ ok: true, skipped: "done" }); return; }
      if (row.notified)          { res.status(200).json({ ok: true, skipped: "already-notified" }); return; }

      const elapsedMs = Date.now() - new Date(row.submitted_at).getTime();

      // Too early — hasn't hit the 10-minute mark yet
      if (elapsedMs < 10 * 60 * 1000) {
        res.status(200).json({ ok: true, skipped: "too-early" }); return;
      }

      // Too old — if a submission is more than 2 hours old and still showing as
      // unprocessed it is almost certainly a historical order that completed before
      // the notified flag existed, or an orphaned row. Silently mark it notified so
      // we never alert on it again, but don't fire Telegram.
      if (elapsedMs > 2 * 60 * 60 * 1000) {
        await fetch(
          `${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(id)}&notified=eq.false`,
          { method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }), body: JSON.stringify({ notified: true }) }
        ).catch(() => {});
        res.status(200).json({ ok: true, skipped: "too-old" }); return;
      }

      // Optimistic-concurrency claim: only proceeds if we're the one flipping notified false → true.
      const claimRes = await fetch(
        `${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(id)}&notified=eq.false`,
        { method: "PATCH", headers: sbHeaders({ "Prefer": "return=representation" }), body: JSON.stringify({ notified: true }) }
      );
      const claimed = await claimRes.json().catch(() => []);
      if (!claimRes.ok || !Array.isArray(claimed) || !claimed.length) {
        res.status(200).json({ ok: true, skipped: "race-lost" }); return;
      }

      const mins = Math.floor(elapsedMs / 60000);
      const alertMsg =
        `⏰ <b>Order Running Long</b>\n` +
        `📁 File: <b>${row.file_name || "unknown"}</b>\n` +
        `🆔 Submission: <code>${id}</code>\n` +
        `⏳ Unprocessed for ${mins}+ minutes\n` +
        `👉 Please check on this order`;
      await sendTelegramAlert(alertMsg);
      if (TG_CHANNEL_ID) await sendTelegramAlert(alertMsg, TG_CHANNEL_ID);

      res.status(200).json({ ok: true, alerted: true });
      return;
    }

    // ── ADMIN REQUEST UPLOAD — signed direct-to-Supabase URL for report delivery ──
    // (avoids the raw ?action=upload path below, which still goes through this
    // Vercel function's body and hits the 4.5MB request-size limit)
    if (action === "admin-request-upload") {
      if (!isAdmin(req)) { res.status(403).json({ error: "Admin only" }); return; }
      const body = JSON.parse(await readBody(req) || "{}");
      const { bucket: reqBucket, path: reqPath } = body;
      if (!reqBucket || !reqPath) { res.status(400).json({ error: "Missing bucket or path" }); return; }
      const safePath = String(reqPath).replace(/[^a-zA-Z0-9._-]/g, "_");
      try {
        const uploadUrl = await createSignedUploadUrl(reqBucket, safePath);
        res.status(200).json({ uploadUrl, anonKey: SUPABASE_ANON_KEY, bucket: reqBucket, path: safePath });
      } catch (e) {
        res.status(500).json({ error: "Could not prepare upload. Please try again." });
      }
      return;
    }

    // ── PROXY UPLOAD — client POSTs file bytes here; server streams them to Supabase.
    // The real Supabase uploadUrl and anonKey never reach the browser.
    // The client passes the opaque `ticket` it got from request-submission so we can
    // reconstruct the destination path server-side from the signed token.
    if (action === "proxy-upload") {
      const ticket = req.headers["x-upload-ticket"] || "";
      const payload = ticket ? verifyToken(ticket) : null;
      if (!payload || payload.purpose !== "submission-ticket") {
        res.status(401).json({ error: "Upload session expired. Please try submitting again." }); return;
      }
      const { bucket, path } = payload;
      const contentType = req.headers["content-type"] || "application/octet-stream";
      // Stream the raw bytes from the client straight through to Supabase
      const uploadUrl = await createSignedUploadUrl(bucket, path);
      const fileBytes = await readRawBody(req);
      const putRes = await fetch(uploadUrl, {
        method: "PUT",
        headers: {
          "apikey":        SUPABASE_ANON_KEY,
          "Authorization": `Bearer ${SUPABASE_ANON_KEY}`,
          "Content-Type":  contentType,
        },
        body: fileBytes,
      });
      if (!putRes.ok) {
        const e = await putRes.json().catch(() => ({}));
        res.status(putRes.status).json({ error: e.error || "Upload failed. Please try again." }); return;
      }
      res.status(200).json({ ok: true });
      return;
    }

    // ── STREAM REPORT — fetches report bytes from Supabase and pipes them to the browser.
    // The Supabase signed URL never appears in the DOM or browser network panel as a
    // destination the client navigated to — it stays server-side only.
    if (action === "stream-report") {
      const ref = req.query.ref || "";
      const name = req.query.name || "report.pdf";
      const subId = req.query.subId || "";
      if (!ref) { res.status(400).end("Missing ref"); return; }
      let bkt, fpath;
      if (ref.includes("::")) { [bkt, fpath] = ref.split("::"); }
      else { res.status(400).end("Invalid ref"); return; }
      let signedUrl;
      try { signedUrl = await createSignedDownloadUrl(bkt, fpath, 120); }
      catch(e) { res.status(500).end("Could not prepare file"); return; }
      // Log downloaded_at if subId provided
      if (subId) {
        fetch(`${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(subId)}`, {
          method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
          body: JSON.stringify({ downloaded_at: new Date().toISOString() }),
        }).catch(() => {});
      }
      const fileRes = await fetch(signedUrl);
      if (!fileRes.ok) { res.status(fileRes.status).end("File not available"); return; }
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `inline; filename="${name}"`);
      res.setHeader("Cache-Control", "private, no-store");
      // Stream body through
      const reader = fileRes.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(Buffer.from(value));
      }
      res.end();
      return;
    }

    // ── UPLOAD (legacy raw path — admin only, small files only, e.g. <4.5MB) ──
    if (action === "upload") {
      if (!isAdmin(req)) {
        res.status(403).json({ error: "Use request-submission / confirm-submission to submit files" });
        return;
      }
      const contentType = req.headers["x-content-type"] || "application/octet-stream";
      const fileBytes   = await readRawBody(req);
      const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${path}`;
      const r = await fetch(url, {
        method:  "POST",
        headers: {
          "apikey":         SUPABASE_SERVICE_KEY,
          "Authorization":  `Bearer ${SUPABASE_SERVICE_KEY}`,
          "Content-Type":   contentType,
        },
        body: fileBytes,
      });
      if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        res.status(r.status).json({ error: e.error || `Upload failed ${r.status}` });
        return;
      }
      // Return an opaque ref — the real bucket/path, never a public URL
      res.status(200).json({ ref: `${bucket}::${path}` });
      return;
    }

    // ── REQUEST SUBMISSION — verify account + balance, issue a signed upload URL ──
    if (action === "request-submission") {
      const body = JSON.parse(await readBody(req) || "{}");
      const { fileName } = body;
      if (!fileName) { res.status(400).json({ error: "Missing fileName" }); return; }

      // Block new submissions while the system is set offline. This is the
      // one place every upload path (client/reseller/token-link) funnels
      // through, so checking here — not just showing a banner — is what
      // actually stops uploads rather than just discouraging them.
      const status = await getSystemStatus();
      if (!status.isOnline) { res.status(503).json({ error: status.offlineMessage, offline: true }); return; }

      const submitter = await resolveSubmitter(req, body);
      if (!submitter) { res.status(403).json({ error: "Could not verify your account. Please log in again." }); return; }

      if (submitter.mode === "balance") {
        const bal = Number(submitter.row[submitter.balanceField]) || 0;
        if (bal <= 0) { res.status(402).json({ error: "You have no checks remaining. Please top up." }); return; }
      } else {
        const used = Number(submitter.row.slots_used) || 0;
        const cap  = Number(submitter.row.slots_allocated) || 0;
        if (used >= cap) { res.status(402).json({ error: "No checks remaining on this link." }); return; }
      }

      const safeName = String(fileName).replace(/[^a-zA-Z0-9._-]/g, "_");
      const folder = submitter.mode === "slots" ? `link_${submitter.id}` : `${submitter.table}_${submitter.id}`;
      const path = `${folder}/${Date.now()}_${randomId()}_${safeName}`;
      const bucket = "submissions";

      let uploadUrl;
      try {
        uploadUrl = await createSignedUploadUrl(bucket, path);
      } catch (e) {
        res.status(500).json({ error: "Could not prepare upload. Please try again." }); return;
      }

      const ticket = signToken({
        purpose:     "submission-ticket",
        mode:        submitter.mode,
        table:       submitter.table,
        idField:     submitter.idField,
        id:          submitter.id,
        linkToken:   submitter.linkToken || null,
        bucket,
        path,
        fileName:    safeName,
      }, 60 * 10); // 10 minutes to complete the upload

      // Return only the opaque ticket — uploadUrl and anonKey stay server-side
      // so no Supabase credentials or URLs ever reach the browser.
      res.status(200).json({ ticket });
      return;
    }

    // ── CONFIRM SUBMISSION — atomically decrement balance + insert the row ──
    if (action === "confirm-submission") {
      const body = JSON.parse(await readBody(req) || "{}");
      const { ticket } = body;
      const payload = ticket ? verifyToken(ticket) : null;
      if (!payload || payload.purpose !== "submission-ticket") {
        res.status(401).json({ error: "This upload session expired. Please try submitting again." }); return;
      }

      const { mode, table, id, linkToken, bucket, path, fileName } = payload;

      let decrement;
      if (mode === "balance") {
        decrement = await atomicDecrementBalance(table, id, "checks_balance");
      } else {
        decrement = await atomicIncrementSlotsUsed(table, id);
      }

      if (!decrement.ok) {
        // Upload succeeded but balance ran out in the meantime (rare race) — clean up the orphaned file.
        await deleteStorageObject(bucket, path);
        res.status(409).json({ error: "Your balance changed before this could complete. Please refresh and try again." });
        return;
      }

      // If a token-link account just used its last slot, record exhaustion time (48hr grace period, as before)
      if (mode === "slots" && decrement.exhausted) {
        await fetch(`${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}`, {
          method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
          body: JSON.stringify({ slots_exhausted_at: new Date().toISOString() }),
        });
      }

      const submissionRow = {
        file_name:     fileName,
        file_url:      path,
        // Every fresh submission starts as "queued" so it shows up immediately
        // on both the admin board and the worker task board — no submitter type
        // is held back in a separate "pending" limbo that nothing ever promotes.
        status:        "queued",
        submitted_at:  new Date().toISOString(),
        notified:      false,
        ...(table === "clients"   ? { client_id: id }        : {}),
        ...(table === "resellers" ? { reseller_id: id }      : {}),
        ...(table === "users"     ? { user_token: linkToken } : {}),
      };

      const insRes = await fetch(`${SUPABASE_URL}/rest/v1/submissions`, {
        method: "POST", headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify(submissionRow),
      });
      const insData = await insRes.json();
      if (!insRes.ok) {
        console.error("confirm-submission insert failed:", JSON.stringify(insData));
        // Roll back the decrement we already committed, since the insert failed.
        if (mode === "balance") {
          const row = await fetchRow(table, id);
          await fetch(`${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}`, {
            method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
            body: JSON.stringify({ checks_balance: (Number(row?.checks_balance) || 0) + 1 }),
          });
        } else {
          const row = await fetchRow(table, id);
          await fetch(`${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}`, {
            method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
            body: JSON.stringify({ slots_used: Math.max(0, (Number(row?.slots_used) || 1) - 1) }),
          });
        }
        await deleteStorageObject(bucket, path);
        res.status(500).json({ error: "Could not record your submission. Please try again." });
        return;
      }

      const source = table === "clients" ? `Client ID: <code>${id}</code>`
                   : table === "resellers" ? `Reseller ID: <code>${id}</code>`
                   : `Client token: <code>${linkToken}</code>`;
      const submittedAt = new Date().toLocaleString("en-KE", { timeZone: "Africa/Nairobi" });

      // Existing chat — unchanged, full detail.
      await sendTelegramAlert(
        `📄 <b>New CheckMate Submission</b>\n` +
        `📁 File: <b>${fileName}</b>\n` +
        `👤 From: ${source}\n` +
        `🕐 Time: ${submittedAt}\n` +
        `⚡ Login to admin to process`
      );

      // Channel — shorter, no submitter identity, just the essentials.
      if (TG_CHANNEL_ID) {
        await sendTelegramAlert(
          `📄 <b>New Order Alert</b>\n` +
          `📁 File: <b>${fileName}</b>\n` +
          `🕐 Submitted: ${submittedAt}\n` +
          `⏳ Expected in 10 minutes`,
          TG_CHANNEL_ID
        );
      }

      res.status(200).json({ ok: true, ref: `${bucket}::${path}`, newValue: decrement.newValue });
      return;
    }

    // ── CREATE CLIENT LINK (reseller allocates slots from their own balance) ──
    if (action === "create-client-link") {
      const session = getUserSession(req);
      if (!session || session.role !== "reseller") { res.status(403).json({ error: "Please log in again." }); return; }

      const body = JSON.parse(await readBody(req) || "{}");
      const { name, email, slots, expiryMonths } = body;
      const slotCount = Number(slots);
      if (!name || !slotCount || slotCount < 1) { res.status(400).json({ error: "Missing or invalid fields" }); return; }

      const decrement = await atomicAdjustBalance("resellers", session.id, "checks_balance", -slotCount);
      if (!decrement.ok) {
        res.status(402).json({ error: decrement.reason === "insufficient" ? "Not enough checks in your balance." : "Please try again." });
        return;
      }

      const chars = "abcdefghijklmnopqrstuvwxyz";
      const tok = Array.from(crypto.randomBytes(12)).map(b => chars[b % chars.length]).join("");
      let expiry_date = null;
      if (expiryMonths) {
        const d = new Date();
        d.setMonth(d.getMonth() + Number(expiryMonths));
        expiry_date = d.toISOString().split("T")[0];
      }

      const insRes = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
        method: "POST", headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify({
          token: tok, name, email: email || null,
          slots_allocated: slotCount, slots_used: 0,
          revoked: false, expired: false,
          created_by: session.id, created_at: new Date().toISOString(),
          expiry_date,
        }),
      });
      const insData = await insRes.json();
      if (!insRes.ok) {
        // Roll back the decrement since we couldn't create the link
        await atomicAdjustBalance("resellers", session.id, "checks_balance", slotCount);
        res.status(500).json({ error: "Could not create link. Please try again." });
        return;
      }

      res.status(200).json({ ok: true, link: insData[0], newBalance: decrement.newValue });
      return;
    }

    // ── REDEEM TOP-UP TOKEN (reseller adds checks to their own balance) ──
    if (action === "redeem-topup-token") {
      const session = getUserSession(req);
      if (!session || session.role !== "reseller") { res.status(403).json({ error: "Please log in again." }); return; }

      const body = JSON.parse(await readBody(req) || "{}");
      const code = (body.code || "").trim().toUpperCase();
      if (!code) { res.status(400).json({ error: "Enter a token first" }); return; }

      const claim = await atomicClaimAccessToken(code, session.id);
      if (!claim.ok) {
        res.status(404).json({ error: "Invalid or already-used token." });
        return;
      }

      const credit = await atomicAdjustBalance("resellers", session.id, "checks_balance", claim.checks);
      res.status(200).json({ ok: true, checksAdded: claim.checks, newBalance: credit.newValue });
      return;
    }

    // ── REVOKE CLIENT LINK (reseller may only revoke links they created) ──
    if (action === "revoke-client-link") {
      const session = getUserSession(req);
      if (!session || session.role !== "reseller") { res.status(403).json({ error: "Please log in again." }); return; }

      const body = JSON.parse(await readBody(req) || "{}");
      const linkId = body.id;
      if (!linkId) { res.status(400).json({ error: "Missing link id" }); return; }

      const row = await fetchRow("users", linkId);
      if (!row || String(row.created_by) !== String(session.id)) {
        res.status(403).json({ error: "You can only revoke links you created." });
        return;
      }

      await fetch(`${SUPABASE_URL}/rest/v1/users?id=eq.${encodeURIComponent(linkId)}`, {
        method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
        body: JSON.stringify({ revoked: true, expired: true }),
      });
      res.status(200).json({ ok: true });
      return;
    }

async function createSignedDownloadUrl(bucket, path, expiresIn = 60) {
  const r = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${bucket}/${encodeURIComponent(path)}`, {
    method:  "POST",
    headers: sbHeaders(),
    body:    JSON.stringify({ expiresIn }),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.message || data.error || "Could not create download URL");
  const relative = data.signedUrl || data.signedURL || data.url;
  if (!relative) throw new Error("No signed URL in storage response");
  return relative.startsWith("http") ? relative : `${SUPABASE_URL}/storage/v1${relative}`;
}

    // ── SIGNED DOWNLOAD URL — returns a short-lived Supabase URL the browser
    // downloads directly, skipping the proxy-and-buffer round-trip entirely.
    // Expires in 60 s so the real URL is never permanently exposed.
    if (action === "signed-download-url") {
      const { ref, name, subId } = req.query;
      if (!ref) { res.status(400).json({ error: "Missing ref" }); return; }

      const sep   = ref.indexOf("::");
      const bkt   = ref.slice(0, sep);
      const fpath = ref.slice(sep + 2);

      let signedUrl;
      try {
        signedUrl = await createSignedDownloadUrl(bkt, fpath, 60);
      } catch(e) {
        res.status(500).json({ error: "Could not generate download link" }); return;
      }

      // Log first download (best-effort, same as the streaming action)
      if (subId && bkt === "reports") {
        fetch(
          `${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(subId)}&downloaded_at=is.null`,
          { method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }), body: JSON.stringify({ downloaded_at: new Date().toISOString() }) }
        ).catch(() => {});
      }

      res.setHeader("Cache-Control", "no-store");
      res.status(200).json({ url: signedUrl });
      return;
    }

    // ── DOWNLOAD (legacy streaming proxy — kept for backward compatibility) ──
    if (action === "download") {
      const { ref, name, subId } = req.query;
      if (!ref) { res.status(400).json({ error: "Missing ref" }); return; }

      // ref format: "bucket::path/to/file"
      const sep   = ref.indexOf("::");
      const bkt   = ref.slice(0, sep);
      const fpath = ref.slice(sep + 2);

      // Fetch directly from Supabase storage using service key
      const fileUrl = `${SUPABASE_URL}/storage/v1/object/${bkt}/${fpath}`;
      const r = await fetch(fileUrl, {
        headers: {
          "apikey":        SUPABASE_SERVICE_KEY,
          "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
        },
      });

      if (!r.ok) { res.status(r.status).json({ error: "File not found" }); return; }

      // Record the first time a client downloads a report — used by cleanup-expired
      // to give the client a grace window before the report file is deleted.
      // Best-effort: never let a logging failure block the actual download.
      if (subId && bkt === "reports") {
        fetch(
          `${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(subId)}&downloaded_at=is.null`,
          { method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }), body: JSON.stringify({ downloaded_at: new Date().toISOString() }) }
        ).catch(() => {});
      }

      // Safe filename — strip any path info so only the base filename shows
      const safeName = (name || fpath.split("/").pop()).replace(/[^a-zA-Z0-9._\- ]/g, "_");
      const contentType = r.headers.get("content-type") || "application/octet-stream";

      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
      res.setHeader("Cache-Control", "private, max-age=3600");

      // Stream the file bytes straight to the browser
      const buffer = await r.arrayBuffer();
      res.status(200).send(Buffer.from(buffer));
      return;
    }

    // ── WORKER BOARD — minimal, no client-identifying fields ever leave this endpoint ──
    const WORKER_STALE_CLAIM_MS = 14 * 60 * 1000; // 14 minutes, per business decision
const MAX_CONCURRENT_CLAIMS = 3; // a worker can hold up to 3 tasks at once

    if (action === "worker-board") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }

      // Lazily release any claim that's gone stale — runs on every poll, so no
      // separate cron/schedule is needed for this to stay (eventually) accurate.
      // Reverting status back to "queued" is what makes it reappear on the board.
      const staleCutoff = new Date(Date.now() - WORKER_STALE_CLAIM_MS).toISOString();
      const staleUrl = `${SUPABASE_URL}/rest/v1/submissions?claimed_by=not.is.null&claimed_at=lt.${encodeURIComponent(staleCutoff)}&status=eq.processing&select=id,claimed_by`;
      const staleRes = await fetch(staleUrl, { headers: sbHeaders() }).catch(() => null);
      const staleRows = staleRes && staleRes.ok ? await staleRes.json() : [];
      if (Array.isArray(staleRows) && staleRows.length) {
        await fetch(
          `${SUPABASE_URL}/rest/v1/submissions?claimed_by=not.is.null&claimed_at=lt.${encodeURIComponent(staleCutoff)}&status=eq.processing`,
          { method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }), body: JSON.stringify({ claimed_by: null, claimed_at: null, status: "queued" }) }
        ).catch(() => {});
        staleRows.forEach(row => logEvent(row.id, row.claimed_by, "forfeited"));
      }

      // "queued" is exactly what a fresh client/reseller submission starts as
      // (see confirm-submission) — so every new order is immediately visible
      // here with no manual "move to processing" step needed from admin.
      const selUrl =
        `${SUPABASE_URL}/rest/v1/submissions?status=eq.queued&claimed_by=is.null` +
        `&select=id,file_name,submitted_at&order=submitted_at.asc&limit=100`;
      const r = await fetch(selUrl, { headers: sbHeaders() });
      const rows = await r.json();
      if (!r.ok) { console.error("worker-board select failed:", JSON.stringify(rows)); res.status(500).json({ error: "Could not load the board" }); return; }

      // Rebuild the response by hand — never spread the raw row — so a future
      // column addition to `submissions` can't accidentally leak to workers.
      const board = rows.map(s => ({ id: s.id, fileName: s.file_name, submittedAt: s.submitted_at }));
      res.status(200).json({ ok: true, board });
      return;
    }

    if (action === "worker-my-order") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }

      const selUrl =
        `${SUPABASE_URL}/rest/v1/submissions?claimed_by=eq.${session.id}&status=eq.processing` +
        `&select=id,file_name,file_url,claimed_at&order=claimed_at.asc&limit=${MAX_CONCURRENT_CLAIMS}`;
      const r = await fetch(selUrl, { headers: sbHeaders() });
      const rows = await r.json();
      if (!r.ok) { console.error("worker-my-order select failed:", JSON.stringify(rows)); res.status(500).json({ error: "Could not load your orders" }); return; }

      const orders = rows.map(s => ({
        id: s.id,
        fileName: s.file_name,
        claimedAt: s.claimed_at,
        fileRef: s.file_url ? `submissions::${s.file_url}` : null,
      }));
      res.status(200).json({ ok: true, orders });
      return;
    }

    // Server-computed running total for the calling worker only — sums
    // pay_amount (already locked in at completion time, see worker-submit-report)
    // for their own completed submissions since their own last_payout_at.
    // No total, count, or amount here ever comes from the request body —
    // there is nothing for a worker to tamper with even in principle.
    if (action === "worker-earnings") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }

      const worker = await fetchRow("workers", session.id);
      const since = worker && worker.last_payout_at ? worker.last_payout_at : "1970-01-01T00:00:00.000Z";

      const selUrl =
        `${SUPABASE_URL}/rest/v1/submissions?claimed_by=eq.${session.id}&status=eq.done` +
        `&completed_at=not.is.null&completed_at=gt.${encodeURIComponent(since)}&select=pay_amount`;
      const r = await fetch(selUrl, { headers: sbHeaders() });
      const rows = await r.json();
      if (!r.ok) { console.error("worker-earnings select failed:", JSON.stringify(rows)); res.status(500).json({ error: "Could not load your earnings" }); return; }

      const total = rows.reduce((sum, s) => sum + (Number(s.pay_amount) || 0), 0);
      res.status(200).json({ ok: true, total, count: rows.length, since: worker && worker.last_payout_at ? worker.last_payout_at : null });
      return;
    }

    if (action === "worker-claim") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }

      // Cap how many a worker can hold at once — keeps a single connection/person
      // from hoarding the whole board.
      const mineUrl = `${SUPABASE_URL}/rest/v1/submissions?claimed_by=eq.${session.id}&status=eq.processing&select=id`;
      const mineRes = await fetch(mineUrl, { headers: sbHeaders() });
      const mine = await mineRes.json();
      if (Array.isArray(mine) && mine.length >= MAX_CONCURRENT_CLAIMS) {
        res.status(409).json({ error: `You already have ${MAX_CONCURRENT_CLAIMS} tasks in progress — finish or release one first.` });
        return;
      }

      const body = JSON.parse(await readBody(req) || "{}");
      const { submissionId } = body;
      if (!submissionId) { res.status(400).json({ error: "Missing submissionId" }); return; }

      // Atomic claim: the filter (status=eq.queued&claimed_by=is.null) means this
      // PATCH only takes effect if nobody else grabbed it first — no read-then-write
      // race — and moves it straight from queued to processing in the same step.
      const claimUrl =
        `${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(submissionId)}` +
        `&status=eq.queued&claimed_by=is.null`;
      const claimRes = await fetch(claimUrl, {
        method:  "PATCH",
        headers: sbHeaders({ "Prefer": "return=representation" }),
        body:    JSON.stringify({ claimed_by: session.id, claimed_at: new Date().toISOString(), status: "processing" }),
      });
      const claimed = await claimRes.json();
      if (!claimRes.ok || !Array.isArray(claimed) || !claimed.length) {
        res.status(409).json({ error: "Someone else just picked that one — try another." });
        return;
      }
      const s = claimed[0];
      logEvent(s.id, session.id, "claimed");
      res.status(200).json({
        ok: true,
        order: {
          id: s.id,
          fileName: s.file_name,
          claimedAt: s.claimed_at,
          fileRef: s.file_url ? `submissions::${s.file_url}` : null,
        },
      });
      return;
    }

    if (action === "worker-release") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }
      const body = JSON.parse(await readBody(req) || "{}");
      const { submissionId } = body;
      if (!submissionId) { res.status(400).json({ error: "Missing submissionId" }); return; }

      // Revert to "queued" (not just clearing the claim) so it reappears on
      // the board instead of vanishing into limbo.
      const releaseRes = await fetch(
        `${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(submissionId)}&claimed_by=eq.${session.id}`,
        { method: "PATCH", headers: sbHeaders({ "Prefer": "return=representation" }), body: JSON.stringify({ claimed_by: null, claimed_at: null, status: "queued" }) }
      );
      const released = await releaseRes.json();
      if (releaseRes.ok && Array.isArray(released) && released.length) {
        logEvent(submissionId, session.id, "released");
      }
      res.status(200).json({ ok: true });
      return;
    }

    // Signed upload URL for a worker's report files — same underlying storage
    // path convention admin's own report uploads use (sim_/ai_ + submission id),
    // but only for a submission that worker actually has claimed right now.
    if (action === "worker-request-upload") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }
      const body = JSON.parse(await readBody(req) || "{}");
      const { submissionId, kind } = body; // kind: "sim" | "ai"
      if (!submissionId || !["sim", "ai"].includes(kind)) { res.status(400).json({ error: "Missing/invalid fields" }); return; }

      const owns = await fetchRow("submissions", submissionId);
      if (!owns || String(owns.claimed_by) !== String(session.id)) {
        res.status(403).json({ error: "This order isn't assigned to you." }); return;
      }

      const path = `${kind}_${submissionId}_${Date.now()}.pdf`;
      try {
        const uploadUrl = await createSignedUploadUrl("reports", path);
        res.status(200).json({ uploadUrl, anonKey: SUPABASE_ANON_KEY, bucket: "reports", path });
      } catch (e) {
        console.error("worker-request-upload failed:", e.message);
        res.status(500).json({ error: "Could not prepare upload. Please try again." });
      }
      return;
    }

    if (action === "worker-submit-report") {
      const session = getWorkerSession(req);
      if (!session) { res.status(401).json({ error: "Worker session required" }); return; }
      const body = JSON.parse(await readBody(req) || "{}");
      const { submissionId, report1Path, report2Path, similarityPct, aiPct } = body;
      if (!submissionId) { res.status(400).json({ error: "Missing submissionId" }); return; }

      const owns = await fetchRow("submissions", submissionId);
      if (!owns || String(owns.claimed_by) !== String(session.id)) {
        res.status(403).json({ error: "This order isn't assigned to you." }); return;
      }

      const update = { status: "done" };
      if (report1Path) update.report1_url = `reports::${report1Path}`;
      if (report2Path) update.report2_url = `reports::${report2Path}`;
      if (similarityPct !== undefined && similarityPct !== null && similarityPct !== "") update.similarity_pct = Number(similarityPct);
      if (aiPct !== undefined && aiPct !== null && aiPct !== "") update.ai_pct = Number(aiPct);
      // claimed_by is intentionally left in place — it's the audit trail of who did the work.

      // Mark the moment a submission has BOTH the plagiarism and AI reports on
      // file — this is what powers the admin's worker-completions tally. Only
      // set once, the first time both are present, so re-editing a submission
      // later never double-counts it or resets its completion time.
      const hasReport1 = !!(report1Path || owns.report1_url);
      const hasReport2 = !!(report2Path || owns.report2_url);
      if (hasReport1 && hasReport2 && !owns.completed_at) {
        update.completed_at = new Date().toISOString();
        // Snapshot what this submission is worth in KES right now — set
        // server-side only, from the admin-controlled settings row, never
        // from anything the worker's request could influence. Locking it in
        // at completion time means a later price change never rewrites what
        // a worker already earned for past work.
        update.pay_amount = await getPricePerCheck();
      }

      const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/submissions?id=eq.${encodeURIComponent(submissionId)}`, {
        method: "PATCH", headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify(update),
      });
      const patched = await patchRes.json();
      if (!patchRes.ok || !Array.isArray(patched) || !patched.length) {
        console.error("worker-submit-report failed:", JSON.stringify(patched));
        res.status(500).json({ error: "Could not save your submission. Please try again." });
        return;
      }
      if (update.completed_at) logEvent(submissionId, session.id, "completed");
      res.status(200).json({ ok: true });
      return;
    }

    res.status(400).json({ error: "Unknown action" });

  } catch (err) {
    console.error("API proxy error:", err);
    res.status(500).json({ error: err.message });
  }
}

// ── Body readers ────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => data += chunk);
    req.on("end",  () => resolve(data));
    req.on("error", reject);
  });
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", chunk => chunks.push(chunk));
    req.on("end",  () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
