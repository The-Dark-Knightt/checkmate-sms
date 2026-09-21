/**
 * Vercel Serverless Function: /api/v1
 * Public, key-authenticated API for CLIENT WEBSITES to submit documents to
 * CheckMate and retrieve their similarity/AI reports programmatically —
 * completely separate from the browser dashboard flow in api/db.js.
 *
 * AUTH
 *   Every request must carry the client's API key, either as:
 *     x-api-key: cmk_live_...
 *   or:
 *     Authorization: Bearer cmk_live_...
 *   Keys are issued (and can be rotated) by the admin only, via
 *   api/auth.js?action=admin-generate-api-key. Only a sha256 hash of the
 *   key is ever stored — the plaintext is shown once, at generation time.
 *
 * ACTIONS
 *   GET  ?action=account
 *        → { ok, name, checksRemaining }
 *
 *   POST ?action=submit&fileName=essay.docx
 *        headers: x-api-key, x-content-type (optional, defaults to
 *                 application/octet-stream)
 *        body:    raw file bytes (PDF/DOC/DOCX)
 *        → { ok, submissionId, status:"queued", checksRemaining }
 *        Note: request bodies are capped by Vercel's serverless function
 *        limit (~4.5MB on Hobby/Pro). Large files should be compressed or
 *        split before sending.
 *
 *   GET  ?action=status&id=123
 *        → { ok, id, fileName, status, similarityPct, aiPct,
 *             submittedAt, completedAt, reportsReady }
 *        status is one of: "queued" | "processing" | "completed"
 *
 *   GET  ?action=report&id=123&type=similarity   (or type=ai)
 *        → streams the report PDF directly (only once status is "completed")
 *
 * Every action checks the API key belongs to the client that owns the
 * submission being looked up — one client's key can never see another
 * client's rows, submission IDs included.
 */

import crypto from "crypto";

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-api-key,x-content-type,Authorization");
}

function hashApiKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

function randomId() {
  return crypto.randomBytes(12).toString("hex");
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

// Verifies the x-api-key / Authorization header and returns the owning
// client row, or null. The prefix lookup keeps this a single indexed query
// instead of scanning every client's hash; the real check is the sha256
// comparison against api_key_hash (compared with timingSafeEqual).
async function authenticateClient(req) {
  const header = req.headers["x-api-key"] || req.headers["authorization"] || "";
  const key = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (!key || !key.startsWith("cmk_")) return null;

  const prefix = key.slice(0, 16);
  const rows = await fetchByField("clients", "api_key_prefix", prefix);
  const row = rows && rows[0];
  if (!row || !row.api_enabled || !row.api_key_hash || row.revoked) return null;

  const provided = Buffer.from(hashApiKey(key));
  const stored   = Buffer.from(row.api_key_hash);
  if (provided.length !== stored.length || !crypto.timingSafeEqual(provided, stored)) return null;

  return row;
}

async function getSystemStatus() {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/settings?key=in.(online_status,offline_message)&select=key,value`, { headers: sbHeaders() });
    const rows = await r.json();
    const map = {};
    if (Array.isArray(rows)) for (const row of rows) map[row.key] = row.value;
    const backAt = map.offline_message || "shortly";
    return {
      isOnline: map.online_status !== "false",
      offlineMessage: `We are currently offline. Please wait until we are back at ${backAt}.`,
    };
  } catch {
    return { isOnline: true, offlineMessage: "" };
  }
}

// Same compare-and-swap pattern used by the dashboard flow in api/db.js —
// keeps a client's balance from ever going negative under concurrent calls.
async function atomicDecrementBalance(table, id, field, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const row = await fetchRow(table, id);
    const current = Number(row?.[field]) || 0;
    const next = current - 1;
    if (next < 0) return { ok: false, reason: "insufficient" };
    const url = `${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}&${field}=eq.${current}`;
    const r = await fetch(url, {
      method:  "PATCH",
      headers: sbHeaders({ "Prefer": "return=representation" }),
      body:    JSON.stringify({ [field]: next }),
    });
    const data = await r.json().catch(() => []);
    if (r.ok && Array.isArray(data) && data.length > 0) return { ok: true, newValue: next };
  }
  return { ok: false, reason: "conflict" };
}

async function refundBalance(table, id, field) {
  const row = await fetchRow(table, id);
  await fetch(`${SUPABASE_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}`, {
    method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
    body: JSON.stringify({ [field]: (Number(row?.[field]) || 0) + 1 }),
  });
}

function mapStatus(dbStatus) {
  if (dbStatus === "done") return "completed";
  if (dbStatus === "processing") return "processing";
  return "queued";
}

async function sendTelegramAlert(message) {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: TG_CHAT_ID, text: message, parse_mode: "HTML" }),
    });
  } catch (e) {
    console.error("Telegram alert failed:", e.message);
  }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", chunk => chunks.push(chunk));
    req.on("end",  () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }

  const { action } = req.query;

  try {
    // ── ACCOUNT — quick key check + balance ──────────────
    if (action === "account") {
      const client = await authenticateClient(req);
      if (!client) { res.status(401).json({ error: "Invalid or revoked API key." }); return; }
      res.status(200).json({ ok: true, name: client.name, checksRemaining: Number(client.checks_balance) || 0 });
      return;
    }

    // ── SUBMIT — upload a file, decrement balance, queue it ──
    if (action === "submit") {
      if (req.method !== "POST") { res.status(405).json({ error: "Use POST for submissions." }); return; }
      const client = await authenticateClient(req);
      if (!client) { res.status(401).json({ error: "Invalid or revoked API key." }); return; }

      const status = await getSystemStatus();
      if (!status.isOnline) { res.status(503).json({ error: status.offlineMessage, offline: true }); return; }

      const fileName = req.query.fileName;
      if (!fileName) { res.status(400).json({ error: "Missing fileName query parameter." }); return; }

      const bal = Number(client.checks_balance) || 0;
      if (bal <= 0) { res.status(402).json({ error: "No checks remaining on this account. Please top up." }); return; }

      const safeName = String(fileName).replace(/[^a-zA-Z0-9._-]/g, "_");
      const path = `api_${client.id}/${Date.now()}_${randomId()}_${safeName}`;
      const contentType = req.headers["x-content-type"] || "application/octet-stream";
      const fileBytes = await readRawBody(req);
      if (!fileBytes || !fileBytes.length) { res.status(400).json({ error: "Empty file body." }); return; }

      const upRes = await fetch(`${SUPABASE_URL}/storage/v1/object/submissions/${path}`, {
        method:  "POST",
        headers: {
          "apikey":        SUPABASE_SERVICE_KEY,
          "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
          "Content-Type":  contentType,
        },
        body: fileBytes,
      });
      if (!upRes.ok) {
        const e = await upRes.json().catch(() => ({}));
        res.status(500).json({ error: e.error || "Upload failed. Please try again." });
        return;
      }

      const decrement = await atomicDecrementBalance("clients", client.id, "checks_balance");
      if (!decrement.ok) {
        await fetch(`${SUPABASE_URL}/storage/v1/object/submissions/${path}`, { method: "DELETE", headers: sbHeaders() }).catch(() => {});
        res.status(402).json({ error: "No checks remaining on this account. Please top up." });
        return;
      }

      const insRes = await fetch(`${SUPABASE_URL}/rest/v1/submissions`, {
        method: "POST", headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify({
          file_name:    safeName,
          file_url:     path,
          status:       "queued",
          submitted_at: new Date().toISOString(),
          notified:     false,
          client_id:    client.id,
          source:       "api",
        }),
      });
      const insData = await insRes.json();
      if (!insRes.ok) {
        await refundBalance("clients", client.id, "checks_balance");
        await fetch(`${SUPABASE_URL}/storage/v1/object/submissions/${path}`, { method: "DELETE", headers: sbHeaders() }).catch(() => {});
        res.status(500).json({ error: "Could not record your submission. Please try again." });
        return;
      }
      const row = Array.isArray(insData) ? insData[0] : insData;

      sendTelegramAlert(
        `📄 <b>New API Submission</b>\n` +
        `📁 File: <b>${safeName}</b>\n` +
        `🔑 Client: ${client.name} (API)\n` +
        `🕐 Time: ${new Date().toLocaleString("en-KE", { timeZone: "Africa/Nairobi" })}`
      );

      res.status(200).json({
        ok: true,
        submissionId:    row.id,
        status:          "queued",
        checksRemaining: decrement.newValue,
      });
      return;
    }

    // ── STATUS — poll a submission ────────────────────────
    if (action === "status") {
      const client = await authenticateClient(req);
      if (!client) { res.status(401).json({ error: "Invalid or revoked API key." }); return; }

      const id = req.query.id;
      if (!id) { res.status(400).json({ error: "Missing id query parameter." }); return; }

      const row = await fetchRow("submissions", id);
      if (!row || String(row.client_id) !== String(client.id)) {
        res.status(404).json({ error: "No submission with that ID on this account." }); return;
      }

      res.status(200).json({
        ok:             true,
        id:             row.id,
        fileName:       row.file_name,
        status:         mapStatus(row.status),
        similarityPct:  row.similarity_pct ?? null,
        aiPct:          row.ai_pct ?? null,
        submittedAt:    row.submitted_at,
        completedAt:    row.completed_at || null,
        reportsReady:   !!(row.report1_url && row.report2_url),
      });
      return;
    }

    // ── REPORT — download a finished report PDF ───────────
    if (action === "report") {
      const client = await authenticateClient(req);
      if (!client) { res.status(401).json({ error: "Invalid or revoked API key." }); return; }

      const id = req.query.id;
      const type = req.query.type; // "similarity" | "ai"
      if (!id || !["similarity", "ai"].includes(type)) {
        res.status(400).json({ error: "Missing/invalid id or type (must be 'similarity' or 'ai')." }); return;
      }

      const row = await fetchRow("submissions", id);
      if (!row || String(row.client_id) !== String(client.id)) {
        res.status(404).json({ error: "No submission with that ID on this account." }); return;
      }

      const ref = type === "similarity" ? row.report1_url : row.report2_url;
      if (!ref) { res.status(409).json({ error: "That report isn't ready yet. Poll ?action=status until reportsReady is true." }); return; }

      const sep = ref.indexOf("::");
      const bkt = sep === -1 ? "reports" : ref.slice(0, sep);
      const fpath = sep === -1 ? ref : ref.slice(sep + 2);

      const fileRes = await fetch(`${SUPABASE_URL}/storage/v1/object/${bkt}/${fpath}`, {
        headers: { "apikey": SUPABASE_SERVICE_KEY, "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}` },
      });
      if (!fileRes.ok) { res.status(502).json({ error: "Report file not available right now." }); return; }

      const buffer = await fileRes.arrayBuffer();
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${type}_${id}.pdf"`);
      res.setHeader("Cache-Control", "private, no-store");
      res.status(200).send(Buffer.from(buffer));
      return;
    }

    res.status(400).json({ error: "Unknown action. See api/v1.js header comment for the supported actions." });

  } catch (err) {
    console.error("Public API error:", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
}

export const config = {
  api: { bodyParser: false }, // we read raw bytes ourselves for ?action=submit
};
