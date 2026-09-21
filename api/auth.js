/**
 * Vercel Serverless Function: /api/auth
 * All password handling lives here — passwords are NEVER sent to the
 * browser, and the public /api/db proxy refuses to return password_hash
 * or to let anyone read/write the clients & resellers tables without
 * a verified session.
 *
 * Actions (POST, JSON body):
 *   action=login              { email, password }
 *   action=signup             { name, email, phone, password }
 *   action=complete-reset     { role, id, resetToken, newPassword }
 *   action=change-password    { role, id, token, currentPassword, newPassword }
 *   action=admin-login        { password }
 *   action=forgot-password    { email }                          (clients only)
 *   action=reset-password     { resetToken, newPassword }         (clients only)
 */

import crypto from "crypto";
import { hashPassword, verifyPassword, signToken, verifyToken, stripSensitive } from "./_lib/crypto.js";

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_PANEL_PASSWORD = process.env.ADMIN_PANEL_PASSWORD; // separate from ADMIN_SECRET (which only signs tokens)
const RESEND_API_KEY       = process.env.RESEND_API_KEY;       // Resend.com — sends password-reset emails
const RESET_FROM_EMAIL     = process.env.RESET_FROM_EMAIL || "CheckMate <onboarding@resend.dev>";
const RESET_BASE_URL       = process.env.RESET_BASE_URL || "https://checkmate.co.ke";
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID;     // must match the client_id used in login.html

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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

async function findByEmail(table, email) {
  const url = `${SUPABASE_URL}/rest/v1/${table}?select=*&email=eq.${encodeURIComponent(email)}`;
  const r = await fetch(url, { headers: sbHeaders() });
  const rows = await r.json();
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function findByField(table, field, value) {
  const url = `${SUPABASE_URL}/rest/v1/${table}?select=*&${field}=eq.${encodeURIComponent(value)}`;
  const r = await fetch(url, { headers: sbHeaders() });
  const rows = await r.json();
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function findById(table, id) {
  const url = `${SUPABASE_URL}/rest/v1/${table}?select=*&id=eq.${encodeURIComponent(id)}`;
  const r = await fetch(url, { headers: sbHeaders() });
  const rows = await r.json();
  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function patchRow(table, id, patch) {
  await fetch(`${SUPABASE_URL}/rest/v1/${table}?id=eq.${id}`, {
    method:  "PATCH",
    headers: sbHeaders({ "Prefer": "return=minimal" }),
    body:    JSON.stringify(patch),
  });
}

function sessionPayload(role, row) {
  return { role, id: row.id };
}

// ── API key generation (for clients.api_key_hash / api_key_prefix) ──
// API keys are already high-entropy random values (not human-chosen
// passwords), so a plain sha256 is appropriate here — unlike scrypt for
// passwords, there's no need to slow down a lookup on every API request.
// Format: cmk_live_<32 hex chars>. The first 12 characters (incl. prefix)
// are stored in the clear as `api_key_prefix` purely so the DB can find the
// right row fast; the full key is never stored, only its hash.
function generateApiKey() {
  const raw = crypto.randomBytes(24).toString("hex");
  const full = `cmk_live_${raw}`;
  return { full, prefix: full.slice(0, 16) };
}
function hashApiKey(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}

// ── Admin login brute-force lockout (state stored in the `settings` table) ──
const LOCKOUT_KEY          = "admin_login_lockout";
const LOCKOUT_MAX_FAILS    = 5;
const LOCKOUT_DURATION_MS  = 15 * 60 * 1000; // 15 minutes

async function getLockoutState() {
  const url = `${SUPABASE_URL}/rest/v1/settings?key=eq.${LOCKOUT_KEY}&select=value`;
  const r = await fetch(url, { headers: sbHeaders() });
  const rows = await r.json();
  if (!Array.isArray(rows) || !rows.length) return { fails: 0, lockedUntil: 0 };
  try { return JSON.parse(rows[0].value); } catch { return { fails: 0, lockedUntil: 0 }; }
}

async function setLockoutState(state) {
  const existing = await fetch(`${SUPABASE_URL}/rest/v1/settings?key=eq.${LOCKOUT_KEY}&select=key`, { headers: sbHeaders() });
  const rows = await existing.json();
  const value = JSON.stringify(state);
  if (Array.isArray(rows) && rows.length) {
    await fetch(`${SUPABASE_URL}/rest/v1/settings?key=eq.${LOCKOUT_KEY}`, {
      method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
      body: JSON.stringify({ value }),
    });
  } else {
    await fetch(`${SUPABASE_URL}/rest/v1/settings`, {
      method: "POST", headers: sbHeaders({ "Prefer": "return=minimal" }),
      body: JSON.stringify({ key: LOCKOUT_KEY, value }),
    });
  }
}

// ── Per-account brute-force lockout — same mechanism as above, but keyed to
// a specific role+identifier (e.g. a single client email or worker username)
// instead of one global key. This means a flood of bad guesses against one
// account locks only that account out, not every admin/client/worker at once,
// while still stopping password-guessing attacks against client, reseller,
// and worker accounts the same way admin login has always been protected. ──
const ACCOUNT_LOCKOUT_MAX_FAILS   = 5;
const ACCOUNT_LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

function accountLockoutKey(role, identifier) {
  // Settings keys are plain strings — normalize so casing/whitespace can't be
  // used to dodge the lockout (e.g. "Bob@x.com " vs "bob@x.com").
  return `login_lockout:${role}:${String(identifier).trim().toLowerCase()}`;
}

async function getAccountLockoutState(role, identifier) {
  const key = accountLockoutKey(role, identifier);
  const url = `${SUPABASE_URL}/rest/v1/settings?key=eq.${encodeURIComponent(key)}&select=value`;
  const r = await fetch(url, { headers: sbHeaders() });
  const rows = await r.json();
  if (!Array.isArray(rows) || !rows.length) return { fails: 0, lockedUntil: 0 };
  try { return JSON.parse(rows[0].value); } catch { return { fails: 0, lockedUntil: 0 }; }
}

async function setAccountLockoutState(role, identifier, state) {
  const key = accountLockoutKey(role, identifier);
  const existing = await fetch(`${SUPABASE_URL}/rest/v1/settings?key=eq.${encodeURIComponent(key)}&select=key`, { headers: sbHeaders() });
  const rows = await existing.json();
  const value = JSON.stringify(state);
  if (Array.isArray(rows) && rows.length) {
    await fetch(`${SUPABASE_URL}/rest/v1/settings?key=eq.${encodeURIComponent(key)}`, {
      method: "PATCH", headers: sbHeaders({ "Prefer": "return=minimal" }),
      body: JSON.stringify({ value }),
    });
  } else {
    await fetch(`${SUPABASE_URL}/rest/v1/settings`, {
      method: "POST", headers: sbHeaders({ "Prefer": "return=minimal" }),
      body: JSON.stringify({ key, value }),
    });
  }
}

// Call before checking the password. Returns a res-already-sent boolean.
async function rejectIfLockedOut(res, role, identifier) {
  const state = await getAccountLockoutState(role, identifier);
  if (state.lockedUntil && state.lockedUntil > Date.now()) {
    const minsLeft = Math.ceil((state.lockedUntil - Date.now()) / 60000);
    res.status(429).json({ error: `Too many failed attempts. Try again in ${minsLeft} minute${minsLeft === 1 ? "" : "s"}.` });
    return true;
  }
  return false;
}

// Call after a failed password check.
async function recordFailedAttempt(role, identifier) {
  const state = await getAccountLockoutState(role, identifier);
  const fails = (state.lockedUntil && state.lockedUntil <= Date.now() ? 0 : state.fails || 0) + 1;
  const newState = fails >= ACCOUNT_LOCKOUT_MAX_FAILS
    ? { fails: 0, lockedUntil: Date.now() + ACCOUNT_LOCKOUT_DURATION_MS }
    : { fails, lockedUntil: 0 };
  await setAccountLockoutState(role, identifier, newState);
}

// Call after a successful login, to clear any accumulated fails.
async function clearFailedAttempts(role, identifier) {
  await setAccountLockoutState(role, identifier, { fails: 0, lockedUntil: 0 });
}

function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    // Still run a comparison of equal length to avoid leaking length via timing
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

async function sendResetEmail(to, name, resetUrl) {
  if (!RESEND_API_KEY) {
    console.error("RESEND_API_KEY not set — cannot send password reset email");
    return false;
  }
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type":  "application/json",
      },
      body: JSON.stringify({
        from:    RESET_FROM_EMAIL,
        to,
        subject: "Reset your CheckMate password",
        html: `
          <div style="font-family:sans-serif;max-width:480px;margin:0 auto">
            <h2 style="color:#0f1f45">Reset your password</h2>
            <p>Hi ${name || "there"},</p>
            <p>We received a request to reset the password on your CheckMate account. Click the button below to set a new one. This link expires in 30 minutes.</p>
            <p style="margin:28px 0">
              <a href="${resetUrl}" style="background:#c0192c;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">Reset Password</a>
            </p>
            <p style="color:#6b7a99;font-size:13px">If you didn't request this, you can safely ignore this email — your password will stay the same.</p>
            <p style="color:#6b7a99;font-size:12px;word-break:break-all">Or paste this link into your browser: ${resetUrl}</p>
          </div>
        `,
      }),
    });
    if (!r.ok) {
      console.error("Resend send failed:", await r.text());
      return false;
    }
    return true;
  } catch (e) {
    console.error("Resend send error:", e.message);
    return false;
  }
}

// Verifies a Google ID token server-side (never trust a credential the
// browser claims is valid). Uses Google's tokeninfo endpoint rather than
// pulling in a JWKS/JWT-verification library — one extra HTTP call, no
// new dependency. Returns the decoded payload or null.
async function verifyGoogleIdToken(credential) {
  if (!credential) return null;
  try {
    const r = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
    if (!r.ok) return null;
    const payload = await r.json();
    if (!payload || payload.aud !== GOOGLE_CLIENT_ID) return null; // wrong app
    if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") return null;
    if (payload.email_verified !== "true" && payload.email_verified !== true) return null;
    return payload; // { email, name, sub, ... }
  } catch (e) {
    console.error("Google token verification error:", e.message);
    return null;
  }
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }

  const { action } = req.query;

  // ── GOOGLE CONFIG (public, read-only) ──
  // Lets login.html pick up the Client ID from the server instead of having
  // it pasted into the HTML — set GOOGLE_CLIENT_ID in Vercel and it just
  // starts working, nothing to edit or redeploy in the frontend file.
  if (action === "google-config") {
    if (req.method !== "GET") { res.status(405).json({ error: "Method not allowed" }); return; }
    res.status(200).json({ clientId: GOOGLE_CLIENT_ID || null });
    return;
  }

  if (req.method !== "POST") { res.status(405).json({ error: "Method not allowed" }); return; }

  let body;
  try { body = JSON.parse(await readBody(req)); } catch { body = {}; }

  try {
    // ── ADMIN LOGIN ─────────────────────────────────────
    if (action === "admin-login") {
      const { password } = body;
      if (!ADMIN_PANEL_PASSWORD) {
        res.status(500).json({ error: "Admin panel password not configured on server (set ADMIN_PANEL_PASSWORD env var)" });
        return;
      }

      const state = await getLockoutState();
      if (state.lockedUntil && state.lockedUntil > Date.now()) {
        const minsLeft = Math.ceil((state.lockedUntil - Date.now()) / 60000);
        res.status(429).json({ error: `Too many failed attempts. Try again in ${minsLeft} minute${minsLeft === 1 ? "" : "s"}.` });
        return;
      }

      if (!password || !timingSafeStringEqual(password, ADMIN_PANEL_PASSWORD)) {
        const fails = (state.lockedUntil && state.lockedUntil <= Date.now() ? 0 : state.fails || 0) + 1;
        const newState = fails >= LOCKOUT_MAX_FAILS
          ? { fails: 0, lockedUntil: Date.now() + LOCKOUT_DURATION_MS }
          : { fails, lockedUntil: 0 };
        await setLockoutState(newState);
        res.status(401).json({ error: "Incorrect password" });
        return;
      }

      await setLockoutState({ fails: 0, lockedUntil: 0 });
      const token = signToken({ role: "admin" }, 60 * 60 * 12); // 12h
      res.status(200).json({ ok: true, token });
      return;
    }

    // ── LOGIN (client or reseller) ─────────────────────
    if (action === "login") {
      const { email, password } = body;
      if (!email || !password) { res.status(400).json({ error: "Email and password required" }); return; }

      if (await rejectIfLockedOut(res, "client-reseller", email)) return;

      let role = "reseller";
      let row  = await findByEmail("resellers", email);
      if (!row) { role = "client"; row = await findByEmail("clients", email); }
      if (!row) { await recordFailedAttempt("client-reseller", email); res.status(404).json({ error: "No account found with that email." }); return; }

      const { ok, isLegacyPlaintext } = verifyPassword(password, row.password_hash);
      if (!ok) { await recordFailedAttempt("client-reseller", email); res.status(401).json({ error: "Incorrect password." }); return; }
      if (row.revoked) { res.status(403).json({ error: "Your account has been suspended. Contact support." }); return; }

      await clearFailedAttempts("client-reseller", email);
      const table = role === "reseller" ? "resellers" : "clients";

      // Force-reset check (set must_reset_password = true on rows you want to force)
      if (row.must_reset_password) {
        const resetToken = signToken({ role, id: row.id, purpose: "reset" }, 60 * 15); // 15 min
        res.status(200).json({ requiresReset: true, role, id: row.id, resetToken });
        return;
      }

      // Migrate legacy plaintext passwords to a real hash transparently
      if (isLegacyPlaintext) {
        await patchRow(table, row.id, { password_hash: hashPassword(password) });
      }

      const token = signToken(sessionPayload(role, row), 60 * 60 * 24 * 7); // 7 days
      const safeUser = stripSensitive(row);
      res.status(200).json({ ok: true, role, token, user: safeUser });
      return;
    }

    // ── COMPLETE FORCED RESET ──────────────────────────
    if (action === "complete-reset") {
      const { role, id, resetToken, newPassword } = body;
      if (!role || !id || !resetToken || !newPassword) { res.status(400).json({ error: "Missing fields" }); return; }
      if (newPassword.length < 8) { res.status(400).json({ error: "Password must be at least 8 characters." }); return; }

      const payload = verifyToken(resetToken);
      if (!payload || payload.purpose !== "reset" || payload.role !== role || String(payload.id) !== String(id)) {
        res.status(401).json({ error: "Reset link expired. Please log in again." }); return;
      }

      const table = role === "reseller" ? "resellers" : role === "worker" ? "workers" : "clients";
      const row = await findById(table, id);
      if (!row) { res.status(404).json({ error: "Account not found" }); return; }

      await patchRow(table, id, { password_hash: hashPassword(newPassword), must_reset_password: false });

      const token = signToken(sessionPayload(role, row), 60 * 60 * 24 * 7);
      const safeUser = stripSensitive({ ...row, password_hash: undefined, must_reset_password: false });
      res.status(200).json({ ok: true, role, token, user: safeUser });
      return;
    }

    // ── FORGOT PASSWORD (clients only) — request a reset link ──
    if (action === "forgot-password") {
      const { email } = body;
      const genericMsg = { ok: true, message: "If an account exists with that email, a reset link has been sent." };

      if (!email) { res.status(200).json(genericMsg); return; }

      const row = await findByEmail("clients", email);
      if (row && !row.revoked) {
        const resetToken = signToken({ role: "client", id: row.id, purpose: "self-reset" }, 60 * 30); // 30 min
        const resetUrl = `${RESET_BASE_URL}/login.html?reset=${encodeURIComponent(resetToken)}`;
        await sendResetEmail(row.email, row.name, resetUrl);
      }
      // Always return the same response — don't reveal whether the email exists
      res.status(200).json(genericMsg);
      return;
    }

    // ── RESET PASSWORD (clients only) — via emailed link ────
    if (action === "reset-password") {
      const { resetToken, newPassword } = body;
      if (!resetToken || !newPassword) { res.status(400).json({ error: "Missing fields" }); return; }
      if (newPassword.length < 8) { res.status(400).json({ error: "Password must be at least 8 characters." }); return; }

      const payload = verifyToken(resetToken);
      if (!payload || payload.purpose !== "self-reset" || payload.role !== "client") {
        res.status(401).json({ error: "This reset link has expired. Please request a new one." }); return;
      }

      const row = await findById("clients", payload.id);
      if (!row) { res.status(404).json({ error: "Account not found" }); return; }
      if (row.revoked) { res.status(403).json({ error: "Your account has been suspended. Contact support." }); return; }

      await patchRow("clients", row.id, { password_hash: hashPassword(newPassword), must_reset_password: false });

      const token = signToken(sessionPayload("client", row), 60 * 60 * 24 * 7);
      const safeUser = stripSensitive({ ...row, must_reset_password: false });
      res.status(200).json({ ok: true, role: "client", token, user: safeUser });
      return;
    }

    // ── CHANGE PASSWORD (logged-in user) ───────────────
    if (action === "change-password") {
      const { role, id, token, currentPassword, newPassword } = body;
      if (!role || !id || !token || !currentPassword || !newPassword) { res.status(400).json({ error: "Missing fields" }); return; }
      if (newPassword.length < 8) { res.status(400).json({ error: "New password must be at least 8 characters." }); return; }

      const payload = verifyToken(token);
      if (!payload || payload.role !== role || String(payload.id) !== String(id)) {
        res.status(401).json({ error: "Session expired. Please log in again." }); return;
      }

      const table = role === "reseller" ? "resellers" : "clients";
      const row = await findById(table, id);
      if (!row) { res.status(404).json({ error: "Account not found" }); return; }

      const { ok } = verifyPassword(currentPassword, row.password_hash);
      if (!ok) { res.status(401).json({ error: "Current password is incorrect." }); return; }

      await patchRow(table, id, { password_hash: hashPassword(newPassword) });
      res.status(200).json({ ok: true });
      return;
    }

    // ── GOOGLE LOGIN / SIGNUP (client accounts only) ────
    // Matches an existing client by email, or creates one on first sign-in.
    // Reseller and admin accounts are never created or matched this way.
    if (action === "google-login") {
      if (!GOOGLE_CLIENT_ID) { res.status(500).json({ error: "Google sign-in is not configured on the server (set GOOGLE_CLIENT_ID env var)." }); return; }
      const { credential } = body;
      const payload = await verifyGoogleIdToken(credential);
      if (!payload) { res.status(401).json({ error: "Could not verify Google sign-in. Please try again." }); return; }

      const email = payload.email;
      const name  = payload.name || email.split("@")[0];

      // A reseller signing in with a Google account tied to their reseller
      // email should still land in their reseller account, not a new client one.
      const resellerRow = await findByEmail("resellers", email);
      if (resellerRow) {
        if (resellerRow.revoked) { res.status(403).json({ error: "Your account has been suspended. Contact support." }); return; }
        const token = signToken(sessionPayload("reseller", resellerRow), 60 * 60 * 24 * 7);
        res.status(200).json({ ok: true, role: "reseller", token, user: stripSensitive(resellerRow) });
        return;
      }

      let row = await findByEmail("clients", email);
      if (row) {
        if (row.revoked) { res.status(403).json({ error: "Your account has been suspended. Contact support." }); return; }
      } else {
        const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/clients`, {
          method:  "POST",
          headers: sbHeaders({ "Prefer": "return=representation" }),
          body: JSON.stringify({
            name,
            email,
            phone: "",
            password_hash: hashPassword(crypto.randomUUID()), // unusable random password — this account only ever signs in via Google
            checks_balance: 0,
            revoked: false,
            must_reset_password: false,
            created_at: new Date().toISOString(),
          }),
        });
        const inserted = await insertRes.json();
        if (!insertRes.ok) { res.status(insertRes.status).json(inserted); return; }
        row = Array.isArray(inserted) ? inserted[0] : inserted;
      }

      const token = signToken(sessionPayload("client", row), 60 * 60 * 24 * 7);
      res.status(200).json({ ok: true, role: "client", token, user: stripSensitive(row) });
      return;
    }

    // ── SIGNUP (client accounts only) ──────────────────
    if (action === "signup") {
      const { name, email, phone, password } = body;
      if (!name || !email || !phone || !password) { res.status(400).json({ error: "Missing fields" }); return; }
      if (password.length < 8) { res.status(400).json({ error: "Password must be at least 8 characters." }); return; }
      if (!/^\+\d{7,15}$/.test(phone)) { res.status(400).json({ error: "Enter a valid phone number." }); return; }

      const existing = await findByEmail("clients", email);
      if (existing) { res.status(409).json({ error: "An account with that email already exists. Sign in instead." }); return; }

      const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/clients`, {
        method:  "POST",
        headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify({
          name,
          email,
          phone,
          password_hash: hashPassword(password),
          checks_balance: 0,
          revoked: false,
          must_reset_password: false,
          created_at: new Date().toISOString(),
        }),
      });
      const inserted = await insertRes.json();
      if (!insertRes.ok) { res.status(insertRes.status).json(inserted); return; }
      const row = Array.isArray(inserted) ? inserted[0] : inserted;

      const token = signToken(sessionPayload("client", row), 60 * 60 * 24 * 7);
      res.status(200).json({ ok: true, role: "client", token, user: stripSensitive(row) });
      return;
    }

    // ── ADMIN: create a client or reseller account ─────
    if (action === "admin-create") {
      const { adminToken, role, name, email, password, checks, is_reseller } = body;
      const payload = adminToken ? verifyToken(adminToken) : null;
      if (!payload || payload.role !== "admin") { res.status(401).json({ error: "Admin session required" }); return; }
      if (!role || !name || !email || !password) { res.status(400).json({ error: "Missing fields" }); return; }
      if (password.length < 8) { res.status(400).json({ error: "Password must be at least 8 characters." }); return; }

      const table = role === "reseller" ? "resellers" : "clients";
      const existing = await findByEmail(table, email);
      if (existing) { res.status(409).json({ error: "An account with that email already exists." }); return; }

      const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
        method:  "POST",
        headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify({
          name,
          email,
          password_hash: hashPassword(password),
          checks_balance: Number(checks) || 0,
          revoked: false,
          must_reset_password: false,
          ...(role === "reseller" ? { is_reseller: !!is_reseller } : {}),
          created_at: new Date().toISOString(),
        }),
      });
      const inserted = await insertRes.json();
      if (!insertRes.ok) { res.status(insertRes.status).json(inserted); return; }
      const row = Array.isArray(inserted) ? inserted[0] : inserted;
      res.status(200).json({ ok: true, user: stripSensitive(row) });
      return;
    }

    // ── ADMIN: reset/set a client or reseller's password ──
    if (action === "admin-set-password") {
      const { adminToken, role, id, newPassword, forceReset } = body;
      const payload = adminToken ? verifyToken(adminToken) : null;
      if (!payload || payload.role !== "admin") { res.status(401).json({ error: "Admin session required" }); return; }
      if (!role || !id || !newPassword) { res.status(400).json({ error: "Missing fields" }); return; }

      const table = role === "reseller" ? "resellers" : role === "worker" ? "workers" : "clients";
      await patchRow(table, id, {
        password_hash: hashPassword(newPassword),
        must_reset_password: forceReset !== false, // default true
      });
      res.status(200).json({ ok: true });
      return;
    }

    // ── ADMIN: create a worker account ──
    if (action === "admin-create-worker") {
      const { adminToken, name, username, password } = body;
      const payload = adminToken ? verifyToken(adminToken) : null;
      if (!payload || payload.role !== "admin") { res.status(401).json({ error: "Admin session required" }); return; }
      if (!name || !username || !password) { res.status(400).json({ error: "Missing fields" }); return; }
      if (password.length < 8) { res.status(400).json({ error: "Password must be at least 8 characters." }); return; }

      const existing = await findByField("workers", "username", username);
      if (existing) { res.status(409).json({ error: "That username is already taken." }); return; }

      const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/workers`, {
        method:  "POST",
        headers: sbHeaders({ "Prefer": "return=representation" }),
        body: JSON.stringify({
          name,
          username,
          password_hash: hashPassword(password),
          active: true,
          must_reset_password: true,
          created_at: new Date().toISOString(),
        }),
      });
      const inserted = await insertRes.json();
      if (!insertRes.ok) { res.status(insertRes.status).json(inserted); return; }
      const row = Array.isArray(inserted) ? inserted[0] : inserted;
      res.status(200).json({ ok: true, worker: stripSensitive(row) });
      return;
    }

    // ── ADMIN: generate (or regenerate) a client's API key ──
    // Returns the plaintext key ONCE — only the hash is ever stored, so if
    // it's lost, the fix is to generate a new one, not "look it up again".
    if (action === "admin-generate-api-key") {
      const { adminToken, clientId } = body;
      const payload = adminToken ? verifyToken(adminToken) : null;
      if (!payload || payload.role !== "admin") { res.status(401).json({ error: "Admin session required" }); return; }
      if (!clientId) { res.status(400).json({ error: "Missing clientId" }); return; }

      const client = await findById("clients", clientId);
      if (!client) { res.status(404).json({ error: "No client with that ID." }); return; }

      const { full, prefix } = generateApiKey();
      await patchRow("clients", clientId, {
        api_key_hash:       hashApiKey(full),
        api_key_prefix:     prefix,
        api_enabled:        true,
        api_key_created_at: new Date().toISOString(),
      });

      res.status(200).json({ ok: true, apiKey: full, prefix, clientName: client.name });
      return;
    }

    // ── ADMIN: revoke a client's API key ──
    if (action === "admin-revoke-api-key") {
      const { adminToken, clientId } = body;
      const payload = adminToken ? verifyToken(adminToken) : null;
      if (!payload || payload.role !== "admin") { res.status(401).json({ error: "Admin session required" }); return; }
      if (!clientId) { res.status(400).json({ error: "Missing clientId" }); return; }

      await patchRow("clients", clientId, {
        api_enabled:    false,
        api_key_hash:   null,
        api_key_prefix: null,
      });
      res.status(200).json({ ok: true });
      return;
    }

    // ── WORKER LOGIN ──
    if (action === "worker-login") {
      const { username, password } = body;
      if (!username || !password) { res.status(400).json({ error: "Username and password required" }); return; }

      if (await rejectIfLockedOut(res, "worker", username)) return;

      const row = await findByField("workers", "username", username);
      if (!row) { await recordFailedAttempt("worker", username); res.status(404).json({ error: "No account found with that username." }); return; }

      const { ok } = verifyPassword(password, row.password_hash);
      if (!ok) { await recordFailedAttempt("worker", username); res.status(401).json({ error: "Incorrect password." }); return; }
      if (!row.active) { res.status(403).json({ error: "Your account has been deactivated." }); return; }

      await clearFailedAttempts("worker", username);
      if (row.must_reset_password) {
        const resetToken = signToken({ role: "worker", id: row.id, purpose: "reset" }, 60 * 15);
        res.status(200).json({ requiresReset: true, role: "worker", id: row.id, resetToken });
        return;
      }

      const token = signToken(sessionPayload("worker", row), 60 * 60 * 24 * 7); // 7 days
      res.status(200).json({ ok: true, role: "worker", token, worker: stripSensitive(row) });
      return;
    }

    res.status(400).json({ error: "Unknown action" });

  } catch (err) {
    console.error("Auth handler error:", err);
    // Never expose raw Node/crypto error messages to users
    res.status(500).json({ error: "Something went wrong. Please try again." });
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => data += chunk);
    req.on("end",  () => resolve(data));
    req.on("error", reject);
  });
}
