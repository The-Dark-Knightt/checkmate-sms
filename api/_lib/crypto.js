import crypto from "crypto";

// ── Password hashing (scrypt — built into Node, no extra dependency) ──
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

export function isHashed(stored) {
  return typeof stored === "string" && stored.startsWith("scrypt$");
}

// Returns { ok, isLegacyPlaintext } — isLegacyPlaintext true means the DB
// still has an old plaintext password that matched and should be re-hashed.
export function verifyPassword(password, stored) {
  if (!stored) return { ok: false, isLegacyPlaintext: false };
  if (isHashed(stored)) {
    const [, salt, hash] = stored.split("$");
    const check = crypto.scryptSync(password, salt, 64).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(check, "hex");
    const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
    return { ok, isLegacyPlaintext: false };
  }
  // Legacy plaintext row — use safeStringEqual which handles length mismatch safely
  const ok = safeStringEqual(stored, password);
  return { ok, isLegacyPlaintext: ok };
}

function safeStringEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// ── Signed, expiring tokens (HMAC) for sessions ──
// SECURITY: previously fell back to a hardcoded string when ADMIN_SECRET was
// unset, which would let anyone who read the source code forge ANY session
// token (admin, client, or reseller). Now falls back to a random key generated
// fresh per server instance instead — nobody outside can predict or reuse it,
// though it does mean sessions get invalidated on cold starts if ADMIN_SECRET
// is missing. Either way, set ADMIN_SECRET in Vercel — this is not optional.
if (!process.env.ADMIN_SECRET) {
  console.error("CRITICAL: ADMIN_SECRET env var is not set. Using a random per-instance key as a fallback — set ADMIN_SECRET in Vercel immediately, or all sessions will be invalidated on every cold start.");
}
const SIGNING_KEY = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString("hex");

export function signToken(payload, ttlSeconds = 60 * 60 * 12) {
  const exp = Date.now() + ttlSeconds * 1000;
  const body = JSON.stringify({ ...payload, exp });
  const b64 = Buffer.from(body).toString("base64url");
  const sig = crypto.createHmac("sha256", SIGNING_KEY).update(b64).digest("base64url");
  return `${b64}.${sig}`;
}

export function verifyToken(token) {
  try {
    if (!token || typeof token !== "string" || !token.includes(".")) return null;
    const [b64, sig] = token.split(".");
    const expected = crypto.createHmac("sha256", SIGNING_KEY).update(b64).digest("base64url");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// Strip password/secret fields from any row(s) before they ever reach the browser
export function stripSensitive(rows) {
  const strip = (row) => {
    if (!row || typeof row !== "object") return row;
    const { password_hash, api_key_hash, ...rest } = row;
    return rest;
  };
  return Array.isArray(rows) ? rows.map(strip) : strip(rows);
}

export function getBearer(req, headerName) {
  return req.headers[headerName.toLowerCase()] || null;
}
