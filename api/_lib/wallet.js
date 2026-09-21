/**
 * api/_lib/wallet.js
 *
 * Diamond wallet helpers, same optimistic-concurrency pattern as
 * atomicAdjustBalance() in api/db.js (conditional PATCH on the current
 * value, retry on conflict) — no Postgres functions, consistent with
 * how the rest of this codebase talks to Supabase.
 *
 * Used by api/credits.js (top-ups), api/sms.js (temp number holds),
 * api/writing.js (writing/rewriting order debits).
 */

function sbHeaders(SUPABASE_SERVICE_KEY, extra = {}) {
  return {
    "apikey":        SUPABASE_SERVICE_KEY,
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "Content-Type":  "application/json",
    ...extra,
  };
}

async function fetchClient(env, clientId) {
  const r = await fetch(
    `${env.SUPABASE_URL}/rest/v1/clients?id=eq.${encodeURIComponent(clientId)}&select=id,diamonds`,
    { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
  );
  const rows = await r.json();
  return rows?.[0] || null;
}

/** delta can be positive (credit) or negative (debit). Fails closed on insufficient balance. */
async function adjustDiamonds(env, clientId, delta, attempts = 3) {
  for (let i = 0; i < attempts; i++) {
    const client = await fetchClient(env, clientId);
    if (!client) return { ok: false, reason: "not_found" };
    const current = Number(client.diamonds) || 0;
    const next = current + delta;
    if (next < 0) return { ok: false, reason: "insufficient", available: current };

    const url = `${env.SUPABASE_URL}/rest/v1/clients?id=eq.${encodeURIComponent(clientId)}&diamonds=eq.${current}`;
    const r = await fetch(url, {
      method:  "PATCH",
      headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=representation" }),
      body:    JSON.stringify({ diamonds: next }),
    });
    const data = await r.json().catch(() => []);
    if (r.ok && Array.isArray(data) && data.length > 0) {
      return { ok: true, newBalance: next };
    }
    // 0 rows affected — someone else changed it between read and write; retry
  }
  return { ok: false, reason: "conflict" };
}

/** Records a debit/credit in diamond_transactions for the admin/Telegram trail. Best-effort. */
async function logDiamondTx(env, clientId, amount, note, reference) {
  try {
    await fetch(`${env.SUPABASE_URL}/rest/v1/diamond_transactions`, {
      method:  "POST",
      headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=minimal" }),
      body:    JSON.stringify({ client_id: clientId, amount, note, reference }),
    });
  } catch (e) {
    console.error("logDiamondTx failed (non-fatal):", e.message);
  }
}

// ---- Holds (temp SMS numbers: PVAPins only bills on code delivery) ----

async function availableBalance(env, clientId) {
  const client = await fetchClient(env, clientId);
  if (!client) return null;
  const r = await fetch(
    `${env.SUPABASE_URL}/rest/v1/sms_holds?client_id=eq.${encodeURIComponent(clientId)}&status=eq.held&select=amount`,
    { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
  );
  const holds = await r.json().catch(() => []);
  const held = (holds || []).reduce((sum, h) => sum + Number(h.amount), 0);
  return Number(client.diamonds) - held;
}

/** Places a hold (insert only, no balance change yet). Re-checks available after insert to catch races on the check itself. */
async function holdDiamonds(env, clientId, amount, orderId) {
  const available = await availableBalance(env, clientId);
  if (available === null) return { ok: false, reason: "not_found" };
  if (available < amount) return { ok: false, reason: "insufficient", available };

  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/sms_holds`, {
    method:  "POST",
    headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=representation" }),
    body:    JSON.stringify({ id: orderId, client_id: clientId, amount, status: "held" }),
  });
  if (!r.ok) return { ok: false, reason: "insert_failed" };

  // Re-check after the insert — if two holds raced past the check above,
  // this catches it and rolls one back rather than silently overselling.
  const recheck = await availableBalance(env, clientId);
  if (recheck < 0) {
    await releaseHold(env, orderId);
    return { ok: false, reason: "insufficient", available: recheck + amount };
  }
  return { ok: true, available: recheck };
}

/** Code arrived: convert the hold into a real debit. */
async function finalizeHold(env, orderId) {
  const r = await fetch(
    `${env.SUPABASE_URL}/rest/v1/sms_holds?id=eq.${encodeURIComponent(orderId)}&status=eq.held`,
    { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
  );
  const rows = await r.json();
  const hold = rows?.[0];
  if (!hold) return { ok: false, reason: "no_active_hold" };

  const debit = await adjustDiamonds(env, hold.client_id, -Number(hold.amount));
  if (!debit.ok) return debit; // shouldn't happen since the hold already reserved it, but don't silently succeed if it does

  await fetch(`${env.SUPABASE_URL}/rest/v1/sms_holds?id=eq.${encodeURIComponent(orderId)}`, {
    method:  "PATCH",
    headers: sbHeaders(env.SUPABASE_SERVICE_KEY),
    body:    JSON.stringify({ status: "finalized" }),
  });
  await logDiamondTx(env, hold.client_id, -Number(hold.amount), "SMS number delivered", orderId);

  return { ok: true, newBalance: debit.newBalance };
}

/** Expired/cancelled, no code: release the hold. Nothing was ever charged, nothing to refund. */
async function releaseHold(env, orderId) {
  await fetch(`${env.SUPABASE_URL}/rest/v1/sms_holds?id=eq.${encodeURIComponent(orderId)}&status=eq.held`, {
    method:  "PATCH",
    headers: sbHeaders(env.SUPABASE_SERVICE_KEY),
    body:    JSON.stringify({ status: "released" }),
  });
  return { ok: true };
}

export { adjustDiamonds, logDiamondTx, availableBalance, holdDiamonds, finalizeHold, releaseHold, fetchClient, sbHeaders };
