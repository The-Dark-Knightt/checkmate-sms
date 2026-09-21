/**
 * Vercel Serverless Function: /api/paystack
 *
 * Endpoints:
 *   GET  ?action=region    → Detect visitor's country (for KES/M-Pesa vs USD/card)
 *   POST ?action=initiate  → Start M-Pesa STK push (KES plans only)
 *   POST ?action=status    → Poll payment status / verify + credit
 *   POST ?action=verify    → (legacy) Verify transaction after redirect flow
 *   POST ?action=webhook   → Paystack webhook (backup credit trigger)
 */

import crypto from "crypto";

const PAYSTACK_SECRET_KEY  = process.env.PAYSTACK_SECRET_KEY;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

const PLANS = {
  mpesa_1:       { checks: 1, amount: 10000, currency: "KES", label: "1 Check"  },
  mpesa_3:       { checks: 3, amount: 30000, currency: "KES", label: "3 Checks" },
  mpesa_5:       { checks: 5, amount: 50000, currency: "KES", label: "5 Checks" },

  // International (outside Kenya) — card only, $1.30/check
  usd_1: { checks: 1, amount: 130, currency: "USD", label: "1 Check",  channels: ["card"] },
  usd_3: { checks: 3, amount: 390, currency: "USD", label: "3 Checks", channels: ["card"] },
  usd_5: { checks: 5, amount: 650, currency: "USD", label: "5 Checks", channels: ["card"] },
};

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-paystack-signature");
}

function sbHeaders(extra = {}) {
  return {
    "apikey":        SUPABASE_SERVICE_KEY,
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "Content-Type":  "application/json",
    ...extra,
  };
}

async function sendTelegramAlert(message) {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) {
    console.error("Telegram alert skipped — TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID env var is not set.");
    return;
  }
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: TG_CHAT_ID, text: message, parse_mode: "HTML" }),
    });
    if (!r.ok) {
      const errBody = await r.text().catch(() => "");
      console.error("Telegram alert failed:", r.status, errBody);
    }
  } catch (e) {
    console.error("Telegram alert failed:", e.message);
  }
}

async function creditClient(clientId, checksToAdd, reference, planId) {
  const getRes = await fetch(
    `${SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}&select=checks_balance,email,name`,
    { headers: sbHeaders() }
  );
  const clients = await getRes.json();
  if (!clients || clients.length === 0) throw new Error("Client not found: " + clientId);

  const client = clients[0];
  const newBal = (Number(client.checks_balance) || 0) + checksToAdd;
  const plan   = PLANS[planId];

  await fetch(`${SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}`, {
    method:  "PATCH",
    headers: sbHeaders({ "Prefer": "return=minimal" }),
    body:    JSON.stringify({ checks_balance: newBal }),
  });

  await fetch(`${SUPABASE_URL}/rest/v1/payments`, {
    method:  "POST",
    headers: sbHeaders({ "Prefer": "return=minimal" }),
    body:    JSON.stringify({
      client_id:    clientId,
      reference,
      plan_id:      planId,
      checks_added: checksToAdd,
      amount:       plan.amount,
      currency:     plan.currency,
      status:       "success",
      paid_at:      new Date().toISOString(),
    }),
  });

  await sendTelegramAlert(
    `💳 <b>Payment Received</b>\n` +
    `👤 Client: <b>${client.name || client.email}</b>\n` +
    `📦 Plan: ${plan.label} (+${checksToAdd} checks)\n` +
    `💰 Amount: KES ${(plan.amount / 100).toFixed(0)}\n` +
    `🔑 Ref: <code>${reference}</code>\n` +
    `✅ New balance: ${newBal} checks`
  );

  return newBal;
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }

  const { action } = req.query;

  try {

    // ── REGION: auto-detect visitor country (Vercel sets this header) ─
    if (action === "region" && req.method === "GET") {
      const country = req.headers["x-vercel-ip-country"] || null;
      res.status(200).json({ country }); // e.g. "KE", "US", or null if undetectable (local dev, etc.)
      return;
    }

    // ── INITIATE: Send an M-Pesa STK push directly to the customer's phone ─
    if (action === "initiate" && req.method === "POST") {
      const body = JSON.parse(await readBody(req));
      const { planId, clientId, email, phone } = body;

      if (!planId || !PLANS[planId]) {
        res.status(400).json({ error: "Invalid plan" }); return;
      }
      if (!clientId || !email) {
        res.status(400).json({ error: "Missing clientId or email" }); return;
      }
      const normPhone = normalizePhone(phone);
      if (!normPhone) {
        res.status(400).json({ error: "Enter a valid Safaricom number, e.g. 0712345678" }); return;
      }

      const plan = PLANS[planId];

      const psRes = await fetch("https://api.paystack.co/charge", {
        method:  "POST",
        headers: {
          "Authorization": `Bearer ${PAYSTACK_SECRET_KEY}`,
          "Content-Type":  "application/json",
        },
        body: JSON.stringify({
          email,
          amount:   plan.amount,
          currency: plan.currency,
          mobile_money: {
            phone:    normPhone,
            provider: "mpesa",
          },
          metadata: {
            client_id: clientId,
            plan_id:   planId,
            checks:    plan.checks,
          },
        }),
      });

      const psData = await psRes.json();
      if (!psData.status) {
        res.status(400).json({ error: psData.message || "Could not start payment" }); return;
      }

      // data.status will be "pay_offline" — customer must approve the STK push on their phone
      res.status(200).json({
        reference:    psData.data.reference,
        status:       psData.data.status,
        display_text: psData.data.display_text || "Enter your M-Pesa PIN on your phone to complete payment.",
      });
      return;
    }

    // ── STATUS: Poll while the customer approves the STK push ─────
    if (action === "status" && req.method === "POST") {
      const { reference } = JSON.parse(await readBody(req));
      if (!reference) { res.status(400).json({ error: "Missing reference" }); return; }

      const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
        headers: { "Authorization": `Bearer ${PAYSTACK_SECRET_KEY}` },
      });
      const psData = await psRes.json();
      const txStatus = psData.data?.status; // pending | success | failed | abandoned

      if (!psData.status || !txStatus) {
        res.status(400).json({ status: "failed", error: "Could not check payment status" }); return;
      }

      if (txStatus !== "success") {
        res.status(200).json({ status: txStatus }); // still pending, or failed/abandoned
        return;
      }

      // Success — credit (idempotent, in case the webhook already did it)
      const meta     = psData.data.metadata || {};
      const clientId = meta.client_id;
      const planId   = meta.plan_id;
      const checks   = Number(meta.checks) || PLANS[planId]?.checks || 0;

      if (!clientId || !planId) {
        res.status(200).json({ status: "success", credited: false, error: "Missing metadata" }); return;
      }

      const dupCheck = await fetch(
        `${SUPABASE_URL}/rest/v1/payments?reference=eq.${encodeURIComponent(reference)}&select=id`,
        { headers: sbHeaders() }
      );
      const dups = await dupCheck.json();
      if (dups && dups.length > 0) {
        const cRes = await fetch(
          `${SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}&select=checks_balance`,
          { headers: sbHeaders() }
        );
        const cl = await cRes.json();
        res.status(200).json({ status: "success", checks_added: checks, new_balance: cl[0]?.checks_balance });
        return;
      }

      const newBal = await creditClient(clientId, checks, reference, planId);
      res.status(200).json({ status: "success", checks_added: checks, new_balance: newBal });
      return;
    }

    // ── (legacy) VERIFY: kept for any old redirect-flow links still in flight ─
    if (action === "verify" && req.method === "POST") {
      const { reference } = JSON.parse(await readBody(req));
      if (!reference) { res.status(400).json({ error: "Missing reference" }); return; }

      const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
        headers: { "Authorization": `Bearer ${PAYSTACK_SECRET_KEY}` },
      });
      const psData = await psRes.json();

      if (!psData.status || psData.data?.status !== "success") {
        res.status(400).json({ error: "Payment not successful", status: psData.data?.status });
        return;
      }

      const meta     = psData.data.metadata || {};
      const clientId = meta.client_id;
      const planId   = meta.plan_id;
      const checks   = Number(meta.checks) || PLANS[planId]?.checks || 0;

      if (!clientId || !planId) {
        res.status(400).json({ error: "Metadata missing" }); return;
      }

      // Idempotency — don't double-credit
      const dupCheck = await fetch(
        `${SUPABASE_URL}/rest/v1/payments?reference=eq.${encodeURIComponent(reference)}&select=id`,
        { headers: sbHeaders() }
      );
      const dups = await dupCheck.json();
      if (dups && dups.length > 0) {
        const cRes = await fetch(
          `${SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}&select=checks_balance`,
          { headers: sbHeaders() }
        );
        const cl = await cRes.json();
        res.status(200).json({ ok: true, already_credited: true, new_balance: cl[0]?.checks_balance });
        return;
      }

      const newBal = await creditClient(clientId, checks, reference, planId);
      res.status(200).json({ ok: true, checks_added: checks, new_balance: newBal });
      return;
    }

    // ── WEBHOOK: Backup credit trigger from Paystack ──────
    if (action === "webhook" && req.method === "POST") {
      const rawBody  = await readBody(req);
      const sig      = req.headers["x-paystack-signature"] || "";
      const expected = crypto.createHmac("sha512", PAYSTACK_SECRET_KEY).update(rawBody).digest("hex");

      const sigBuf = Buffer.from(sig);
      const expBuf = Buffer.from(expected);
      const validSig = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
      if (!validSig) {
        res.status(401).json({ error: "Invalid signature" }); return;
      }

      const event = JSON.parse(rawBody);

      if (event.event === "charge.success") {
        const data     = event.data;
        const meta     = data.metadata || {};
        const ref      = data.reference;
        const clientId = meta.client_id;
        const planId   = meta.plan_id;
        const checks   = Number(meta.checks) || PLANS[planId]?.checks || 0;

        if (clientId && planId && ref) {
          const dupCheck = await fetch(
            `${SUPABASE_URL}/rest/v1/payments?reference=eq.${encodeURIComponent(ref)}&select=id`,
            { headers: sbHeaders() }
          );
          const dups = await dupCheck.json();
          if (!dups || dups.length === 0) {
            await creditClient(clientId, checks, ref, planId);
          }
        }
      }

      res.status(200).json({ received: true });
      return;
    }

    res.status(400).json({ error: "Unknown action or method" });

  } catch (err) {
    console.error("Paystack handler error:", err);
    res.status(500).json({ error: err.message });
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

// Accepts 07xxxxxxxx, 01xxxxxxxx, 254xxxxxxxxx, +254xxxxxxxxx → returns +254xxxxxxxxx or null
function normalizePhone(raw) {
  if (!raw) return null;
  let p = String(raw).replace(/[^\d]/g, "");
  if (p.startsWith("0") && p.length === 10) p = "254" + p.slice(1);
  else if (p.startsWith("254") && p.length === 12) { /* already fine */ }
  else if (p.length === 9) p = "254" + p; // e.g. 712345678
  else return null;
  if (!/^254(7|1)\d{8}$/.test(p)) return null;
  return "+" + p; // Paystack's M-Pesa charge API expects the leading +
}
