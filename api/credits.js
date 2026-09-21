/**
 * Vercel Serverless Function: /api/credits
 *
 * Same shape as your real /api/paystack.js — same actions, same STK
 * push flow, same idempotency-by-reference pattern — but credits the
 * unified `diamonds` balance on `clients` instead of `checks_balance`,
 * and used by all four services (Turnitin, SMS, Writing, Rewriting).
 *
 * Balance math goes through api/_lib/wallet.js's adjustDiamonds(), the
 * same conditional-PATCH-and-retry pattern as atomicAdjustBalance() in
 * api/db.js — no new Postgres functions, consistent with how the rest
 * of this codebase talks to Supabase.
 */

import crypto from "crypto";
import { adjustDiamonds, logDiamondTx, sbHeaders } from "./_lib/wallet.js";

const env = {
  SUPABASE_URL:         process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
};
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

// 1/100, 2/200, 5/500 — same price-per-diamond as the packages agreed for the hub.
const PLANS = {
  mpesa_1: { gems: 1, amount: 10000, currency: "KES", label: "1 Diamond"  },
  mpesa_2: { gems: 2, amount: 20000, currency: "KES", label: "2 Diamonds" },
  mpesa_5: { gems: 5, amount: 50000, currency: "KES", label: "5 Diamonds" },
};

function planFor(planId) {
  if (PLANS[planId]) return PLANS[planId];
  const m = /^custom_(\d+)$/.exec(planId || ""); // custom_7 -> 7 diamonds @ 100 KES each
  if (m) {
    const gems = Number(m[1]);
    if (gems > 0) return { gems, amount: gems * 10000, currency: "KES", label: `${gems} Diamonds` };
  }
  return null;
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-paystack-signature");
}

async function sendTelegramAlert(message) {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) {
    console.error("Telegram alert skipped — TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.");
    return;
  }
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: TG_CHAT_ID, text: message, parse_mode: "HTML" }),
    });
    if (!r.ok) console.error("Telegram alert failed:", r.status, await r.text().catch(() => ""));
  } catch (e) {
    console.error("Telegram alert failed:", e.message);
  }
}

async function alreadyCredited(reference) {
  const r = await fetch(
    `${env.SUPABASE_URL}/rest/v1/diamond_transactions?reference=eq.${encodeURIComponent(reference)}&select=id&limit=1`,
    { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
  );
  const rows = await r.json().catch(() => []);
  return Array.isArray(rows) && rows.length > 0;
}

async function creditClient(clientId, gems, reference, planId) {
  const plan = planFor(planId);

  const result = await adjustDiamonds(env, clientId, gems);
  if (!result.ok) throw new Error(`credit failed: ${result.reason}`);
  await logDiamondTx(env, clientId, gems, `Top-up: ${plan?.label || planId}`, reference);

  await fetch(`${env.SUPABASE_URL}/rest/v1/payments`, {
    method:  "POST",
    headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=minimal" }),
    body: JSON.stringify({
      client_id: clientId, reference, plan_id: planId,
      checks_added: gems, // same payments table/column as before — gems are the new unit
      amount: plan?.amount, currency: plan?.currency || "KES",
      status: "success", paid_at: new Date().toISOString(),
    }),
  });

  const clientRes = await fetch(
    `${env.SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}&select=name,email`,
    { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
  );
  const client = (await clientRes.json())?.[0] || {};

  await sendTelegramAlert(
    `\uD83D\uDC8E <b>Diamond Top-up</b>\n` +
    `\uD83D\uDC64 Client: <b>${client.name || client.email || clientId}</b>\n` +
    `\uD83D\uDCE6 Plan: ${plan?.label || planId} (+${gems})\n` +
    `\uD83D\uDCB0 Amount: KES ${plan ? (plan.amount / 100).toFixed(0) : "?"}\n` +
    `\uD83D\uDD11 Ref: <code>${reference}</code>\n` +
    `\u2705 New balance: ${result.newBalance} diamonds`
  );

  return result.newBalance;
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }
  const { action } = req.query;

  try {
    if (action === "region" && req.method === "GET") {
      res.status(200).json({ country: req.headers["x-vercel-ip-country"] || null });
      return;
    }

    if (action === "initiate" && req.method === "POST") {
      const { planId, clientId, email, phone } = JSON.parse(await readBody(req));
      const plan = planFor(planId);
      if (!plan) return res.status(400).json({ error: "Invalid plan" });
      if (!clientId || !email) return res.status(400).json({ error: "Missing clientId or email" });

      const normPhone = normalizePhone(phone);
      if (!normPhone) return res.status(400).json({ error: "Enter a valid Safaricom number, e.g. 0712345678" });

      const psRes = await fetch("https://api.paystack.co/charge", {
        method: "POST",
        headers: { "Authorization": `Bearer ${PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          email, amount: plan.amount, currency: plan.currency,
          mobile_money: { phone: normPhone, provider: "mpesa" },
          metadata: { client_id: clientId, plan_id: planId, gems: plan.gems },
        }),
      });
      const psData = await psRes.json();
      if (!psData.status) return res.status(400).json({ error: psData.message || "Could not start payment" });

      res.status(200).json({
        reference: psData.data.reference,
        status: psData.data.status,
        display_text: psData.data.display_text || "Enter your M-Pesa PIN on your phone to complete payment.",
      });
      return;
    }

    if (action === "status" && req.method === "POST") {
      const { reference } = JSON.parse(await readBody(req));
      if (!reference) return res.status(400).json({ error: "Missing reference" });

      const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
        headers: { "Authorization": `Bearer ${PAYSTACK_SECRET_KEY}` },
      });
      const psData = await psRes.json();
      const txStatus = psData.data?.status;
      if (!psData.status || !txStatus) return res.status(400).json({ status: "failed", error: "Could not check payment status" });
      if (txStatus !== "success") return res.status(200).json({ status: txStatus });

      const meta = psData.data.metadata || {};
      const gems = Number(meta.gems) || planFor(meta.plan_id)?.gems || 0;
      if (!meta.client_id || !meta.plan_id) return res.status(200).json({ status: "success", credited: false, error: "Missing metadata" });

      if (await alreadyCredited(reference)) {
        const c = await fetch(`${env.SUPABASE_URL}/rest/v1/clients?id=eq.${meta.client_id}&select=diamonds`, { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) });
        const bal = (await c.json())?.[0]?.diamonds ?? null;
        return res.status(200).json({ status: "success", gems_added: gems, new_balance: bal });
      }

      const newBal = await creditClient(meta.client_id, gems, reference, meta.plan_id);
      res.status(200).json({ status: "success", gems_added: gems, new_balance: newBal });
      return;
    }

    if (action === "webhook" && req.method === "POST") {
      const rawBody = await readBody(req);
      const sig = req.headers["x-paystack-signature"] || "";
      const expected = crypto.createHmac("sha512", PAYSTACK_SECRET_KEY).update(rawBody).digest("hex");
      const sigBuf = Buffer.from(sig), expBuf = Buffer.from(expected);
      const validSig = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
      if (!validSig) return res.status(401).json({ error: "Invalid signature" });

      const event = JSON.parse(rawBody);
      if (event.event === "charge.success") {
        const data = event.data;
        const meta = data.metadata || {};
        const gems = Number(meta.gems) || planFor(meta.plan_id)?.gems || 0;
        if (meta.client_id && meta.plan_id && data.reference && !(await alreadyCredited(data.reference))) {
          await creditClient(meta.client_id, gems, data.reference, meta.plan_id);
        }
      }
      res.status(200).json({ received: true });
      return;
    }

    res.status(400).json({ error: "Unknown action or method" });
  } catch (err) {
    console.error("Credits handler error:", err);
    res.status(500).json({ error: err.message });
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => data += c);
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function normalizePhone(raw) {
  if (!raw) return null;
  let p = String(raw).replace(/[^\d]/g, "");
  if (p.startsWith("0") && p.length === 10) p = "254" + p.slice(1);
  else if (p.startsWith("254") && p.length === 12) { /* fine */ }
  else if (p.length === 9) p = "254" + p;
  else return null;
  if (!/^254(7|1)\d{8}$/.test(p)) return null;
  return "+" + p;
}
