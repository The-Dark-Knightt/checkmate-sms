/**
 * Vercel Serverless Function: /api/sms
 *
 * Client-facing SMS number purchase flow. Requires x-user-token like
 * every other client-scoped endpoint (see api/db.js's authHeaders).
 *
 * PVAPins REST API only — this file doesn't cover renting, that's
 * legacy-API-only and belongs in a separate api/sms-rentals.js once
 * you're ready to build it (needs load_apps.php?is_rent=1 for pricing,
 * which we still don't have the response shape for).
 *
 * Billing follows PVAPins' real behavior: reserving a number
 * (POST /orders) is free on their side, they only bill when a code is
 * delivered. So this holds diamonds (sms_holds) rather than charging
 * them, and only finalizes the debit once a code arrives. An
 * expired/cancelled order just releases the hold — nothing was ever
 * charged, so there's nothing to refund.
 */

import crypto from "crypto";
import { verifyToken } from "./_lib/crypto.js";
import { holdDiamonds, finalizeHold, releaseHold, sbHeaders } from "./_lib/wallet.js";

const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramAlert(message) {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) { console.error("Telegram alert skipped — env vars not set."); return; }
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

const env = {
  SUPABASE_URL:         process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
};
const PVAPINS_API_KEY = process.env.PVAPINS_API_KEY;
const PVAPINS_BASE    = "https://api.pvapins.com";
const FX_RATE          = Number(process.env.USD_KES_RATE || 129); // placeholder, needs a real periodically-updated rate

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-user-token");
}

function getClientSession(req) {
  const token = req.headers["x-user-token"];
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload || payload.role !== "client") return null;
  return payload; // { role, id, exp }
}

async function pvapins(path, { method = "GET", query, body } = {}) {
  const url = new URL(PVAPINS_BASE + path);
  if (query) for (const [k, v] of Object.entries(query)) if (v != null) url.searchParams.set(k, v);
  const r = await fetch(url, {
    method,
    headers: { "X-API-Key": PVAPINS_API_KEY, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    const err = new Error((data && (data.message || data.error)) || `PVAPins ${method} ${path} -> ${r.status}`);
    err.status = r.status;
    throw err;
  }
  return data;
}

// Sell-price formula agreed for the hub: floor 200 KES / cap 800 KES,
// tapering margin via sqrt, cap lifts if wholesale cost alone exceeds it.
// Divided by 100 at the end since 1 diamond = 100 KES.
function priceFromUsd(costUsd, fxRate = FX_RATE) {
  const costLocal = costUsd * fxRate;
  const floor = 200, cap = 800, richK = 25, thinK = 8;
  let priceKes;
  if (costLocal >= cap) {
    priceKes = Math.round(costLocal + thinK * Math.sqrt(costLocal));
  } else {
    const raw = costLocal + richK * Math.sqrt(costLocal);
    priceKes = Math.round(Math.max(floor, Math.min(cap, raw)));
  }
  return { price: priceKes / 100, costLocal: costLocal / 100 };
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => data += c);
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }

  const session = getClientSession(req);
  if (!session) { res.status(401).json({ error: "Not authenticated" }); return; }
  const clientId = session.id;

  const { action } = req.query;

  try {
    if (action === "quote" && req.method === "GET") {
      const { country, service } = req.query;
      if (!country || !service) return res.status(400).json({ error: "country and service are required" });

      const operators = await pvapins("/api/v1/operators", { query: { country, service } });
      if (!operators?.length) return res.status(409).json({ error: "No numbers available for that country/service" });

      const cheapest = operators.reduce((a, b) => (b.price < a.price ? b : a));
      const { price } = priceFromUsd(cheapest.price);
      res.status(200).json({ country, service, operator: cheapest.operator, costUsd: cheapest.price, sellPrice: price });
      return;
    }

    if (action === "buy" && req.method === "POST") {
      const { country, service } = JSON.parse(await readBody(req));
      if (!country || !service) return res.status(400).json({ error: "country and service are required" });

      const operators = await pvapins("/api/v1/operators", { query: { country, service } });
      if (!operators?.length) return res.status(409).json({ error: "No numbers available for that country/service" });
      const cheapest = operators.reduce((a, b) => (b.price < a.price ? b : a));
      const { price: sellPrice } = priceFromUsd(cheapest.price);

      const orderId = crypto.randomUUID();
      const hold = await holdDiamonds(env, clientId, sellPrice, orderId);
      if (!hold.ok) {
        return res.status(402).json({ error: "INSUFFICIENT_BALANCE", available: hold.available, needed: sellPrice });
      }

      let remote;
      try {
        remote = await pvapins("/api/v1/orders", {
          method: "POST",
          body: { country, service, operator: cheapest.operator },
        });
      } catch (err) {
        await releaseHold(env, orderId); // reservation failed outright, nothing was charged
        return res.status(502).json({ error: err.message });
      }

      await fetch(`${env.SUPABASE_URL}/rest/v1/sms_orders`, {
        method:  "POST",
        headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=minimal" }),
        body: JSON.stringify({
          id: orderId, pvapins_id: remote.id, client_id: clientId,
          service_code: service, country_code: country,
          cost_usd: cheapest.price, sell_price: sellPrice,
          phone_number: remote.phoneNumber, status: remote.status || "active",
        }),
      });

      res.status(201).json({ id: orderId, phoneNumber: remote.phoneNumber, status: remote.status, sellPrice });

      const buyerRes = await fetch(`${env.SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}&select=name,email`, { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) });
      const buyer = (await buyerRes.json())?.[0] || {};
      await sendTelegramAlert(
        `\uD83D\uDCF1 <b>SMS Number — Receipt</b>\n` +
        `\uD83C\uDD94 Order: <code>${orderId}</code>\n` +
        `\uD83D\uDC64 Client: <b>${buyer.name || buyer.email || clientId}</b>\n` +
        `\uD83D\uDCE6 ${service} / ${country}\n` +
        `\uD83D\uDCDE ${remote.phoneNumber}\n` +
        `\uD83D\uDC8E Held: ${sellPrice} diamonds (charged only once a code arrives)\n` +
        `\uD83D\uDCC5 ${new Date().toISOString()}`
      );
      return;
    }

    if (action === "poll" && req.method === "GET") {
      const { id } = req.query;
      const orderRes = await fetch(
        `${env.SUPABASE_URL}/rest/v1/sms_orders?id=eq.${encodeURIComponent(id)}&client_id=eq.${clientId}&select=*`,
        { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
      );
      const order = (await orderRes.json())?.[0];
      if (!order) return res.status(404).json({ error: "Order not found" });

      if (["completed", "expired", "cancelled"].includes(order.status)) {
        res.status(200).json(order);
        return;
      }

      const remote = await pvapins(`/api/v1/orders/${order.pvapins_id}`);

      if (remote.status === "completed" && order.status !== "completed") {
        await finalizeHold(env, id); // code arrived — this is the moment PVAPins bills us, so it's when we bill the client
        const buyerRes = await fetch(`${env.SUPABASE_URL}/rest/v1/clients?id=eq.${order.client_id}&select=name,email`, { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) });
        const buyer = (await buyerRes.json())?.[0] || {};
        await sendTelegramAlert(
          `\u2705 <b>SMS Code Delivered — Receipt</b>\n` +
          `\uD83C\uDD94 Order: <code>${id}</code>\n` +
          `\uD83D\uDC64 Client: <b>${buyer.name || buyer.email || order.client_id}</b>\n` +
          `\uD83D\uDCDE ${order.phone_number}\n` +
          `\uD83D\uDD22 Code: <code>${remote.otpCode}</code>\n` +
          `\uD83D\uDC8E Charged: ${order.sell_price} diamonds\n` +
          `\uD83D\uDCC5 ${new Date().toISOString()}`
        );
      }
      if (["expired", "cancelled"].includes(remote.status)) {
        await releaseHold(env, id); // no code — nothing was charged, nothing to refund
      }

      await fetch(`${env.SUPABASE_URL}/rest/v1/sms_orders?id=eq.${encodeURIComponent(id)}`, {
        method:  "PATCH",
        headers: sbHeaders(env.SUPABASE_SERVICE_KEY),
        body:    JSON.stringify({ status: remote.status, otp_code: remote.otpCode || null }),
      });

      res.status(200).json({ ...order, status: remote.status, otp_code: remote.otpCode });
      return;
    }

    if (action === "list" && req.method === "GET") {
      const { status } = req.query;
      let url = `${env.SUPABASE_URL}/rest/v1/sms_orders?client_id=eq.${clientId}&order=created_at.desc`;
      if (status) url += `&status=eq.${encodeURIComponent(status)}`;
      const r = await fetch(url, { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) });
      res.status(200).json(await r.json());
      return;
    }

    res.status(400).json({ error: "Unknown action or method" });
  } catch (err) {
    console.error("SMS handler error:", err);
    res.status(500).json({ error: err.message });
  }
}
