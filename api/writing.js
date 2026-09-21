/**
 * Vercel Serverless Function: /api/writing
 *
 * Handles the "send your request directly" path for Writing/Rewriting
 * (the Discord path needs no backend — it's just a link). Requires
 * x-user-token like api/sms.js.
 *
 * Attachments: expects an array of {name, url} the client already
 * uploaded via your existing signed-upload-URL flow (createSignedUploadUrl
 * in api/db.js / the admin-request-upload action) — this endpoint just
 * records the URLs, it doesn't handle the upload itself, reuse what
 * Turnitin submissions already use for that rather than building a
 * second upload path.
 */

import crypto from "crypto";
import { verifyToken } from "./_lib/crypto.js";
import { adjustDiamonds, logDiamondTx, sbHeaders } from "./_lib/wallet.js";

const env = {
  SUPABASE_URL:         process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_KEY,
};
const TG_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TG_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

const RATES = { writing: 3, rewriting: 1.5 }; // diamonds per page, matches the hub

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin",  "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-user-token,x-worker-token");
}

function getClientSession(req) {
  const token = req.headers["x-user-token"];
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload || payload.role !== "client") return null;
  return payload;
}

function getWorkerSession(req) {
  const token = req.headers["x-worker-token"]; // workers use their own header, never x-user-token
  const payload = token ? verifyToken(token) : null;
  if (!payload || payload.role !== "worker") return null;
  return payload;
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => data += c);
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
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

function escapeHtml(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === "OPTIONS") { res.status(200).end(); return; }
  const { action } = req.query;

  // ── Worker-facing: same order queue every service feeds into, kind
  // (writing/rewriting) is the label a worker sees to tell them apart.
  // SMS numbers aren't here — PVAPins delivers those automatically,
  // there's no human step. Turnitin keeps using its existing
  // submissions/worker-claim flow untouched.
  if (action === "queue" && req.method === "GET") {
    const worker = getWorkerSession(req);
    if (!worker) return res.status(401).json({ error: "Not authenticated" });
    const r = await fetch(
      `${env.SUPABASE_URL}/rest/v1/writing_orders?status=in.(new,files_received)&order=created_at.asc&select=id,kind,category,pages,status,created_at`,
      { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
    );
    return res.status(200).json(await r.json());
  }

  if (action === "claim" && req.method === "POST") {
    const worker = getWorkerSession(req);
    if (!worker) return res.status(401).json({ error: "Not authenticated" });
    const { id } = JSON.parse(await readBody(req));

    // conditional PATCH — only succeeds if still unclaimed, same
    // compare-and-swap spirit as the wallet helpers, so two workers
    // can't both claim the same order
    const r = await fetch(
      `${env.SUPABASE_URL}/rest/v1/writing_orders?id=eq.${encodeURIComponent(id)}&worker_id=is.null`,
      { method: "PATCH", headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=representation" }),
        body: JSON.stringify({ worker_id: worker.id, status: "in_progress" }) }
    );
    const rows = await r.json().catch(() => []);
    if (!r.ok || !rows.length) return res.status(409).json({ error: "Already claimed" });
    return res.status(200).json(rows[0]);
  }

  if (action === "update-status" && req.method === "POST") {
    const worker = getWorkerSession(req);
    if (!worker) return res.status(401).json({ error: "Not authenticated" });
    const { id, status, adminNotes, deliverableUrl } = JSON.parse(await readBody(req));
    if (!["files_received", "in_progress", "completed", "delivered"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }
    const body = { status };
    if (adminNotes !== undefined) body.admin_notes = adminNotes;
    if (deliverableUrl !== undefined) body.deliverable_url = deliverableUrl;
    await fetch(`${env.SUPABASE_URL}/rest/v1/writing_orders?id=eq.${encodeURIComponent(id)}&worker_id=eq.${worker.id}`, {
      method: "PATCH", headers: sbHeaders(env.SUPABASE_SERVICE_KEY), body: JSON.stringify(body),
    });
    return res.status(200).json({ ok: true });
  }

  // ── Client-facing: submit a new order ──
  if (req.method !== "POST") { res.status(405).json({ error: "Method not allowed" }); return; }

  const session = getClientSession(req);
  if (!session) { res.status(401).json({ error: "Not authenticated" }); return; }
  const clientId = session.id;

  try {
    const body = JSON.parse(await readBody(req));
    const {
      kind,             // 'writing' | 'rewriting'
      category,         // 'technical' | 'non_technical'
      instructions,
      pages,
      whatsappCountryCode,
      whatsappNumber,
      attachments,      // [{name, url}]
    } = body;

    if (!["writing", "rewriting"].includes(kind)) return res.status(400).json({ error: "Invalid kind" });
    if (!instructions || !instructions.trim()) return res.status(400).json({ error: "Instructions are required" });
    if (!Number.isInteger(pages) || pages < 1) return res.status(400).json({ error: "Number of pages is required" });
    if (!whatsappCountryCode || !whatsappNumber) return res.status(400).json({ error: "WhatsApp number is required" });

    const price = Math.round(pages * RATES[kind] * 10) / 10;
    const orderId = crypto.randomUUID();

    const debit = await adjustDiamonds(env, clientId, -price);
    if (!debit.ok) {
      return res.status(402).json({ error: "INSUFFICIENT_BALANCE", reason: debit.reason, available: debit.available });
    }
    await logDiamondTx(env, clientId, -price, `${kind} order (${pages}p)`, orderId);

    await fetch(`${env.SUPABASE_URL}/rest/v1/writing_orders`, {
      method:  "POST",
      headers: sbHeaders(env.SUPABASE_SERVICE_KEY, { "Prefer": "return=minimal" }),
      body: JSON.stringify({
        id: orderId, client_id: clientId, kind, category: category || "non_technical",
        instructions, pages, price,
        whatsapp_country_code: whatsappCountryCode, whatsapp_number: whatsappNumber,
        attachments: attachments || [], status: "new",
      }),
    });

    const clientRes = await fetch(
      `${env.SUPABASE_URL}/rest/v1/clients?id=eq.${clientId}&select=name,email`,
      { headers: sbHeaders(env.SUPABASE_SERVICE_KEY) }
    );
    const client = (await clientRes.json())?.[0] || {};
    const fileList = (attachments || []).map(a => `  • ${escapeHtml(a.name)}`).join("\n") || "  (none)";

    await sendTelegramAlert(
      `\uD83D\uDCDD <b>New ${kind === "writing" ? "Writing" : "Rewriting"} Order</b>\n` +
      `\uD83C\uDD94 Order: <code>${orderId}</code>\n` +
      `\uD83D\uDC64 Client: <b>${escapeHtml(client.name || client.email || clientId)}</b>\n` +
      `\uD83D\uDCC4 Pages: ${pages} (${category || "non_technical"})\n` +
      `\uD83D\uDCC1 Files:\n${fileList}\n` +
      `\uD83D\uDCAC Instructions:\n${escapeHtml(instructions).slice(0, 600)}\n` +
      `\uD83D\uDCF1 WhatsApp: ${escapeHtml(whatsappCountryCode)} ${escapeHtml(whatsappNumber)}\n` +
      `\uD83D\uDC8E Price: ${price} diamonds (balance now ${debit.newBalance})\n` +
      `\uD83D\uDCC5 ${new Date().toISOString()}\n` +
      `\uD83D\uDCCC Status: new`
    );

    res.status(201).json({ id: orderId, status: "new", price, newBalance: debit.newBalance });
  } catch (err) {
    console.error("Writing handler error:", err);
    res.status(500).json({ error: err.message });
  }
}
