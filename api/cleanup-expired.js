/**
 * Vercel Serverless Function: /api/cleanup-expired
 *
 * Runs on a schedule (see vercel.json "crons") to delete files from Supabase
 * Storage once they're no longer needed:
 *
 *  1. Original submitted documents — deleted 72h after a submission is
 *     marked "done". Admin has already produced the reports by then, so
 *     the original upload has served its purpose.
 *
 *  2. Report PDFs (similarity + AI reports delivered to the client) —
 *     these are the client's deliverable, so we're more careful:
 *       - If the client has downloaded the report (downloaded_at is set),
 *         delete it REPORT_GRACE_AFTER_DOWNLOAD_HOURS after that download.
 *       - If the client never downloaded it, fall back to a longer safety
 *         net of REPORT_MAX_AGE_HOURS after "done", so files don't pile up
 *         forever for clients who never come back for them.
 *
 * Submissions that are still pending/processing are left alone regardless
 * of age, so admin never loses access to a file they haven't gotten to yet.
 *
 * Protected by CRON_SECRET — Vercel automatically sends
 * "Authorization: Bearer <CRON_SECRET>" on scheduled invocations when that
 * env var is set, so nobody else can trigger this endpoint.
 *
 * Also accepts a valid admin session token (the same one used for the
 * cm-ctrl-9x7k.html dashboard, via the x-admin-token header) so the admin
 * can trigger an on-demand run by clicking a button, without ever needing
 * to know or handle CRON_SECRET itself.
 */

import crypto from "crypto";
import { verifyToken } from "./_lib/crypto.js";

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const CRON_SECRET          = process.env.CRON_SECRET;

const DOC_EXPIRY_HOURS               = 72; // original uploaded document, after "done"
const REPORT_GRACE_AFTER_DOWNLOAD_HOURS = 72; // report file, after the client downloads it
const REPORT_MAX_AGE_HOURS              = 24 * 14; // report file, safety net if never downloaded (14 days)
const BATCH_LIMIT  = 500; // safety cap per run so this can't run away

function sbHeaders(extra = {}) {
  return {
    "apikey":        SUPABASE_SERVICE_KEY,
    "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
    "Content-Type":  "application/json",
    ...extra,
  };
}

function isCronRequest(req) {
  const header = req.headers["authorization"] || "";
  if (!CRON_SECRET) return false;
  const expected = `Bearer ${CRON_SECRET}`;
  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isAdminRequest(req) {
  const token = req.headers["x-admin-token"];
  const payload = token ? verifyToken(token) : null;
  return !!(payload && payload.role === "admin");
}

function isAuthorized(req) {
  return isCronRequest(req) || isAdminRequest(req);
}

async function deleteStorageObject(bucket, path) {
  // No body on this request, so no Content-Type either — Supabase Storage's
  // Fastify backend 400s on "Content-Type: application/json" with an empty
  // body ("Body cannot be empty when content-type is set to 'application/json'").
  const r = await fetch(`${SUPABASE_URL}/storage/v1/object/${bucket}/${path}`, {
    method:  "DELETE",
    headers: { "apikey": SUPABASE_SERVICE_KEY, "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  // Treat "already gone" (404) as success too — the goal state is achieved either way
  const ok = r.ok || r.status === 404;
  let body = null;
  if (!ok) { try { body = await r.text(); } catch { /* ignore */ } }
  return { ok, status: r.status, body, bucket, path };
}

// A report ref is stored as "bucket::path" (see api/db.js upload/download).
// Returns null if the ref is missing or in an unexpected shape.
function parseRef(ref) {
  if (!ref) return null;
  const sep = ref.indexOf("::");
  if (sep === -1) return null;
  return { bucket: ref.slice(0, sep), path: ref.slice(sep + 2) };
}

export default async function handler(req, res) {
  if (!isAuthorized(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const now = Date.now();
    const docCutoff = new Date(now - DOC_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();

    let docsDeleted = 0, docsFailed = 0;
    let reportsDeleted = 0, reportsFailed = 0;
    const docSampleErrors = [];
    const reportSampleErrors = [];

    // ── 1. Original documents ──
    {
      const selUrl =
        `${SUPABASE_URL}/rest/v1/submissions` +
        `?submitted_at=lt.${encodeURIComponent(docCutoff)}` +
        `&status=eq.done` +
        `&expired=eq.false` +
        `&file_url=not.is.null` +
        `&select=id,file_url` +
        `&limit=${BATCH_LIMIT}`;

      const selRes = await fetch(selUrl, { headers: sbHeaders() });
      const rows = await selRes.json();
      if (!selRes.ok) {
        res.status(500).json({ error: "Could not query submissions (docs)", detail: rows });
        return;
      }

      for (const row of rows) {
        try {
          const result = await deleteStorageObject("submissions", row.file_url);
          if (!result.ok) {
            docsFailed++;
            if (docSampleErrors.length < 5) docSampleErrors.push({ submissionId: row.id, path: row.file_url, status: result.status, body: result.body });
            console.error(`Doc delete failed for submission ${row.id} (status ${result.status}):`, result.body);
            continue;
          }
          await fetch(`${SUPABASE_URL}/rest/v1/submissions?id=eq.${row.id}`, {
            method:  "PATCH",
            headers: sbHeaders({ "Prefer": "return=minimal" }),
            body:    JSON.stringify({ expired: true }),
          });
          docsDeleted++;
        } catch (e) {
          console.error(`Doc cleanup failed for submission ${row.id}:`, e.message);
          docsFailed++;
          if (docSampleErrors.length < 5) docSampleErrors.push({ submissionId: row.id, path: row.file_url, status: null, body: e.message });
        }
      }
    }

    // ── 2. Report PDFs ──
    {
      const downloadCutoff = new Date(now - REPORT_GRACE_AFTER_DOWNLOAD_HOURS * 60 * 60 * 1000).toISOString();
      const maxAgeCutoff    = new Date(now - REPORT_MAX_AGE_HOURS * 60 * 60 * 1000).toISOString();

      // Candidates: done, not yet report-expired, and has at least one report file.
      // We fetch a slightly broader set (by max age OR download cutoff) then filter in JS,
      // since Supabase's REST filter syntax can't easily express an OR across two different
      // timestamp columns in one query.
      const selUrl =
        `${SUPABASE_URL}/rest/v1/submissions` +
        `?status=eq.done` +
        `&reports_expired=eq.false` +
        `&or=(report1_url.not.is.null,report2_url.not.is.null)` +
        `&submitted_at=lt.${encodeURIComponent(maxAgeCutoff)}` +
        `&select=id,report1_url,report2_url,downloaded_at,submitted_at` +
        `&limit=${BATCH_LIMIT}`;

      // Also fetch ones eligible purely via the (shorter) download-grace window,
      // which may be more recent than maxAgeCutoff.
      const selUrl2 =
        `${SUPABASE_URL}/rest/v1/submissions` +
        `?status=eq.done` +
        `&reports_expired=eq.false` +
        `&or=(report1_url.not.is.null,report2_url.not.is.null)` +
        `&downloaded_at=lt.${encodeURIComponent(downloadCutoff)}` +
        `&select=id,report1_url,report2_url,downloaded_at,submitted_at` +
        `&limit=${BATCH_LIMIT}`;

      const [selRes1, selRes2] = await Promise.all([
        fetch(selUrl, { headers: sbHeaders() }),
        fetch(selUrl2, { headers: sbHeaders() }),
      ]);
      const [rows1, rows2] = await Promise.all([selRes1.json(), selRes2.json()]);
      if (!selRes1.ok || !selRes2.ok) {
        res.status(500).json({ error: "Could not query submissions (reports)", detail: !selRes1.ok ? rows1 : rows2 });
        return;
      }

      const byId = new Map();
      for (const row of [...rows1, ...rows2]) byId.set(row.id, row);

      for (const row of byId.values()) {
        // Only actually eligible if it hits ONE of the two real cutoffs
        // (the max-age query above is a superset by design, so double-check here).
        const downloadedEligible = row.downloaded_at && row.downloaded_at < downloadCutoff;
        const maxAgeEligible     = row.submitted_at && row.submitted_at < maxAgeCutoff;
        if (!downloadedEligible && !maxAgeEligible) continue;

        try {
          const refs = [row.report1_url, row.report2_url].map(parseRef).filter(Boolean);
          let allOk = true;
          for (const { bucket, path } of refs) {
            const result = await deleteStorageObject(bucket, path);
            if (!result.ok) {
              allOk = false;
              if (reportSampleErrors.length < 5) reportSampleErrors.push({ submissionId: row.id, bucket, path, status: result.status, body: result.body });
              console.error(`Report delete failed for submission ${row.id} (status ${result.status}):`, result.body);
            }
          }
          if (!allOk) { reportsFailed++; continue; }
          await fetch(`${SUPABASE_URL}/rest/v1/submissions?id=eq.${row.id}`, {
            method:  "PATCH",
            headers: sbHeaders({ "Prefer": "return=minimal" }),
            body:    JSON.stringify({ reports_expired: true }),
          });
          reportsDeleted++;
        } catch (e) {
          console.error(`Report cleanup failed for submission ${row.id}:`, e.message);
          reportsFailed++;
          if (reportSampleErrors.length < 5) reportSampleErrors.push({ submissionId: row.id, status: null, body: e.message });
        }
      }
    }

    res.status(200).json({
      ok: true,
      docs:    { deleted: docsDeleted, failed: docsFailed, sampleErrors: docSampleErrors },
      reports: { deleted: reportsDeleted, failed: reportsFailed, sampleErrors: reportSampleErrors },
    });
  } catch (err) {
    console.error("cleanup-expired error:", err);
    res.status(500).json({ error: err.message });
  }
}
