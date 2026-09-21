# CheckMate V2 — Full Setup Guide

## File Overview

| File | Purpose |
|------|---------|
| `login.html` | Single login page — routes resellers → `reseller.html`, clients → `dashboard.html` |
| `reseller.html` | Reseller dashboard — submit docs, create client links, redeem tokens |
| `dashboard.html` | Client dashboard — submit docs, view scores, download reports |
| `admin.html` | Admin panel — create accounts, upload reports, set %, manage tokens |
| `api/db.js` | Serverless Supabase proxy (unchanged from V1) |
| `vercel.json` | Vercel routing config |

---

## Test Credentials

| Role | How to access |
|------|--------------|
| **Admin** | Go to `/admin.html`, password: `Dawkins03!@#$` |
| **Reseller** | Admin → Resellers tab → Create Account → set Type = Reseller → login at `/login.html` |
| **Client** | Admin → Resellers tab → Create Account → set Type = Client → login at `/login.html` |

**Login routing:**
- Reseller email+password → lands on `reseller.html`
- Client email+password → lands on `dashboard.html`

---

## Step 1 — Supabase: Run This SQL

Go to Supabase → SQL Editor → New Query, paste and run:

```sql
-- Resellers + clients table (unified)
create table if not exists resellers (
  id              bigserial primary key,
  name            text not null,
  email           text unique not null,
  password_hash   text not null,
  checks_balance  integer default 0,
  is_reseller     boolean default false,   -- true = reseller, false = client
  revoked         boolean default false,
  created_at      timestamptz default now()
);

-- Access tokens (for adding checks)
create table if not exists access_tokens (
  id          bigserial primary key,
  code        text unique not null,
  checks      integer not null,
  note        text,
  used        boolean default false,
  used_by     bigint references resellers(id),
  used_at     timestamptz,
  created_at  timestamptz default now()
);

-- Submissions
create table if not exists submissions (
  id              bigserial primary key,
  reseller_id     bigint references resellers(id),
  file_name       text,
  file_url        text,
  status          text default 'pending',
  submitted_at    timestamptz default now(),
  notified        boolean default false,
  similarity_pct  integer,
  ai_pct          integer,
  report1_url     text,
  report2_url     text
);

-- Client links (created by resellers, used by clients via subdomain)
create table if not exists users (
  id              bigserial primary key,
  token           text unique not null,
  name            text,
  email           text,
  slots_allocated integer default 1,
  slots_used      integer default 0,
  revoked         boolean default false,
  expired         boolean default false,
  created_by      bigint references resellers(id),
  created_at      timestamptz default now(),
  expiry_date     date
);

-- Storage buckets
insert into storage.buckets (id, name, public)
values ('submissions', 'submissions', false)
on conflict do nothing;

insert into storage.buckets (id, name, public)
values ('reports', 'reports', false)
on conflict do nothing;
```

---

## Step 2 — Create GitHub Repo

1. Go to github.com → New repository → name it `checkmate-v2`
2. Upload all files from this folder
3. Make sure folder structure is:
   ```
   login.html
   reseller.html
   dashboard.html
   admin.html
   vercel.json
   api/
     db.js
   ```

---

## Step 3 — Vercel Setup

1. Go to vercel.com → New Project → Import your GitHub repo
2. Click **Settings → Environment Variables** and add:

| Variable | Where to find it |
|----------|-----------------|
| `SUPABASE_URL` | Supabase → Settings → API → Project URL |
| `SUPABASE_ANON_KEY` | Supabase → Settings → API → anon public key |
| `SUPABASE_SERVICE_KEY` | Supabase → Settings → API → service_role key |

3. Redeploy after adding env vars
4. Go to **Domains** → add your custom domain

---

## Step 4 — Railway (for Telegram bot, optional)

1. Go to railway.app → New Project → Deploy from GitHub
2. Select your repo (or a separate bot repo)
3. Add env variables:
   - `BOT_TOKEN` — from @BotFather on Telegram
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_KEY`
4. Railway auto-detects Python and runs `main.py` continuously

---

## Step 5 — First Run Checklist

```
✅ /admin.html           → password: Dawkins03!@#$
✅ Admin → create Reseller account (Type = Reseller)
✅ Admin → create Client account (Type = Client)
✅ /login.html           → login as reseller → lands on reseller.html
✅ /login.html           → login as client   → lands on dashboard.html
✅ Reseller: Create token in admin, redeem in reseller dashboard
✅ Reseller: Create a client link
✅ Client: Upload a document
✅ Admin → Upload Reports → select submission → upload PDFs → enter % → set status Done
✅ Client dashboard shows scores + download buttons instantly
```

---

## How the Two Account Types Work

**Reseller account** (`is_reseller = true`):
- Logs in → `reseller.html`
- Can submit documents
- Can create client links for their clients
- Can redeem tokens to add checks
- Sees their own submission history

**Client account** (`is_reseller = false`):
- Logs in → `dashboard.html`  
- Can only submit documents
- Sees scores (similarity % and AI %) as soon as admin enters them
- Can download reports when admin uploads them
- Cannot create links or manage tokens

---

## Admin Workflow: Delivering a Report

1. Admin panel → **Upload Reports** tab
2. Select submission from dropdown
3. Upload Similarity PDF (from Turnitin)
4. Upload AI Report PDF
5. Enter Similarity % (e.g. `14`)
6. Enter AI % (e.g. `3`)
7. Set status to `Done`
8. User sees percentages and download buttons immediately — even before downloading
