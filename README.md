# LastMile Ready — Dashboard (Render + Supabase build)

Same dashboard, same UI, same PIN/admin login flow, same registration/
approval process, same video-watch-time and dwell-timer gating, same admin
panel. This version uses **Supabase** (Postgres + Storage) instead of
Firebase — only `server.js` changed; `public/index.html` and
`public/admin.html` are untouched, because they only ever talk to this
server's own `/api/...` routes, never to the database directly.

## What changed vs the Firebase build

Nothing user-facing. Under the hood: Firestore documents became Postgres
rows (see `schema.sql`), Firebase Storage became a Supabase Storage
bucket, and `firebase-admin` became `@supabase/supabase-js`. The same
five behavior differences from the original Claude-artifact version still
apply (device-based recognition instead of org identity, no org-directory
search, bcrypt password hashing, PIN shown instead of emailed) — see the
previous README if you want the full explanation of each.

## 1. Create a Supabase project

1. Go to https://supabase.com → **New project** → pick an org, name it
   (e.g. `lastmile-ready`), set a database password (save it somewhere —
   you won't need it for this app, but Supabase requires one), pick a
   region, create.
2. Wait ~2 minutes for it to provision.

## 2. Create the database tables

1. In the left sidebar: **SQL Editor** → **New query**.
2. Open `schema.sql` from this project, copy its entire contents, paste
   into the query editor, click **Run**.
3. You should see 6 new tables under **Table Editor**: `registrations`,
   `profiles`, `admins`, `content`, `assessments`, `submissions`,
   `progress`.

## 3. Create the Storage bucket

1. Left sidebar → **Storage** → **New bucket**.
2. Name it `content-files` (or pick your own name — just match it in the
   `SUPABASE_STORAGE_BUCKET` env var below).
3. Toggle **Public bucket** ON — so uploaded videos/PDFs/PPTs can be
   viewed by staff without a login wall, same as before.

## 4. Get your API credentials

1. Left sidebar → **Project Settings** (gear icon) → **API**.
2. Copy the **Project URL** → this is `SUPABASE_URL`.
3. Copy the **service_role** key (NOT the `anon`/`public` one — the
   service role key is what lets the server bypass Row Level Security;
   never expose it to the browser) → this is `SUPABASE_SERVICE_ROLE_KEY`.

## 5. Configure environment variables

Copy `.env.example` → `.env` for local testing, or set these directly as
**Environment Variables** in Render:

| Variable | Value |
|---|---|
| `SUPABASE_URL` | From step 4 |
| `SUPABASE_SERVICE_ROLE_KEY` | From step 4 (the service_role key) |
| `SUPABASE_STORAGE_BUCKET` | `content-files` (or whatever you named it) |
| `JWT_SECRET` | A long random string |

## 6. Deploy to Render

- **Root Directory**: blank (if this folder is your repo root).
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- Add the four environment variables above under **Environment**.
- Deploy. Visit `/` for the staff dashboard and `/admin` for the admin
  panel.

## Local testing (optional)

```
npm install
npm start
```
Visit `http://localhost:3000` and `http://localhost:3000/admin`.

## File map

```
server.js         — Express API + static file server (only thing that touches Supabase)
package.json       — dependencies + start script
schema.sql         — run once in Supabase's SQL Editor to create tables
public/index.html  — staff dashboard (identical to the Firebase build)
public/admin.html  — admin panel (identical to the Firebase build)
.env.example       — required environment variables
```
