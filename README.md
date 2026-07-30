# Reset The Time — Mod Portal

A small Flask site for sharing **Reset The Time** mods. Every uploaded
`.rttmod` is scanned before it can be downloaded, so players only get vetted
files.

## What it does

- **Upload** a `.rttmod` (executable Python for the game).
- **Scan** it through a pipeline (`scanner.py`):
  1. **Structure** — `.rttmod` extension, ≤256 KB, valid UTF-8, parses as Python.
  2. **Manifest** — a well-formed `MOD` dict (id/name/version/author/description)
     and an `apply(api)` function.
  3. **Static safety** — an AST *allowlist*. Mods may only import a small set of
     pure/rendering modules (`math`, `random`, `pygame`, `numpy`, …). Anything
     touching the filesystem, network, processes, or reflection
     (`os`, `subprocess`, `open`, `eval`, `exec`, `__globals__`, …) is **blocked**.
  4. **Content** — profanity / inappropriate-language filter over the code and
     the metadata text.
  5. **Antivirus** — optional VirusTotal hash lookup (set `VT_API_KEY`). It can
     only *reject* on positive detections; an unknown file is allowed on the
     strength of the static scan.
- **Publish** approved mods with a download button, install steps, and the full
  scan report. A JSON catalogue is at `/api/mods`.

Any single **BLOCK** finding rejects the upload; nothing is stored.

> ⚠️ Mods are executable Python. The scanner's allowlist is a strong first line
> of defence, but no static analysis is perfect. The game also makes players
> explicitly enable each mod, and shows a "runs code on your PC" warning.

## Run locally

```bash
cd website
python -m venv .venv && . .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py           # http://localhost:5000
```

Optional VirusTotal scanning:

```bash
export VT_API_KEY=your_key_here      # Windows PowerShell: $env:VT_API_KEY="..."
```

## Deploy on Render

This folder is self-contained — push it to its own repo and either:

- point Render at the repo (it reads `render.yaml`), **or**
- create a **Web Service**: build `pip install -r requirements.txt`,
  start `gunicorn app:app`.

Set `VT_API_KEY` in the Render dashboard to turn on VirusTotal.

## Storage: Supabase (recommended for durable mods)

Game builds in `builds/` ship with the repo, so they always persist. **Uploaded
mods**, however, are written at runtime — and on Render's free plan the
filesystem is ephemeral, so they'd be wiped on every redeploy. To keep uploaded
mods durable and downloadable by everyone, back them with Supabase:

1. In your Supabase project, open **SQL Editor**, paste
   [`supabase_setup.sql`](supabase_setup.sql), and **Run**. This creates the
   `mods` table and a public `mods` storage bucket (with read policies).
2. In Render (or your local `.env`) set:
   - `SUPABASE_URL` — e.g. `https://xxxx.supabase.co`
   - `SUPABASE_SERVICE_KEY` — the **service_role** key (Project Settings → API).
     This is a server-side secret; never commit it or expose it to clients.

With both set, the app stores `.rttmod` files in the bucket and metadata in the
table. Without them, it transparently falls back to local files (fine for dev).

The `service_role` key bypasses row-level security, so only the server (after a
mod passes scanning) can write; the public can read/download but never upload
directly.

After it's live, update `WEBSITE_URL` in the game's `modloader.py` so the
**GET MODS** button opens your deployed site.

## Files

| file | purpose |
|------|---------|
| `app.py` | Flask routes: browse, upload, mod page, download, `/api/mods` |
| `scanner.py` | the scan pipeline (importable + unit-testable) |
| `templates/` | pages |
| `static/style.css` | styling |
| `render.yaml` / `Procfile` | deploy config |
