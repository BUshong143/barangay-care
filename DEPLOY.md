# Railway deployment notes

## Why you saw Internal Server Error

1. **Bug: `app.logger` used without defining `app`** in many route exception handlers.
   When any DB/query error occurred, the `except` block raised `NameError: name 'app' is not defined`,
   which turned into a 500 Internal Server Error. Fixed: all uses are now `current_app.logger`.

2. **DATABASE_URL `channel_binding=require`** can fail with some psycopg2 builds.
   Removed from the sample `.env` and stripped automatically in `get_db()`.

3. **Environment variables on Railway**
   The repo `.env` is gitignored. You MUST set these in Railway → Variables:
   - `SECRET_KEY` (long random string)
   - `DATABASE_URL` (Neon/Postgres URL, prefer `?sslmode=require` only)
   - `ADMIN_USERNAME` / `ADMIN_PASSWORD`
   - `FLASK_ENV=production`
   - `SECURE_COOKIES=true`
   - `PUBLIC_BASE_URL=https://barangay-care-production.up.railway.app`

4. **Start command** (Procfile / railway.toml already set):
   `gunicorn -w 2 -b 0.0.0.0:$PORT app:app --timeout 120`

## Redeploy

1. Push this fixed tree to your Railway-connected Git repo, **or**
2. In Railway dashboard: upload / redeploy from this zip root (`barangay-complaint-system/`).
3. Confirm Variables are set (especially `DATABASE_URL` without `channel_binding=require`).
4. Open the public URL again.

Default admin after bootstrap: username from `ADMIN_USERNAME`, password from `ADMIN_PASSWORD`.
Change `admin123` immediately in production.
