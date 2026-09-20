# Barangay Care — Community Complaint Tracking System

Secure Flask application for barangay complaint submission, staff workflow, resident accounts, messaging, notifications, maps, reports, and administrative tools.

## Features (Phases 1–5)

### Residents
- Account registration / login
- Submit complaints with photo, GPS pin, category, and priority
- Duplicate-complaint detection before filing
- Track by tracking number + **My Cases** dashboard
- Status timeline and detailed history
- In-app messaging with staff
- In-app notifications (unread indicators)
- Confirm resolution with optional **1–5★ rating** and feedback
- Before / resolution / after evidence photos

### Staff (Admin · Responder · Tanod)
- Staff accounts with unique **Staff IDs** (`STF-0001`, …)
- Role-based permissions (admin vs assigned-only responders/tanods)
- **Staff-ID assignment / reassignment** (not name-only)
- Workflow: Submitted → Verified → Assigned → In Progress → Resolved → Confirmed
- Priority + SLA due dates (Urgent 1d · Normal 3d · Low 7d)
- Overdue detection and Needs Attention lists
- Emergency escalation (urgent + notify admins)
- Resolution remarks and evidence photos
- Complaint history and **activity logs**
- Map + heatmap of geo-tagged cases
- Advanced filters, CSV / Excel / PDF reports
- Manageable categories
- JSON data export + restore (portable); see DR notes below

### Security
- CSRF on POST forms
- Password hashing (Werkzeug)
- HttpOnly / SameSite sessions; optional Secure cookies
- Security headers (CSP, frame options, nosniff, referrer, permissions)
- Bleach sanitization + parameterized SQL
- Rate limits on login, register, submit, messaging, public APIs
- Upload validation (type, MIME, size, Pillow, EXIF strip)
- Public APIs omit PII (no names, contacts, exact coordinates)
- Secrets via environment variables (no production credentials in source)

## Tech stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python 3 + Flask |
| Database | PostgreSQL (psycopg2) |
| Frontend | HTML / CSS / Vanilla JS |
| Maps     | Leaflet + heat / markercluster |
| Charts   | Chart.js |
| Export   | openpyxl, reportlab |
| Images   | Pillow |

## Database tables

Created/migrated automatically on startup:

| Table | Purpose |
|-------|---------|
| `staff_users` | Staff accounts, roles, staff_code |
| `residents` | Resident accounts |
| `categories` | Manageable complaint categories |
| `complaints` | Cases, assignment, due dates, escalation, evidence |
| `messages` | Resident ↔ staff thread |
| `complaint_history` | Status / assignment timeline |
| `activity_logs` | Admin audit trail |
| `notifications` | In-app notifications |
| `complaint_feedback` | Resident ratings |

## Project structure

```
barangay-complaint-system/
├── app.py
├── requirements.txt
├── .env.example
├── README.md
├── templates/          # Public, resident, admin pages
└── static/
    ├── css/style.css
    ├── js/main.js
    ├── js/chart.umd.min.js
    └── uploads/        # runtime uploads (gitignored content)
```

## Setup (development)

```bash
cd barangay-complaint-system
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — at minimum DATABASE_URL and SECRET_KEY
```

`.env` example:

```bash
SECRET_KEY=generate-a-long-random-value
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DB?sslmode=require
ADMIN_USERNAME=admin
ADMIN_PASSWORD=use-a-strong-password
# Or set a precomputed hash:
# ADMIN_PASSWORD_HASH=pbkdf2:sha256:...
SECURE_COOKIES=false
FLASK_ENV=development             # allows default admin only if password unset
# ALLOW_DEFAULT_ADMIN=true        # optional explicit dev fallback
```

```bash
python app.py
```

Open **http://127.0.0.1:5000**

### Default admin (development only)

If `FLASK_ENV=development` or `ALLOW_DEFAULT_ADMIN=true` and no `ADMIN_PASSWORD` is set, the bootstrap password is `BarangayAdmin@2026` for username `admin`.

**Production must set `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`.** Without that (and without `ALLOW_DEFAULT_ADMIN`), the default password is disabled.

## Production

```bash
export SECRET_KEY=...
export DATABASE_URL=...
export ADMIN_USERNAME=...
export ADMIN_PASSWORD=...   # or ADMIN_PASSWORD_HASH
export SECURE_COOKIES=true  # behind HTTPS
export FLASK_ENV=production
# Do NOT set ALLOW_DEFAULT_ADMIN

gunicorn -w 2 -b 0.0.0.0:5000 app:app
```

Serve only over HTTPS (reverse proxy). Rotate admin password after first deploy.

## Backup & disaster recovery

| Method | Use case |
|--------|----------|
| **JSON export** (`/admin/backup`) | Portable data snapshot; restore categories, staff, residents, complaints by tracking #, messages when possible |
| **`pg_dump` / `pg_restore`** | **True** disaster recovery — schema, constraints, indexes, sequences, FKs, all rows |

```bash
# Full database backup (recommended for production)
pg_dump "$DATABASE_URL" -Fc -f barangay_care_$(date +%Y%m%d).dump

# Restore
pg_restore -d "$DATABASE_URL" --clean --if-exists barangay_care_YYYYMMDD.dump
```

Treat the in-app JSON tool as a **data export**, not a replacement for `pg_dump`.

## Tracking-only + free Web Push

Residents do **not** need an account for the main flow:

1. Submit → receive tracking number  
2. Open **Track** → enable **browser alerts** for that number  
3. Staff updates trigger a free **Web Push** notification (no FCM required)

Optional resident accounts still exist for a multi-case dashboard; they are not required.

Generate VAPID keys and set in `.env`:

```bash
pip install pywebpush
python -c "from pywebpush import webpush; import base64, os; from cryptography.hazmat.primitives.asymmetric import ec; from cryptography.hazmat.primitives import serialization; k=ec.generate_private_key(ec.SECP256R1()); print('Use web-push CLI or py_vapid to export VAPID keys')"
# Easiest:
npx web-push generate-vapid-keys
```

Set `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, and `VAPID_CLAIM_EMAIL` in `.env`.

## Mobile / Android (future)

In-app notifications are stored in the `notifications` table and shown on the web UI. Web Push works on the HTTPS website today. The server also exposes `/api/fcm/register` for a native Android Studio app. See **docs/ANDROID.md**.

## License

For educational and civic use.
