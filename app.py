"""
Barangay Care — Community Complaint Tracking System
Secure Flask application with photo upload, messaging, and admin auth.
"""
import os
import re
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
try:
    from zoneinfo import ZoneInfo
except ImportError:
    try:
        from backports.zoneinfo import ZoneInfo  # type: ignore
    except ImportError:
        ZoneInfo = None  # type: ignore

try:
    PH_TZ = ZoneInfo("Asia/Manila") if ZoneInfo else timezone(timedelta(hours=8))
except Exception:
    # Windows without tzdata package
    PH_TZ = timezone(timedelta(hours=8))

from functools import wraps

from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, session, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import bleach
from PIL import Image

load_dotenv()

app = Flask(__name__)

# ─── Security configuration ───────────────────────────────────────────────
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SECURE_COOKIES", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB max upload

# CSRF token serializer
csrf_serializer = URLSafeTimedSerializer(app.secret_key)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    # Local/dev fallback only — never embed production credentials in source
    DATABASE_URL = os.getenv(
        "DATABASE_URL_FALLBACK",
        "postgresql://localhost:5432/barangay_care",
    )

# Admin credentials — production must set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
_admin_pw_hash_env = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
_admin_pw_env = os.getenv("ADMIN_PASSWORD", "").strip()
_allow_default_admin = os.getenv("ALLOW_DEFAULT_ADMIN", "").lower() in ("1", "true", "yes")
_is_dev = os.getenv("FLASK_ENV", "").lower() in ("development", "dev") or os.getenv("ENV", "").lower() in ("development", "dev")

if _admin_pw_hash_env:
    ADMIN_PASSWORD_HASH = _admin_pw_hash_env
elif _admin_pw_env:
    ADMIN_PASSWORD_HASH = generate_password_hash(_admin_pw_env)
elif _allow_default_admin or _is_dev:
    # Dev-only fallback — never rely on this in production
    ADMIN_PASSWORD_HASH = generate_password_hash("BarangayAdmin@2026")
    print(
        "WARNING: Using default admin password. "
        "Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH for production."
    )
else:
    ADMIN_PASSWORD_HASH = None  # Bootstrap login via env staff_users only

# Web Push (VAPID) — free browser push, no account required
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "").strip()
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "").strip()
VAPID_CLAIM_EMAIL = os.getenv("VAPID_CLAIM_EMAIL", "mailto:admin@barangay.local").strip()

# Android FCM (Firebase) — used by Android Studio / native app
# Set either FIREBASE_CREDENTIALS_JSON (path to service account) or FCM_SERVER_KEY (legacy)
FIREBASE_CREDENTIALS_JSON = os.getenv("FIREBASE_CREDENTIALS_JSON", "").strip()
FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")  # e.g. https://barangay.example.com

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_MIME = {"image/png", "image/jpeg", "image/gif", "image/webp"}
MAX_IMAGE_DIMENSION = 2048

STATUSES = ["Submitted", "Verified", "Assigned", "In Progress", "Resolved", "Confirmed"]
PRIORITIES = ["Low", "Normal", "Urgent"]
# Working-day targets from assignment / verification
PRIORITY_DUE_DAYS = {"Urgent": 1, "Normal": 3, "Low": 7}
CATEGORIES = ["Streetlight", "Garbage", "Noise", "Roads", "Drainage", "Public Safety", "Other"]

# Role permission matrix (staff)
# admin: full access
# responder / tanod: view & update assigned cases, message, limited dashboard
ROLE_PERMISSIONS = {
    "admin": {
        "view_all_cases", "manage_staff", "assign_cases", "update_any_status",
        "view_activity_logs", "manage_settings", "view_resident_pii",
    },
    "responder": {
        "view_assigned_cases", "update_assigned_status", "message_resident",
        "view_own_dashboard",
    },
    "tanod": {
        "view_assigned_cases", "update_assigned_status", "message_resident",
        "view_own_dashboard",
    },
}

# Simple in-memory rate limit store (per process)
_rate_limit_store = {}


# ─── Helpers ───────────────────────────────────────────────────────────────


def now_ph():
    """Current datetime in Philippines timezone."""
    return datetime.now(PH_TZ)


def to_ph(dt):
    """Convert a naive/aware datetime to Asia/Manila for display."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        # DB timestamps are treated as Philippines local time
        return dt.replace(tzinfo=PH_TZ)
    try:
        return dt.astimezone(PH_TZ)
    except Exception:
        return dt


def format_ph(dt, fmt="%b %d, %Y %I:%M %p"):
    """Format datetime in Philippines time."""
    t = to_ph(dt)
    if t is None:
        return "—"
    return t.strftime(fmt)


def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. Copy .env.example to .env and configure it."
        )
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id SERIAL PRIMARY KEY,
            tracking_number VARCHAR(50) UNIQUE NOT NULL,
            category VARCHAR(100) NOT NULL,
            location VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            photo_path VARCHAR(500),
            priority VARCHAR(20) DEFAULT 'Normal',
            status VARCHAR(30) DEFAULT 'Submitted',
            assigned_personnel VARCHAR(150),
            resident_name VARCHAR(150),
            resident_contact VARCHAR(100),
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Migrate photo_url → photo_path if old column exists
    cur.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'photo_url'
            ) AND NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'photo_path'
            ) THEN
                ALTER TABLE complaints RENAME COLUMN photo_url TO photo_path;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'photo_path'
            ) THEN
                ALTER TABLE complaints ADD COLUMN photo_path VARCHAR(500);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'updated_at'
            ) THEN
                ALTER TABLE complaints ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'resident_name'
            ) THEN
                ALTER TABLE complaints ADD COLUMN resident_name VARCHAR(150);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'resident_contact'
            ) THEN
                ALTER TABLE complaints ADD COLUMN resident_contact VARCHAR(100);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'latitude'
            ) THEN
                ALTER TABLE complaints ADD COLUMN latitude DOUBLE PRECISION;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'longitude'
            ) THEN
                ALTER TABLE complaints ADD COLUMN longitude DOUBLE PRECISION;
            END IF;
        END $$;
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS staff_users (
            id SERIAL PRIMARY KEY,
            staff_code VARCHAR(20) UNIQUE,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(150) NOT NULL,
            email VARCHAR(150),
            role VARCHAR(20) NOT NULL DEFAULT 'responder',
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP
        );
    """)
    # Migrate staff_users columns
    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'staff_users' AND column_name = 'staff_code'
            ) THEN
                ALTER TABLE staff_users ADD COLUMN staff_code VARCHAR(20);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'staff_users' AND column_name = 'email'
            ) THEN
                ALTER TABLE staff_users ADD COLUMN email VARCHAR(150);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'staff_users' AND column_name = 'last_login_at'
            ) THEN
                ALTER TABLE staff_users ADD COLUMN last_login_at TIMESTAMP;
            END IF;
        END $$;
    """)
    # Backfill staff_code for existing rows
    cur.execute("SELECT id FROM staff_users WHERE staff_code IS NULL ORDER BY id")
    for row in cur.fetchall() or []:
        code = f"STF-{row['id']:04d}"
        cur.execute("UPDATE staff_users SET staff_code = %s WHERE id = %s", (code, row["id"]))
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_users_staff_code
        ON staff_users(staff_code) WHERE staff_code IS NOT NULL;
    """)

    # Seed default admin if no users exist
    cur.execute("SELECT COUNT(*) AS cnt FROM staff_users")
    if (cur.fetchone() or {}).get("cnt", 0) == 0:
        if ADMIN_PASSWORD_HASH:
            cur.execute(
                """
                INSERT INTO staff_users (staff_code, username, password_hash, full_name, role)
                VALUES (%s, %s, %s, %s, 'admin')
                """,
                ("STF-0001", ADMIN_USERNAME, ADMIN_PASSWORD_HASH, "Barangay Admin")
            )
            print("Seeded default admin user.")
        else:
            print(
                "WARNING: No staff users and no ADMIN_PASSWORD set. "
                "Create a staff account via SQL or set ADMIN_PASSWORD to seed admin."
            )

    # Resident accounts
    cur.execute("""
        CREATE TABLE IF NOT EXISTS residents (
            id SERIAL PRIMARY KEY,
            email VARCHAR(150) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(150) NOT NULL,
            contact VARCHAR(100),
            address VARCHAR(255),
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login_at TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_residents_email ON residents(email);
    """)

    # Link complaints to resident + assigned staff
    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'resident_id'
            ) THEN
                ALTER TABLE complaints ADD COLUMN resident_id INTEGER
                    REFERENCES residents(id) ON DELETE SET NULL;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'assigned_staff_id'
            ) THEN
                ALTER TABLE complaints ADD COLUMN assigned_staff_id INTEGER
                    REFERENCES staff_users(id) ON DELETE SET NULL;
            END IF;
        END $$;
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaints_resident_id ON complaints(resident_id);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaints_assigned_staff_id ON complaints(assigned_staff_id);
    """)

    # Phase 2: due dates, resolution evidence
    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'due_at'
            ) THEN
                ALTER TABLE complaints ADD COLUMN due_at TIMESTAMP;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'resolution_remarks'
            ) THEN
                ALTER TABLE complaints ADD COLUMN resolution_remarks TEXT;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'resolution_photo_path'
            ) THEN
                ALTER TABLE complaints ADD COLUMN resolution_photo_path VARCHAR(500);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'after_photo_path'
            ) THEN
                ALTER TABLE complaints ADD COLUMN after_photo_path VARCHAR(500);
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'resolved_at'
            ) THEN
                ALTER TABLE complaints ADD COLUMN resolved_at TIMESTAMP;
            END IF;
        END $$;
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaints_due_at ON complaints(due_at)
        WHERE due_at IS NOT NULL AND status NOT IN ('Resolved', 'Confirmed');
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            complaint_id INTEGER NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
            sender_type VARCHAR(20) NOT NULL,
            sender_name VARCHAR(150) NOT NULL,
            sender_id INTEGER,
            body TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'messages' AND column_name = 'sender_id'
            ) THEN
                ALTER TABLE messages ADD COLUMN sender_id INTEGER;
            END IF;
        END $$;
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_complaint
        ON messages(complaint_id, created_at);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaints_tracking
        ON complaints(tracking_number);
    """)

    # Complaint status / assignment history
    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaint_history (
            id SERIAL PRIMARY KEY,
            complaint_id INTEGER NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
            old_status VARCHAR(30),
            new_status VARCHAR(30),
            old_assigned VARCHAR(150),
            new_assigned VARCHAR(150),
            changed_by_type VARCHAR(20) NOT NULL,
            changed_by_id INTEGER,
            changed_by_name VARCHAR(150) NOT NULL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaint_history_complaint
        ON complaint_history(complaint_id, created_at);
    """)

    # Staff / system activity audit log
    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,
            actor_type VARCHAR(20) NOT NULL,
            actor_id INTEGER,
            actor_name VARCHAR(150) NOT NULL,
            action VARCHAR(80) NOT NULL,
            entity_type VARCHAR(40),
            entity_id INTEGER,
            details TEXT,
            ip_address VARCHAR(64),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_activity_logs_created
        ON activity_logs(created_at DESC);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_activity_logs_actor
        ON activity_logs(actor_type, actor_id);
    """)

    # Phase 3: in-app notifications + feedback/ratings
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            recipient_type VARCHAR(20) NOT NULL,
            recipient_id INTEGER NOT NULL,
            title VARCHAR(200) NOT NULL,
            body TEXT,
            link VARCHAR(300),
            complaint_id INTEGER REFERENCES complaints(id) ON DELETE CASCADE,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_recipient
        ON notifications(recipient_type, recipient_id, is_read, created_at DESC);
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id SERIAL PRIMARY KEY,
            tracking_number VARCHAR(50) NOT NULL,
            endpoint TEXT NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tracking_number, endpoint)
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_push_subscriptions_tracking
        ON push_subscriptions(tracking_number);
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_tokens (
            id SERIAL PRIMARY KEY,
            tracking_number VARCHAR(50),
            staff_id INTEGER REFERENCES staff_users(id) ON DELETE CASCADE,
            token TEXT NOT NULL,
            platform VARCHAR(20) DEFAULT 'android',
            app_version VARCHAR(40),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(token)
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_device_tokens_tracking
        ON device_tokens(tracking_number);
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_device_tokens_staff
        ON device_tokens(staff_id);
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaint_feedback (
            id SERIAL PRIMARY KEY,
            complaint_id INTEGER NOT NULL REFERENCES complaints(id) ON DELETE CASCADE,
            resident_id INTEGER REFERENCES residents(id) ON DELETE SET NULL,
            rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (complaint_id)
        );
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaint_feedback_complaint
        ON complaint_feedback(complaint_id);
    """)

    # Phase 5: manageable categories + escalation flag
    cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL,
            description VARCHAR(255),
            is_active BOOLEAN DEFAULT TRUE,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("SELECT COUNT(*) AS cnt FROM categories")
    if (cur.fetchone() or {}).get("cnt", 0) == 0:
        for i, name in enumerate(
            ["Streetlight", "Garbage", "Noise", "Roads", "Drainage", "Public Safety", "Other"]
        ):
            cur.execute(
                "INSERT INTO categories (name, sort_order) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING",
                (name, i),
            )
        print("Seeded default categories.")

    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'is_escalated'
            ) THEN
                ALTER TABLE complaints ADD COLUMN is_escalated BOOLEAN DEFAULT FALSE;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'escalated_at'
            ) THEN
                ALTER TABLE complaints ADD COLUMN escalated_at TIMESTAMP;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'complaints' AND column_name = 'escalation_reason'
            ) THEN
                ALTER TABLE complaints ADD COLUMN escalation_reason TEXT;
            END IF;
        END $$;
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_complaints_escalated
        ON complaints(is_escalated) WHERE is_escalated = TRUE;
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("Database initialized.")


def generate_tracking_number():
    year = now_ph().year
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) AS cnt FROM complaints WHERE EXTRACT(YEAR FROM created_at) = %s",
        (year,)
    )
    count = (cur.fetchone()["cnt"] or 0) + 1
    cur.close()
    conn.close()
    return f"#{year}-{count:05d}"


def next_staff_code(cur):
    """Generate next STF-#### staff code."""
    cur.execute(
        """
        SELECT COALESCE(MAX(
            CAST(NULLIF(regexp_replace(staff_code, '[^0-9]', '', 'g'), '') AS INTEGER)
        ), 0) + 1 AS n
        FROM staff_users
        WHERE staff_code ~ '^STF-[0-9]+$'
        """
    )
    n = (cur.fetchone() or {}).get("n") or 1
    return f"STF-{int(n):04d}"


def client_ip():
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown").split(",")[0].strip()


def log_activity(action, entity_type=None, entity_id=None, details=None,
                 actor_type=None, actor_id=None, actor_name=None, cur=None):
    """Write an audit row. Uses current session if actor not passed."""
    if actor_type is None:
        if session.get("admin_logged_in"):
            actor_type = "staff"
            actor_id = session.get("staff_id")
            actor_name = session.get("staff_name") or session.get("admin_user") or "Staff"
        elif session.get("resident_logged_in"):
            actor_type = "resident"
            actor_id = session.get("resident_id")
            actor_name = session.get("resident_name") or "Resident"
        else:
            actor_type = "anonymous"
            actor_id = None
            actor_name = "Anonymous"
    own_conn = cur is None
    try:
        if own_conn:
            conn = get_db()
            cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO activity_logs
                (actor_type, actor_id, actor_name, action, entity_type, entity_id, details, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (actor_type, actor_id, actor_name, action, entity_type, entity_id,
             (details or "")[:2000] or None, client_ip())
        )
        if own_conn:
            conn.commit()
            cur.close()
            conn.close()
    except Exception as e:
        app.logger.error(f"activity log failed: {e}")
        if own_conn:
            try:
                cur.close()
                conn.close()
            except Exception:
                pass


def log_complaint_history(complaint_id, old_status=None, new_status=None,
                          old_assigned=None, new_assigned=None, note=None, cur=None):
    """Record a status/assignment change on a complaint."""
    if session.get("admin_logged_in"):
        by_type, by_id = "staff", session.get("staff_id")
        by_name = session.get("staff_name") or session.get("admin_user") or "Staff"
    elif session.get("resident_logged_in"):
        by_type, by_id = "resident", session.get("resident_id")
        by_name = session.get("resident_name") or "Resident"
    else:
        by_type, by_id, by_name = "system", None, "System"
    own_conn = cur is None
    try:
        if own_conn:
            conn = get_db()
            cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO complaint_history
                (complaint_id, old_status, new_status, old_assigned, new_assigned,
                 changed_by_type, changed_by_id, changed_by_name, note)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (complaint_id, old_status, new_status, old_assigned, new_assigned,
             by_type, by_id, by_name, (note or "")[:500] or None)
        )
        if own_conn:
            conn.commit()
            cur.close()
            conn.close()
    except Exception as e:
        app.logger.error(f"complaint history failed: {e}")
        if own_conn:
            try:
                cur.close()
                conn.close()
            except Exception:
                pass



def compute_due_at(priority, from_dt=None):
    """Return due datetime based on priority SLA days."""
    days = PRIORITY_DUE_DAYS.get(priority or "Normal", 3)
    base = from_dt or now_ph()
    if base.tzinfo is None:
        base = base.replace(tzinfo=PH_TZ)
    return base + timedelta(days=days)


def is_overdue(complaint_row):
    """True if open complaint is past due_at."""
    if not complaint_row:
        return False
    status = complaint_row.get("status") or ""
    if status in ("Resolved", "Confirmed"):
        return False
    due = complaint_row.get("due_at")
    if not due:
        return False
    try:
        due_ph = to_ph(due)
        return due_ph < now_ph()
    except Exception:
        return False


def notify_user(recipient_type, recipient_id, title, body=None, link=None, complaint_id=None, cur=None):
    """Create an in-app notification for a resident or staff member."""
    if not recipient_id:
        return
    own = cur is None
    try:
        if own:
            conn = get_db()
            cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO notifications
                (recipient_type, recipient_id, title, body, link, complaint_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (recipient_type, recipient_id, (title or "")[:200],
             (body or "")[:1000] or None, (link or "")[:300] or None, complaint_id)
        )
        if own:
            conn.commit()
            cur.close()
            conn.close()
    except Exception as e:
        app.logger.error(f"notify failed: {e}")
        if own:
            try:
                cur.close()
                conn.close()
            except Exception:
                pass


def unread_notification_count(recipient_type, recipient_id):
    if not recipient_id:
        return 0
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COUNT(*) AS cnt FROM notifications
            WHERE recipient_type = %s AND recipient_id = %s AND is_read = FALSE
            """,
            (recipient_type, recipient_id)
        )
        n = (cur.fetchone() or {}).get("cnt", 0)
        cur.close()
        conn.close()
        return n
    except Exception:
        return 0


def get_active_categories():
    """Return list of active category names (fallback to CATEGORIES constant)."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT name FROM categories
            WHERE is_active = TRUE
            ORDER BY sort_order, name
            """
        )
        rows = [r["name"] for r in cur.fetchall()]
        cur.close()
        conn.close()
        if rows:
            return rows
    except Exception as e:
        app.logger.error(e)
    return list(CATEGORIES)


def find_duplicate_complaints(category, location, latitude=None, longitude=None, days=7, limit=5):
    """
    Find likely duplicates: same category, similar location text, or nearby coordinates,
    within the last `days` days, still open.
    """
    results = []
    try:
        conn = get_db()
        cur = conn.cursor()
        # Location token overlap via ILIKE on significant words
        loc = (location or "").strip()
        loc_like = f"%{loc[:80]}%" if loc else "%"
        cur.execute(
            """
            SELECT id, tracking_number, category, location, status, priority,
                   latitude, longitude, created_at, description
            FROM complaints
            WHERE created_at >= (CURRENT_TIMESTAMP - (%s || ' days')::interval)
              AND status NOT IN ('Resolved', 'Confirmed')
              AND (
                (category = %s AND location ILIKE %s)
                OR (
                  %s IS NOT NULL AND %s IS NOT NULL
                  AND latitude IS NOT NULL AND longitude IS NOT NULL
                  AND abs(latitude - %s) < 0.003
                  AND abs(longitude - %s) < 0.003
                  AND category = %s
                )
              )
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (str(days), category, loc_like,
             latitude, longitude, latitude, longitude, category, limit),
        )
        results = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"duplicate check: {e}")
    return results


def send_web_push_for_tracking(tracking_number, title, body=None, url=None):
    """Send free Web Push to all browsers subscribed for this tracking number."""
    if not tracking_number or not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        return 0
    try:
        from pywebpush import webpush, WebPushException
    except ImportError:
        app.logger.warning("pywebpush not installed — skip Web Push")
        return 0

    payload = {
        "title": title or "Barangay Care",
        "body": body or "",
        "url": url or f"/track?tracking={tracking_number}",
        "tracking": tracking_number,
    }
    import json
    data = json.dumps(payload)
    sent = 0
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, endpoint, p256dh, auth FROM push_subscriptions
            WHERE tracking_number = %s
            """,
            (tracking_number,),
        )
        rows = cur.fetchall()
        dead = []
        for row in rows:
            try:
                webpush(
                    subscription_info={
                        "endpoint": row["endpoint"],
                        "keys": {"p256dh": row["p256dh"], "auth": row["auth"]},
                    },
                    data=data,
                    vapid_private_key=VAPID_PRIVATE_KEY,
                    vapid_claims={"sub": VAPID_CLAIM_EMAIL},
                )
                sent += 1
            except Exception as e:
                status = getattr(e, "response", None)
                code = getattr(status, "status_code", None) if status is not None else None
                # Gone / invalid subscription
                if code in (404, 410) or "410" in str(e) or "404" in str(e):
                    dead.append(row["id"])
                else:
                    app.logger.warning(f"webpush fail: {e}")
        for did in dead:
            cur.execute("DELETE FROM push_subscriptions WHERE id = %s", (did,))
        if dead:
            conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(f"send_web_push_for_tracking: {e}")
    return sent


def _absolute_url(path):
    if not path:
        return PUBLIC_BASE_URL or "/"
    if path.startswith("http://") or path.startswith("https://"):
        return path
    base = PUBLIC_BASE_URL or ""
    if not base:
        try:
            return request.url_root.rstrip("/") + path
        except RuntimeError:
            return path
    return base + (path if path.startswith("/") else "/" + path)


_firebase_app = None

def _init_firebase():
    """Lazy-init Firebase Admin SDK for FCM."""
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app
    if not FIREBASE_CREDENTIALS_JSON:
        return None
    try:
        import firebase_admin
        from firebase_admin import credentials
        if not firebase_admin._apps:
            path = FIREBASE_CREDENTIALS_JSON
            if path.startswith("{"):
                import json
                cred = credentials.Certificate(json.loads(path))
            else:
                cred = credentials.Certificate(path)
            _firebase_app = firebase_admin.initialize_app(cred)
        else:
            _firebase_app = firebase_admin.get_app()
        return _firebase_app
    except Exception as e:
        app.logger.error(f"Firebase init failed: {e}")
        return None


def send_fcm_for_tracking(tracking_number, title, body=None, url=None):
    """Send FCM push to Android devices registered for this tracking number."""
    if not tracking_number:
        return 0
    tokens = []
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, token FROM device_tokens WHERE tracking_number = %s",
            (tracking_number,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        tokens = rows
    except Exception as e:
        app.logger.error(e)
        return 0
    if not tokens:
        return 0

    full_url = _absolute_url(url or f"/track?tracking={tracking_number}")
    sent = 0
    dead = []

    # Prefer Firebase Admin SDK
    if _init_firebase():
        try:
            from firebase_admin import messaging
            for row in tokens:
                try:
                    msg = messaging.Message(
                        notification=messaging.Notification(
                            title=title or "Barangay Care",
                            body=body or "",
                        ),
                        data={
                            "title": title or "Barangay Care",
                            "body": body or "",
                            "url": full_url,
                            "tracking": tracking_number,
                        },
                        token=row["token"],
                        android=messaging.AndroidConfig(
                            priority="high",
                            notification=messaging.AndroidNotification(
                                click_action="FLUTTER_NOTIFICATION_CLICK",
                                channel_id="barangay_care",
                            ),
                        ),
                    )
                    messaging.send(msg)
                    sent += 1
                except Exception as e:
                    err = str(e).lower()
                    if "not-found" in err or "unregistered" in err or "invalid" in err:
                        dead.append(row["id"])
                    else:
                        app.logger.warning(f"FCM send fail: {e}")
        except Exception as e:
            app.logger.error(e)

    # Legacy HTTP API fallback (if only server key set)
    elif FCM_SERVER_KEY:
        import json
        import urllib.request
        for row in tokens:
            payload = json.dumps({
                "to": row["token"],
                "priority": "high",
                "notification": {
                    "title": title or "Barangay Care",
                    "body": body or "",
                    "click_action": full_url,
                },
                "data": {
                    "title": title or "Barangay Care",
                    "body": body or "",
                    "url": full_url,
                    "tracking": tracking_number,
                },
            }).encode("utf-8")
            req = urllib.request.Request(
                "https://fcm.googleapis.com/fcm/send",
                data=payload,
                headers={
                    "Authorization": f"key={FCM_SERVER_KEY}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.loads(resp.read().decode())
                    if result.get("success"):
                        sent += 1
                    elif result.get("results"):
                        for r in result["results"]:
                            if r.get("error") in ("NotRegistered", "InvalidRegistration"):
                                dead.append(row["id"])
            except Exception as e:
                app.logger.warning(f"FCM legacy fail: {e}")

    if dead:
        try:
            conn = get_db()
            cur = conn.cursor()
            for did in dead:
                cur.execute("DELETE FROM device_tokens WHERE id = %s", (did,))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            app.logger.error(e)
    return sent


def notify_tracking(tracking_number, title, body=None, link=None, complaint_id=None, resident_id=None, cur=None):
    """In-app notify + Web Push + FCM (Android) by tracking number."""
    if resident_id:
        notify_user(
            "resident", resident_id, title, body=body, link=link,
            complaint_id=complaint_id, cur=cur,
        )
    path = link or (f"/track?tracking={tracking_number}" if tracking_number else None)
    try:
        send_web_push_for_tracking(tracking_number, title, body=body, url=path)
    except Exception as e:
        app.logger.error(e)
    try:
        send_fcm_for_tracking(tracking_number, title, body=body, url=path)
    except Exception as e:
        app.logger.error(e)


def role_has_permission(permission, role=None):
    role = role or session.get("staff_role") or "responder"
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms


def staff_can_access_complaint(complaint_row):
    """Whether the logged-in staff may view/edit this complaint (staff-ID first)."""
    if not session.get("admin_logged_in"):
        return False
    role = session.get("staff_role") or "admin"
    if role == "admin" or role_has_permission("view_all_cases", role):
        return True
    sid = session.get("staff_id")
    if sid and complaint_row.get("assigned_staff_id") == sid:
        return True
    # Legacy fallback: name match only if no staff_id on the case
    if not complaint_row.get("assigned_staff_id"):
        sname = (session.get("staff_name") or "").strip().lower()
        assigned = (complaint_row.get("assigned_personnel") or "").strip().lower()
        if sname and assigned and sname in assigned:
            return True
    return False


def list_active_staff():
    """Active staff for assignment dropdowns."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, staff_code, full_name, role
            FROM staff_users
            WHERE is_active = TRUE
            ORDER BY role, full_name
            """
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows
    except Exception as e:
        app.logger.error(e)
        return []


def resolve_staff_assignment(staff_id_raw, name_fallback=""):
    """Resolve form assignment to (staff_id, display_name). Prefers staff ID."""
    staff_id = None
    display = sanitize_text(name_fallback or "", 150) or None
    try:
        if staff_id_raw:
            staff_id = int(staff_id_raw)
    except (TypeError, ValueError):
        staff_id = None
    if staff_id:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, full_name, staff_code FROM staff_users
                WHERE id = %s AND is_active = TRUE
                """,
                (staff_id,),
            )
            row = cur.fetchone()
            cur.close()
            conn.close()
            if row:
                display = row["full_name"]
                if row.get("staff_code"):
                    display = f"{row['full_name']} ({row['staff_code']})"
                return row["id"], display
        except Exception as e:
            app.logger.error(e)
    # Name-only legacy
    if display:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, full_name, staff_code FROM staff_users
                WHERE full_name ILIKE %s AND is_active = TRUE LIMIT 1
                """,
                (display,),
            )
            row = cur.fetchone()
            cur.close()
            conn.close()
            if row:
                label = row["full_name"]
                if row.get("staff_code"):
                    label = f"{row['full_name']} ({row['staff_code']})"
                return row["id"], label
        except Exception as e:
            app.logger.error(e)
    return None, display


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_text(text, max_len=2000):
    if not text:
        return ""
    cleaned = bleach.clean(str(text).strip(), tags=[], strip=True)
    return cleaned[:max_len]


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return csrf_serializer.dumps(session["_csrf_token"])


def validate_csrf_token(token):
    if not token:
        return False
    try:
        data = csrf_serializer.loads(token, max_age=3600)
        return data == session.get("_csrf_token")
    except (BadSignature, SignatureExpired):
        return False


def check_rate_limit(key, max_requests=10, window_seconds=60):
    """Simple IP-based rate limiting."""
    now = datetime.utcnow()
    if key not in _rate_limit_store:
        _rate_limit_store[key] = []
    # Prune old
    _rate_limit_store[key] = [
        t for t in _rate_limit_store[key]
        if (now - t).total_seconds() < window_seconds
    ]
    if len(_rate_limit_store[key]) >= max_requests:
        return False
    _rate_limit_store[key].append(now)
    return True


def process_and_save_image(file_storage):
    """Validate, resize if needed, and save image. Returns relative path or None."""
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise ValueError("Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP.")
    # Check MIME if available
    mime = getattr(file_storage, "content_type", None) or ""
    if mime and mime not in ALLOWED_MIME:
        raise ValueError("Invalid image MIME type.")

    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)

    # Save temporarily then validate with Pillow
    file_storage.save(filepath)
    try:
        with Image.open(filepath) as img:
            img.verify()
        with Image.open(filepath) as img:
            # Re-open after verify
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
            w, h = img.size
            if w > MAX_IMAGE_DIMENSION or h > MAX_IMAGE_DIMENSION:
                img.thumbnail((MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION), Image.Resampling.LANCZOS)
            # Always re-save as JPEG for consistency & strip metadata (privacy)
            out_name = f"{uuid.uuid4().hex}.jpg"
            out_path = os.path.join(app.config["UPLOAD_FOLDER"], out_name)
            img.save(out_path, "JPEG", quality=85, optimize=True)
            if filepath != out_path and os.path.exists(filepath):
                os.remove(filepath)
            return f"uploads/{out_name}"
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        raise ValueError(f"Invalid or corrupted image: {e}")



def admin_only_redirect():
    """If staff is logged in, send them to admin dashboard instead of resident pages."""
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))
    return None


def permission_required(permission):
    """Require a specific staff permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("admin_logged_in"):
                flash("Please log in.", "error")
                return redirect(url_for("admin_login", next=request.path))
            if not role_has_permission(permission):
                flash("You do not have permission for that action.", "error")
                return redirect(url_for("admin_dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_role_required(f):
    """Only full admins (not responders/tanod) may access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in.", "error")
            return redirect(url_for("admin_login", next=request.path))
        role = session.get("staff_role") or "admin"
        if role != "admin":
            flash("Only administrators can access that page.", "error")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return decorated


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in to access the admin panel.", "error")
            return redirect(url_for("admin_login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def resident_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("resident_logged_in"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("resident_login", next=request.path))
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_globals():
    return {
        "csrf_token": generate_csrf_token,
        "admin_logged_in": session.get("admin_logged_in", False),
        "staff_name": session.get("staff_name"),
        "staff_role": session.get("staff_role"),
        "staff_code": session.get("staff_code"),
        "admin_user": session.get("admin_user"),
        "resident_logged_in": session.get("resident_logged_in", False),
        "resident_name": session.get("resident_name"),
        "resident_id": session.get("resident_id"),
        "unread_notifications": (
            unread_notification_count("resident", session.get("resident_id"))
            if session.get("resident_logged_in") else 0
        ),
        "format_ph": format_ph,
        "now_ph": now_ph,
        "role_has_permission": role_has_permission,
        "is_overdue": is_overdue,
        "PRIORITY_DUE_DAYS": PRIORITY_DUE_DAYS,
        "get_active_categories": get_active_categories,
    }


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(self)"
    # CSP allowing Font Awesome CDN + Google Fonts
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' https://unpkg.com https://cdn.jsdelivr.net https://router.project-osrm.org; "
        "frame-ancestors 'self';"
    )
    return response


# ─── Public routes ─────────────────────────────────────────────────────────


@app.route("/favicon.ico")
def favicon():
    return redirect(url_for("static", filename="favicon.svg"))

@app.route("/")
def index():
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    public_stats = {
        "total": 0,
        "submitted": 0,
        "in_progress": 0,
        "resolved": 0,
        "confirmed": 0,
        "urgent": 0,
    }
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'Submitted') AS submitted,
                COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved,
                COUNT(*) FILTER (WHERE status = 'Confirmed') AS confirmed,
                COUNT(*) FILTER (WHERE priority = 'Urgent') AS urgent
            FROM complaints
        """)
        row = cur.fetchone()
        if row:
            public_stats = dict(row)
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error("index stats: %s", e)
    return render_template(
        "index.html",
        categories=get_active_categories(),
        priorities=PRIORITIES,
        public_stats=public_stats,
    )


@app.route("/submit", methods=["GET", "POST"])
def submit_complaint():
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    active_cats = get_active_categories()
    if request.method == "GET":
        return render_template("submit.html", categories=active_cats, priorities=PRIORITIES)

    # Rate limit
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if not check_rate_limit(f"submit:{ip}", max_requests=5, window_seconds=300):
        flash("Too many submissions. Please wait a few minutes.", "error")
        return redirect(url_for("submit_complaint"))

    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("submit_complaint"))

    category = sanitize_text(request.form.get("category", ""), 100)
    location = sanitize_text(request.form.get("location", ""), 255)
    description = sanitize_text(request.form.get("description", ""), 3000)
    priority = sanitize_text(request.form.get("priority", "Normal"), 20)
    resident_name = sanitize_text(request.form.get("resident_name", ""), 150) or None
    resident_contact = sanitize_text(request.form.get("resident_contact", ""), 100) or None
    force_submit = request.form.get("force_submit") == "1"

    latitude = None
    longitude = None
    try:
        lat_raw = request.form.get("latitude", "").strip()
        lng_raw = request.form.get("longitude", "").strip()
        if lat_raw and lng_raw:
            latitude = float(lat_raw)
            longitude = float(lng_raw)
            # Philippines rough bounds
            if not (4.0 <= latitude <= 21.5 and 116.0 <= longitude <= 127.0):
                latitude = None
                longitude = None
    except (ValueError, TypeError):
        latitude = None
        longitude = None

    if not category or not location or not description:
        flash("Category, location, and description are required.", "error")
        return redirect(url_for("submit_complaint"))
    if priority not in PRIORITIES:
        priority = "Normal"
    if category not in active_cats:
        category = active_cats[-1] if active_cats else "Other"

    photo_path = None
    if "photo" in request.files:
        f = request.files["photo"]
        if f and f.filename:
            try:
                photo_path = process_and_save_image(f)
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("submit_complaint"))

    # Prefer logged-in resident profile for identity
    resident_id = session.get("resident_id") if session.get("resident_logged_in") else None
    if resident_id:
        resident_name = resident_name or session.get("resident_name")
        # Prefer stored contact from account if form left blank
        if not resident_contact:
            try:
                _c = get_db()
                _cur = _c.cursor()
                _cur.execute("SELECT contact, full_name FROM residents WHERE id = %s", (resident_id,))
                _r = _cur.fetchone()
                _cur.close()
                _c.close()
                if _r:
                    resident_contact = resident_contact or _r.get("contact")
                    resident_name = resident_name or _r.get("full_name")
            except Exception:
                pass

    # Duplicate detection (skip if resident confirms force_submit)
    if not force_submit:
        dupes = find_duplicate_complaints(category, location, latitude, longitude)
        if dupes:
            return render_template(
                "submit_duplicate.html",
                duplicates=dupes,
                form={
                    "category": category,
                    "location": location,
                    "description": description,
                    "priority": priority,
                    "resident_name": resident_name or "",
                    "resident_contact": resident_contact or "",
                    "latitude": latitude,
                    "longitude": longitude,
                },
                categories=active_cats,
                priorities=PRIORITIES,
            )

    tracking_number = generate_tracking_number()
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO complaints
                (tracking_number, category, location, description, photo_path,
                 priority, status, resident_name, resident_contact, latitude, longitude,
                 resident_id)
            VALUES (%s, %s, %s, %s, %s, %s, 'Submitted', %s, %s, %s, %s, %s)
            RETURNING id, tracking_number
            """,
            (tracking_number, category, location, description, photo_path,
             priority, resident_name, resident_contact, latitude, longitude, resident_id)
        )
        row = cur.fetchone()
        log_complaint_history(
            row["id"], old_status=None, new_status="Submitted",
            note="Complaint submitted", cur=cur
        )
        log_activity(
            "complaint.submit", entity_type="complaint", entity_id=row["id"],
            details=f"tracking={row['tracking_number']} category={category}", cur=cur
        )
        conn.commit()
        cur.close()
        conn.close()
        return render_template(
            "submit_success.html",
            tracking_number=row["tracking_number"],
            complaint_id=row["id"]
        )
    except Exception as e:
        flash(f"Error saving complaint. Please try again.", "error")
        app.logger.error(f"Submit error: {e}")
        return redirect(url_for("submit_complaint"))


@app.route("/track", methods=["GET", "POST"])
def track():
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    complaint = None
    messages = []
    tracking = sanitize_text(
        request.args.get("tracking", "") or request.form.get("tracking", ""), 50
    )
    if tracking and not tracking.startswith("#"):
        tracking = "#" + tracking

    history = []
    feedback = None
    if tracking:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM complaints WHERE tracking_number = %s", (tracking,))
            complaint = cur.fetchone()
            if complaint:
                cur.execute(
                    """
                    SELECT * FROM messages
                    WHERE complaint_id = %s
                    ORDER BY created_at ASC
                    """,
                    (complaint["id"],)
                )
                messages = cur.fetchall()
                cur.execute(
                    """
                    SELECT * FROM complaint_history
                    WHERE complaint_id = %s
                    ORDER BY created_at ASC
                    LIMIT 50
                    """,
                    (complaint["id"],)
                )
                history = cur.fetchall()
                cur.execute(
                    "SELECT * FROM complaint_feedback WHERE complaint_id = %s",
                    (complaint["id"],)
                )
                feedback = cur.fetchone()
                # If logged-in owner views, mark staff messages as read
                if (
                    session.get("resident_logged_in")
                    and complaint.get("resident_id")
                    and complaint["resident_id"] == session.get("resident_id")
                ):
                    cur.execute(
                        """
                        UPDATE messages SET is_read = TRUE
                        WHERE complaint_id = %s AND sender_type = 'admin' AND is_read = FALSE
                        """,
                        (complaint["id"],)
                    )
                    conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            flash("Lookup error. Please try again.", "error")
            app.logger.error(e)

    return render_template(
        "track.html",
        complaint=complaint,
        messages=messages,
        history=history,
        feedback=feedback,
        tracking=tracking
    )


@app.route("/track/message", methods=["POST"])
def resident_send_message():
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if not check_rate_limit(f"msg:{ip}", max_requests=15, window_seconds=60):
        flash("Too many messages. Please slow down.", "error")
        return redirect(request.referrer or url_for("track"))

    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token.", "error")
        return redirect(request.referrer or url_for("track"))

    tracking = sanitize_text(request.form.get("tracking_number", ""), 50)
    body = sanitize_text(request.form.get("body", ""), 1000)
    sender_name = sanitize_text(request.form.get("sender_name", "Resident"), 150) or "Resident"

    if not tracking or not body:
        flash("Message cannot be empty.", "error")
        return redirect(url_for("track", tracking=tracking))

    if not tracking.startswith("#"):
        tracking = "#" + tracking

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM complaints WHERE tracking_number = %s", (tracking,))
        row = cur.fetchone()
        if not row:
            flash("Complaint not found.", "error")
            cur.close()
            conn.close()
            return redirect(url_for("track"))
        # Prefer logged-in resident identity
        if session.get("resident_logged_in"):
            sender_name = session.get("resident_name") or sender_name
            sender_id = session.get("resident_id")
        else:
            sender_id = None
        cur.execute(
            """
            INSERT INTO messages (complaint_id, sender_type, sender_name, sender_id, body)
            VALUES (%s, 'resident', %s, %s, %s)
            """,
            (row["id"], sender_name, sender_id, body)
        )
        # Notify assigned staff if any
        cur.execute(
            "SELECT assigned_staff_id, tracking_number FROM complaints WHERE id = %s",
            (row["id"],)
        )
        crow = cur.fetchone() or {}
        if crow.get("assigned_staff_id"):
            notify_user(
                "staff", crow["assigned_staff_id"],
                title="New resident message",
                body=f"{sender_name}: {body[:120]}",
                link=f"/admin/complaint/{row['id']}",
                complaint_id=row["id"],
                cur=cur,
            )
        log_activity("complaint.message_resident", "complaint", row["id"],
                     details=f"tracking={tracking}", cur=cur)
        conn.commit()
        cur.close()
        conn.close()
        flash("Message sent.", "success")
    except Exception as e:
        flash("Could not send message.", "error")
        app.logger.error(e)
    return redirect(url_for("track", tracking=tracking))


@app.route("/confirm/<path:tracking_number>", methods=["POST"])
def confirm_resolution(tracking_number):
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token.", "error")
        return redirect(url_for("track", tracking=tracking_number))

    tracking_number = sanitize_text(tracking_number, 50)
    if not tracking_number.startswith("#"):
        tracking_number = "#" + tracking_number

    rating_raw = request.form.get("rating", "")
    comment = sanitize_text(request.form.get("feedback_comment", ""), 1000)
    rating = None
    try:
        rating = int(rating_raw)
        if rating < 1 or rating > 5:
            rating = None
    except (TypeError, ValueError):
        rating = None

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE complaints
            SET status = 'Confirmed', updated_at = CURRENT_TIMESTAMP
            WHERE tracking_number = %s AND status = 'Resolved'
            RETURNING id, resident_id, assigned_staff_id
            """,
            (tracking_number,)
        )
        row = cur.fetchone()
        if row:
            log_complaint_history(
                row["id"], "Resolved", "Confirmed",
                note="Resident confirmed resolution", cur=cur
            )
            if rating:
                cur.execute(
                    """
                    INSERT INTO complaint_feedback (complaint_id, resident_id, rating, comment)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (complaint_id) DO UPDATE
                    SET rating = EXCLUDED.rating, comment = EXCLUDED.comment
                    """,
                    (row["id"], session.get("resident_id"), rating, comment or None)
                )
            if row.get("assigned_staff_id"):
                notify_user(
                    "staff", row["assigned_staff_id"],
                    title="Resident confirmed resolution",
                    body=f"{tracking_number}" + (f" · {rating}★" if rating else ""),
                    link=f"/admin/complaint/{row['id']}",
                    complaint_id=row["id"],
                    cur=cur,
                )
            log_activity("complaint.confirm", "complaint", row["id"],
                         details=f"rating={rating}" if rating else None, cur=cur)
            conn.commit()
            flash(
                "Thank you! Your confirmation" +
                (f" and {rating}-star rating" if rating else "") +
                " have been recorded.",
                "success",
            )
        else:
            conn.rollback()
            flash("Complaint not found or not yet marked as Resolved.", "error")
        cur.close()
        conn.close()
    except Exception as e:
        flash("Error confirming.", "error")
        app.logger.error(e)
    return redirect(url_for("track", tracking=tracking_number))


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """Serve uploaded images safely (no path traversal)."""
    safe = secure_filename(filename)
    if not safe or ".." in filename or filename.startswith("/"):
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], safe)


# ─── Admin auth ────────────────────────────────────────────────────────────


# ─── Resident accounts ─────────────────────────────────────────────────────

@app.route("/resident/register", methods=["GET", "POST"])
def resident_register():
    if session.get("resident_logged_in"):
        return redirect(url_for("resident_dashboard"))
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        ip = client_ip()
        if not check_rate_limit(f"res_reg:{ip}", max_requests=5, window_seconds=600):
            flash("Too many registration attempts. Try again later.", "error")
            return render_template("resident_register.html")

        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return render_template("resident_register.html")

        email = sanitize_text(request.form.get("email", ""), 150).lower()
        full_name = sanitize_text(request.form.get("full_name", ""), 150)
        contact = sanitize_text(request.form.get("contact", ""), 100) or None
        address = sanitize_text(request.form.get("address", ""), 255) or None
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not email or not full_name or len(password) < 8:
            flash("Name, email, and password (min 8 characters) are required.", "error")
            return render_template("resident_register.html")
        if not re.match(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", email):
            flash("Please enter a valid email address.", "error")
            return render_template("resident_register.html")
        if password != password2:
            flash("Passwords do not match.", "error")
            return render_template("resident_register.html")

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM residents WHERE email = %s", (email,))
            if cur.fetchone():
                cur.close()
                conn.close()
                flash("An account with that email already exists. Please log in.", "error")
                return redirect(url_for("resident_login"))
            cur.execute(
                """
                INSERT INTO residents (email, password_hash, full_name, contact, address)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, full_name, email
                """,
                (email, generate_password_hash(password), full_name, contact, address)
            )
            row = cur.fetchone()
            log_activity(
                "resident.register", entity_type="resident", entity_id=row["id"],
                details=f"email={email}",
                actor_type="resident", actor_id=row["id"], actor_name=full_name, cur=cur
            )
            conn.commit()
            cur.close()
            conn.close()
            session.clear()
            session["resident_logged_in"] = True
            session["resident_id"] = row["id"]
            session["resident_name"] = row["full_name"]
            session["resident_email"] = row["email"]
            session.permanent = True
            flash("Account created. Welcome!", "success")
            return redirect(url_for("resident_dashboard"))
        except Exception as e:
            app.logger.error(e)
            flash("Registration failed. Please try again.", "error")

    return render_template("resident_register.html")


@app.route("/resident/login", methods=["GET", "POST"])
def resident_login():
    if session.get("resident_logged_in"):
        return redirect(url_for("resident_dashboard"))
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        ip = client_ip()
        if not check_rate_limit(f"res_login:{ip}", max_requests=8, window_seconds=300):
            flash("Too many login attempts. Try again later.", "error")
            return render_template("resident_login.html")

        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return render_template("resident_login.html")

        email = sanitize_text(request.form.get("email", ""), 150).lower()
        password = request.form.get("password", "")
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, email, password_hash, full_name, is_active
                FROM residents WHERE email = %s
                """,
                (email,)
            )
            row = cur.fetchone()
            if row and row.get("is_active") and check_password_hash(row["password_hash"], password):
                cur.execute(
                    "UPDATE residents SET last_login_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (row["id"],)
                )
                log_activity(
                    "resident.login", entity_type="resident", entity_id=row["id"],
                    actor_type="resident", actor_id=row["id"], actor_name=row["full_name"], cur=cur
                )
                conn.commit()
                cur.close()
                conn.close()
                session.clear()
                session["resident_logged_in"] = True
                session["resident_id"] = row["id"]
                session["resident_name"] = row["full_name"]
                session["resident_email"] = row["email"]
                session.permanent = True
                flash(f"Welcome back, {row['full_name']}.", "success")
                next_url = request.args.get("next") or url_for("resident_dashboard")
                if not next_url.startswith("/"):
                    next_url = url_for("resident_dashboard")
                return redirect(next_url)
            cur.close()
            conn.close()
        except Exception as e:
            app.logger.error(e)
        flash("Invalid email or password.", "error")

    return render_template("resident_login.html")


@app.route("/resident/logout")
def resident_logout():
    try:
        log_activity("resident.logout")
    except Exception:
        pass
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/resident/dashboard")
@resident_login_required
def resident_dashboard():
    complaints = []
    stats = {"total": 0, "open": 0, "resolved": 0, "confirmed": 0}
    status_filter = sanitize_text(request.args.get("status", ""), 30)
    notifications = []
    try:
        rid = session.get("resident_id")
        conn = get_db()
        cur = conn.cursor()
        if status_filter and status_filter in STATUSES:
            cur.execute(
                """
                SELECT id, tracking_number, category, location, status, priority,
                       created_at, updated_at, due_at, resolution_remarks
                FROM complaints
                WHERE resident_id = %s AND status = %s
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (rid, status_filter)
            )
        else:
            cur.execute(
                """
                SELECT id, tracking_number, category, location, status, priority,
                       created_at, updated_at, due_at, resolution_remarks
                FROM complaints
                WHERE resident_id = %s
                ORDER BY created_at DESC
                LIMIT 50
                """,
                (rid,)
            )
        complaints = cur.fetchall()
        cur.execute(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Confirmed')) AS open,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved,
                COUNT(*) FILTER (WHERE status = 'Confirmed') AS confirmed
            FROM complaints WHERE resident_id = %s
            """,
            (rid,)
        )
        stats = dict(cur.fetchone() or stats)
        # Unread staff messages per complaint
        cur.execute(
            """
            SELECT m.complaint_id, COUNT(*) AS cnt
            FROM messages m
            JOIN complaints c ON c.id = m.complaint_id
            WHERE c.resident_id = %s AND m.sender_type = 'admin' AND m.is_read = FALSE
            GROUP BY m.complaint_id
            """,
            (rid,)
        )
        unread_msgs = {r["complaint_id"]: r["cnt"] for r in cur.fetchall()}
        for c in complaints:
            c["unread_msgs"] = unread_msgs.get(c["id"], 0)
        cur.execute(
            """
            SELECT id, title, body, link, is_read, created_at, complaint_id
            FROM notifications
            WHERE recipient_type = 'resident' AND recipient_id = %s
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (rid,)
        )
        notifications = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
        flash("Could not load your complaints.", "error")
    return render_template(
        "resident_dashboard.html",
        complaints=complaints,
        stats=stats,
        notifications=notifications,
        current_status=status_filter,
        statuses=STATUSES,
    )


@app.route("/resident/notifications")
@resident_login_required
def resident_notifications():
    items = []
    try:
        rid = session.get("resident_id")
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, title, body, link, is_read, created_at, complaint_id
            FROM notifications
            WHERE recipient_type = 'resident' AND recipient_id = %s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (rid,)
        )
        items = cur.fetchall()
        # Mark all as read when viewing the list
        cur.execute(
            """
            UPDATE notifications SET is_read = TRUE
            WHERE recipient_type = 'resident' AND recipient_id = %s AND is_read = FALSE
            """,
            (rid,)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
    return render_template("resident_notifications.html", notifications=items)


@app.route("/resident/notifications/read/<int:nid>", methods=["POST"])
@resident_login_required
def resident_notification_read(nid):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE notifications SET is_read = TRUE
            WHERE id = %s AND recipient_type = 'resident' AND recipient_id = %s
            RETURNING link
            """,
            (nid, session.get("resident_id"))
        )
        row = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        if row and row.get("link"):
            return redirect(row["link"])
    except Exception as e:
        app.logger.error(e)
    return redirect(url_for("resident_notifications"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        if not check_rate_limit(f"login:{ip}", max_requests=5, window_seconds=300):
            flash("Too many login attempts. Try again later.", "error")
            return render_template("admin_login.html")

        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return render_template("admin_login.html")

        username = sanitize_text(request.form.get("username", ""), 50)
        password = request.form.get("password", "")

        user_row = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, username, password_hash, full_name, role, is_active, staff_code
                FROM staff_users WHERE username = %s
                """,
                (username,)
            )
            user_row = cur.fetchone()
            cur.close()
            conn.close()
        except Exception as e:
            app.logger.error(e)

        authenticated = False
        role = "admin"
        full_name = username
        user_id = None
        staff_code = None

        if user_row and user_row.get("is_active") and check_password_hash(user_row["password_hash"], password):
            authenticated = True
            role = user_row["role"] or "responder"
            full_name = user_row["full_name"] or username
            user_id = user_row["id"]
            staff_code = user_row.get("staff_code")
        elif (
            ADMIN_PASSWORD_HASH
            and username == ADMIN_USERNAME
            and check_password_hash(ADMIN_PASSWORD_HASH, password)
        ):
            # Env fallback for bootstrap (dev or explicit ADMIN_PASSWORD)
            authenticated = True
            role = "admin"
            full_name = "Barangay Admin"
            staff_code = "STF-0001"

        if authenticated:
            session.clear()
            session["admin_logged_in"] = True
            session["admin_user"] = username
            session["staff_role"] = role
            session["staff_name"] = full_name
            session["staff_id"] = user_id
            session["staff_code"] = staff_code
            session.permanent = True
            session.pop("_csrf_token", None)
            # Update last login + audit
            try:
                if user_id:
                    c2 = get_db()
                    c2c = c2.cursor()
                    c2c.execute(
                        "UPDATE staff_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (user_id,)
                    )
                    log_activity(
                        "staff.login", entity_type="staff", entity_id=user_id,
                        details=f"role={role} code={staff_code}",
                        actor_type="staff", actor_id=user_id, actor_name=full_name, cur=c2c
                    )
                    c2.commit()
                    c2c.close()
                    c2.close()
                else:
                    log_activity(
                        "staff.login", entity_type="staff", entity_id=None,
                        details=f"role={role} bootstrap=1",
                        actor_type="staff", actor_id=None, actor_name=full_name
                    )
            except Exception as e:
                app.logger.error(e)
            flash(f"Welcome, {full_name}" + (f" ({staff_code})" if staff_code else "") + ".", "success")
            next_url = request.args.get("next") or url_for("admin_dashboard")
            if not next_url.startswith("/"):
                next_url = url_for("admin_dashboard")
            return redirect(next_url)
        flash("Invalid username or password.", "error")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    try:
        log_activity("staff.logout")
    except Exception:
        pass
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# ─── Admin routes ──────────────────────────────────────────────────────────

def _get_status_stats():
    """Fetch complaint counts per status, scoped to the logged-in staff's own cases when applicable."""
    stats = {}
    try:
        conn = get_db()
        cur = conn.cursor()
        if session.get("staff_role") in ("responder", "tanod"):
            sid = session.get("staff_id")
            if sid:
                cur.execute(
                    "SELECT status, COUNT(*) AS cnt FROM complaints WHERE assigned_staff_id = %s GROUP BY status",
                    (sid,),
                )
            else:
                cur.execute(
                    "SELECT status, COUNT(*) AS cnt FROM complaints WHERE assigned_personnel ILIKE %s GROUP BY status",
                    (f"%{session.get('staff_name', '')}%",)
                )
        else:
            cur.execute("SELECT status, COUNT(*) AS cnt FROM complaints GROUP BY status")
        stats = {r["status"]: r["cnt"] for r in cur.fetchall()}
        cur.close()
        conn.close()
    except Exception as e:
        flash("Database error.", "error")
        app.logger.error(e)
    return stats


def _get_dashboard_extras():
    """Needs-attention list + category breakdown + overdue for the admin dashboard."""
    needs_attention = []
    category_counts = []
    unread_total = 0
    overdue_count = 0
    overdue_cases = []
    try:
        conn = get_db()
        cur = conn.cursor()

        role_clause = ""
        role_params = []
        if session.get("staff_role") in ("responder", "tanod"):
            if session.get("staff_id"):
                role_clause = " AND assigned_staff_id = %s"
                role_params = [session.get("staff_id")]
            else:
                role_clause = " AND assigned_personnel ILIKE %s"
                role_params = [f"%{session.get('staff_name', '')}%"]

        # Urgent, unverified, or overdue cases
        cur.execute(
            f"""
            SELECT id, tracking_number, category, location, priority, status, created_at, due_at
            FROM complaints
            WHERE status NOT IN ('Resolved', 'Confirmed')
              AND (
                priority = 'Urgent'
                OR status = 'Submitted'
                OR is_escalated = TRUE
                OR (due_at IS NOT NULL AND due_at < CURRENT_TIMESTAMP)
              )
              {role_clause}
            ORDER BY
              (due_at IS NOT NULL AND due_at < CURRENT_TIMESTAMP) DESC,
              (priority = 'Urgent') DESC,
              created_at ASC
            LIMIT 10
            """,
            role_params
        )
        needs_attention = cur.fetchall()

        cur.execute(
            f"""
            SELECT category, COUNT(*) AS cnt
            FROM complaints
            WHERE status NOT IN ('Resolved', 'Confirmed') {role_clause}
            GROUP BY category
            ORDER BY cnt DESC
            """,
            role_params
        )
        category_counts = cur.fetchall()

        if role_clause:
            cur.execute(
                f"""
                SELECT COUNT(*) AS cnt FROM messages m
                JOIN complaints c ON c.id = m.complaint_id
                WHERE m.sender_type = 'resident' AND m.is_read = FALSE
                  {role_clause.replace('assigned_personnel', 'c.assigned_personnel')}
                """,
                role_params
            )
        else:
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM messages WHERE sender_type = 'resident' AND is_read = FALSE"
            )
        unread_total = (cur.fetchone() or {}).get("cnt", 0)

        cur.execute(
            f"""
            SELECT COUNT(*) AS cnt FROM complaints
            WHERE status NOT IN ('Resolved', 'Confirmed')
              AND due_at IS NOT NULL AND due_at < CURRENT_TIMESTAMP
              {role_clause}
            """,
            role_params
        )
        overdue_count = (cur.fetchone() or {}).get("cnt", 0)

        cur.execute(
            f"""
            SELECT id, tracking_number, category, priority, status, due_at
            FROM complaints
            WHERE status NOT IN ('Resolved', 'Confirmed')
              AND due_at IS NOT NULL AND due_at < CURRENT_TIMESTAMP
              {role_clause}
            ORDER BY due_at ASC
            LIMIT 8
            """,
            role_params
        )
        overdue_cases = cur.fetchall()

        cur.close()
        conn.close()
    except Exception as e:
        flash("Database error.", "error")
        app.logger.error(e)
    return needs_attention, category_counts, unread_total, overdue_count, overdue_cases


@app.route("/admin/dashboard")
@login_required
def admin_stats_dashboard():
    stats = _get_status_stats()
    needs_attention, category_counts, unread_total, overdue_count, overdue_cases = _get_dashboard_extras()
    max_category = max([c["cnt"] for c in category_counts], default=0)

    monthly = []
    avg_rating = None
    resolution_rate = None
    try:
        conn = get_db()
        cur = conn.cursor()
        role_clause = ""
        role_params = []
        if session.get("staff_role") in ("responder", "tanod"):
            if session.get("staff_id"):
                role_clause = " AND assigned_staff_id = %s"
                role_params = [session.get("staff_id")]
            else:
                role_clause = " AND assigned_personnel ILIKE %s"
                role_params = [f"%{session.get('staff_name', '')}%"]

        cur.execute(
            f"""
            SELECT to_char(date_trunc('month', created_at), 'YYYY-MM') AS ym,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE status IN ('Resolved', 'Confirmed')) AS closed
            FROM complaints
            WHERE created_at >= (CURRENT_DATE - INTERVAL '12 months')
              {role_clause}
            GROUP BY 1
            ORDER BY 1
            """,
            role_params,
        )
        monthly = cur.fetchall()

        cur.execute(
            f"""
            SELECT ROUND(AVG(f.rating)::numeric, 2) AS avg_rating, COUNT(*) AS n
            FROM complaint_feedback f
            JOIN complaints c ON c.id = f.complaint_id
            WHERE 1=1 {role_clause.replace('assigned_personnel', 'c.assigned_personnel') if role_clause else ''}
            """,
            role_params,
        )
        row = cur.fetchone() or {}
        avg_rating = row.get("avg_rating")
        feedback_n = row.get("n") or 0

        total_all = sum(stats.values()) if stats else 0
        closed = (stats.get("Resolved") or 0) + (stats.get("Confirmed") or 0)
        resolution_rate = round(100.0 * closed / total_all, 1) if total_all else 0

        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
        feedback_n = 0

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        statuses=STATUSES,
        needs_attention=needs_attention,
        category_counts=category_counts,
        max_category=max_category,
        unread_total=unread_total,
        overdue_count=overdue_count,
        overdue_cases=overdue_cases,
        monthly=monthly,
        avg_rating=avg_rating,
        feedback_n=feedback_n,
        resolution_rate=resolution_rate,
    )


@app.route("/admin/search")
@login_required
def admin_search():
    status_filter = sanitize_text(request.args.get("status", ""), 30)
    priority_filter = sanitize_text(request.args.get("priority", ""), 20)
    search = sanitize_text(request.args.get("q", ""), 100)
    return render_template(
        "admin_search.html",
        statuses=STATUSES,
        priorities=PRIORITIES,
        current_status=status_filter,
        current_priority=priority_filter,
        search=search
    )


@app.route("/admin")
@login_required
def admin_dashboard():
    status_filter = sanitize_text(request.args.get("status", ""), 30)
    priority_filter = sanitize_text(request.args.get("priority", ""), 20)
    category_filter = sanitize_text(request.args.get("category", ""), 100)
    assigned_filter = sanitize_text(request.args.get("assigned", ""), 150)
    date_from = sanitize_text(request.args.get("from", ""), 20)
    date_to = sanitize_text(request.args.get("to", ""), 20)
    overdue_only = request.args.get("overdue") == "1"
    search = sanitize_text(request.args.get("q", ""), 100)

    query = "SELECT * FROM complaints WHERE 1=1"
    params = []

    if session.get("staff_role") in ("responder", "tanod"):
        if session.get("staff_id"):
            query += " AND assigned_staff_id = %s"
            params.append(session.get("staff_id"))
        else:
            query += " AND assigned_personnel ILIKE %s"
            params.append(f"%{session.get('staff_name', '')}%")
    if status_filter and status_filter in STATUSES:
        query += " AND status = %s"
        params.append(status_filter)
    if priority_filter and priority_filter in PRIORITIES:
        query += " AND priority = %s"
        params.append(priority_filter)
    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)
    if assigned_filter:
        query += " AND assigned_personnel ILIKE %s"
        params.append(f"%{assigned_filter}%")
    if date_from:
        try:
            datetime.strptime(date_from, "%Y-%m-%d")
            query += " AND created_at >= %s::date"
            params.append(date_from)
        except ValueError:
            pass
    if date_to:
        try:
            datetime.strptime(date_to, "%Y-%m-%d")
            query += " AND created_at < (%s::date + INTERVAL '1 day')"
            params.append(date_to)
        except ValueError:
            pass
    if overdue_only:
        query += """ AND due_at IS NOT NULL AND due_at < CURRENT_TIMESTAMP
                     AND status NOT IN ('Resolved', 'Confirmed')"""
    if search:
        query += """ AND (tracking_number ILIKE %s OR location ILIKE %s
                     OR description ILIKE %s OR category ILIKE %s
                     OR assigned_personnel ILIKE %s)"""
        like = f"%{search}%"
        params.extend([like, like, like, like, like])
    query += " ORDER BY created_at DESC LIMIT 500"

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query, params)
        complaints = cur.fetchall()
        cur.execute("SELECT status, COUNT(*) AS cnt FROM complaints GROUP BY status")
        stats = {r["status"]: r["cnt"] for r in cur.fetchall()}
        cur.execute("""
            SELECT complaint_id, COUNT(*) AS unread
            FROM messages
            WHERE sender_type = 'resident' AND is_read = FALSE
            GROUP BY complaint_id
        """)
        unread_map = {r["complaint_id"]: r["unread"] for r in cur.fetchall()}
        cur.close()
        conn.close()
    except Exception as e:
        flash("Database error.", "error")
        app.logger.error(e)
        complaints, stats, unread_map = [], {}, {}

    return render_template(
        "admin.html",
        complaints=complaints,
        stats=stats,
        unread_map=unread_map,
        statuses=STATUSES,
        priorities=PRIORITIES,
        categories=get_active_categories(),
        current_status=status_filter,
        current_priority=priority_filter,
        current_category=category_filter,
        current_assigned=assigned_filter,
        date_from=date_from,
        date_to=date_to,
        overdue_only=overdue_only,
        search=search
    )


@app.route("/admin/complaint/<int:complaint_id>", methods=["GET", "POST"])
@login_required
def admin_complaint(complaint_id):
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin_complaint", complaint_id=complaint_id))

        action = sanitize_text(request.form.get("action", ""), 30)
        status = sanitize_text(request.form.get("status", ""), 30)
        assigned = sanitize_text(request.form.get("assigned_personnel", ""), 150) or None
        priority = sanitize_text(request.form.get("priority", ""), 20)

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "SELECT status, assigned_personnel, resident_id, tracking_number FROM complaints WHERE id = %s",
                (complaint_id,),
            )
            before = cur.fetchone()
            if not before:
                cur.close()
                conn.close()
                flash("Complaint not found.", "error")
                return redirect(url_for("admin_dashboard"))
            # Permission: responders may only act on assigned cases
            if not staff_can_access_complaint({"assigned_personnel": before.get("assigned_personnel"),
                                              "assigned_staff_id": None}) and (session.get("staff_role") or "admin") != "admin":
                # Re-fetch full row for assigned_staff_id
                cur.execute("SELECT * FROM complaints WHERE id = %s", (complaint_id,))
                full = cur.fetchone()
                if not staff_can_access_complaint(full or {}):
                    cur.close()
                    conn.close()
                    flash("You can only update cases assigned to you.", "error")
                    return redirect(url_for("admin_dashboard"))

            old_status = before.get("status")
            old_assigned = before.get("assigned_personnel")

            if action == "verify":
                # Set due date from priority if not already set
                cur.execute("SELECT priority, due_at FROM complaints WHERE id = %s", (complaint_id,))
                prow = cur.fetchone() or {}
                due = prow.get("due_at") or compute_due_at(prow.get("priority") or "Normal")
                # Store as naive PH local for DB
                due_naive = due.replace(tzinfo=None) if getattr(due, "tzinfo", None) else due
                cur.execute(
                    """UPDATE complaints SET status='Verified', due_at=COALESCE(due_at, %s),
                       updated_at=CURRENT_TIMESTAMP
                       WHERE id=%s AND status='Submitted'""",
                    (due_naive, complaint_id)
                )
                log_complaint_history(complaint_id, old_status, "Verified", note="Verified by staff", cur=cur)
                log_activity("complaint.verify", "complaint", complaint_id, cur=cur)
                if before.get("resident_id"):
                    notify_user(
                        "resident", before["resident_id"],
                        title="Complaint verified",
                        body=f'{before.get("tracking_number")} was verified by barangay staff.',
                        link=f'/track?tracking={before.get("tracking_number")}',
                        complaint_id=complaint_id, cur=cur,
                    )
            elif action == "assign":
                staff_id_raw = request.form.get("assigned_staff_id", "")
                assigned_staff_id, assigned = resolve_staff_assignment(staff_id_raw, assigned)
                if not assigned_staff_id and not assigned:
                    flash("Please select a staff member.", "error")
                    return redirect(url_for("admin_complaint", complaint_id=complaint_id))
                cur.execute("SELECT priority, due_at FROM complaints WHERE id = %s", (complaint_id,))
                prow = cur.fetchone() or {}
                due = prow.get("due_at") or compute_due_at(prow.get("priority") or "Normal")
                due_naive = due.replace(tzinfo=None) if getattr(due, "tzinfo", None) else due
                cur.execute(
                    """UPDATE complaints SET status='Assigned', assigned_personnel=%s,
                       assigned_staff_id=%s, due_at=COALESCE(due_at, %s),
                       updated_at=CURRENT_TIMESTAMP
                       WHERE id=%s AND status IN ('Verified','Submitted')""",
                    (assigned, assigned_staff_id, due_naive, complaint_id)
                )
                log_complaint_history(
                    complaint_id, old_status, "Assigned",
                    old_assigned=old_assigned, new_assigned=assigned,
                    note=f"Assigned to {assigned} (staff_id={assigned_staff_id})", cur=cur
                )
                log_activity("complaint.assign", "complaint", complaint_id,
                             details=f"to={assigned} staff_id={assigned_staff_id}", cur=cur)
                notify_tracking(
                    before.get("tracking_number"),
                    "Complaint assigned",
                    body=f'{before.get("tracking_number")} was assigned to staff.',
                    link=f'/track?tracking={before.get("tracking_number")}',
                    complaint_id=complaint_id,
                    resident_id=before.get("resident_id"),
                    cur=cur,
                )
                if before.get("resident_id"):
                    notify_user(
                        "resident", before["resident_id"],
                        title="Complaint assigned",
                        body=f'{before.get("tracking_number")} assigned to {assigned}.',
                        link=f'/track?tracking={before.get("tracking_number")}',
                        complaint_id=complaint_id, cur=cur,
                    )
            elif action == "reassign":
                if old_status not in ("Assigned", "In Progress", "Verified"):
                    flash("Only active cases can be reassigned.", "error")
                    return redirect(url_for("admin_complaint", complaint_id=complaint_id))
                staff_id_raw = request.form.get("assigned_staff_id", "")
                reason = sanitize_text(request.form.get("reassign_reason", ""), 300)
                assigned_staff_id, assigned = resolve_staff_assignment(staff_id_raw, assigned)
                if not assigned_staff_id and not assigned:
                    flash("Please select a staff member to reassign.", "error")
                    return redirect(url_for("admin_complaint", complaint_id=complaint_id))
                new_priority = sanitize_text(request.form.get("priority", ""), 20)
                due_sql = ""
                params = [assigned, assigned_staff_id]
                if new_priority in PRIORITIES:
                    due = compute_due_at(new_priority)
                    due_naive = due.replace(tzinfo=None) if getattr(due, "tzinfo", None) else due
                    due_sql = ", priority = %s, due_at = %s"
                    params.extend([new_priority, due_naive])
                params.append(complaint_id)
                cur.execute(
                    f"""UPDATE complaints SET assigned_personnel=%s, assigned_staff_id=%s,
                       status=CASE WHEN status='Verified' THEN 'Assigned' ELSE status END,
                       updated_at=CURRENT_TIMESTAMP{due_sql}
                       WHERE id=%s""",
                    params
                )
                note = f"Reassigned to {assigned}"
                if reason:
                    note += f" — reason: {reason}"
                if new_priority in PRIORITIES:
                    note += f" (priority {new_priority})"
                log_complaint_history(
                    complaint_id, old_status, old_status if old_status != "Verified" else "Assigned",
                    old_assigned=old_assigned, new_assigned=assigned, note=note, cur=cur
                )
                log_activity("complaint.reassign", "complaint", complaint_id,
                             details=f"to={assigned} staff_id={assigned_staff_id}", cur=cur)
                if before.get("resident_id"):
                    notify_user(
                        "resident", before["resident_id"],
                        title="Complaint reassigned",
                        body=f'{before.get("tracking_number")} reassigned to {assigned}.',
                        link=f'/track?tracking={before.get("tracking_number")}',
                        complaint_id=complaint_id, cur=cur,
                    )
            elif action == "start":
                cur.execute(
                    """UPDATE complaints SET status='In Progress', updated_at=CURRENT_TIMESTAMP
                       WHERE id=%s AND status IN ('Assigned','Verified')""",
                    (complaint_id,)
                )
                log_complaint_history(complaint_id, old_status, "In Progress", note="Work started", cur=cur)
                log_activity("complaint.start", "complaint", complaint_id, cur=cur)
                notify_tracking(
                    before.get("tracking_number"),
                    "Work in progress",
                    body=f'{before.get("tracking_number")} is now In Progress.',
                    link=f'/track?tracking={before.get("tracking_number")}',
                    complaint_id=complaint_id,
                    resident_id=before.get("resident_id"),
                    cur=cur,
                )
            elif action == "escalate":
                reason = sanitize_text(request.form.get("escalation_reason", ""), 500) or "Emergency escalation"
                due = compute_due_at("Urgent")
                due_naive = due.replace(tzinfo=None) if getattr(due, "tzinfo", None) else due
                cur.execute(
                    """
                    UPDATE complaints SET
                        is_escalated = TRUE,
                        escalated_at = CURRENT_TIMESTAMP,
                        escalation_reason = %s,
                        priority = 'Urgent',
                        due_at = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND status NOT IN ('Resolved', 'Confirmed')
                    """,
                    (reason, due_naive, complaint_id),
                )
                log_complaint_history(
                    complaint_id, old_status, old_status,
                    note=f"ESCALATED: {reason}", cur=cur,
                )
                log_activity("complaint.escalate", "complaint", complaint_id,
                             details=reason, cur=cur)
                # Notify all admins
                cur.execute(
                    "SELECT id FROM staff_users WHERE role = 'admin' AND is_active = TRUE"
                )
                for admin in cur.fetchall():
                    notify_user(
                        "staff", admin["id"],
                        title="🚨 Emergency escalation",
                        body=f'{before.get("tracking_number")}: {reason}',
                        link=f"/admin/complaint/{complaint_id}",
                        complaint_id=complaint_id, cur=cur,
                    )
                notify_tracking(
                    before.get("tracking_number"),
                    "Your complaint was escalated",
                    body=f'{before.get("tracking_number")} was marked as urgent.',
                    link=f'/track?tracking={before.get("tracking_number")}',
                    complaint_id=complaint_id,
                    resident_id=before.get("resident_id"),
                    cur=cur,
                )
            elif action == "resolve":
                remarks = sanitize_text(request.form.get("resolution_remarks", ""), 3000)
                if not remarks:
                    flash("Resolution remarks are required.", "error")
                    return redirect(url_for("admin_complaint", complaint_id=complaint_id))
                resolution_photo = None
                after_photo = None
                try:
                    if "resolution_photo" in request.files:
                        f = request.files["resolution_photo"]
                        if f and f.filename:
                            resolution_photo = process_and_save_image(f)
                    if "after_photo" in request.files:
                        f = request.files["after_photo"]
                        if f and f.filename:
                            after_photo = process_and_save_image(f)
                except ValueError as e:
                    flash(str(e), "error")
                    return redirect(url_for("admin_complaint", complaint_id=complaint_id))
                cur.execute(
                    """UPDATE complaints SET status='Resolved',
                       resolution_remarks=%s,
                       resolution_photo_path=COALESCE(%s, resolution_photo_path),
                       after_photo_path=COALESCE(%s, after_photo_path),
                       resolved_at=CURRENT_TIMESTAMP,
                       updated_at=CURRENT_TIMESTAMP
                       WHERE id=%s AND status='In Progress'""",
                    (remarks, resolution_photo, after_photo, complaint_id)
                )
                log_complaint_history(
                    complaint_id, old_status, "Resolved",
                    note=(remarks[:200] if remarks else "Marked resolved"), cur=cur
                )
                log_activity("complaint.resolve", "complaint", complaint_id,
                             details="with_evidence=1" if (resolution_photo or after_photo) else None, cur=cur)
                if before.get("resident_id"):
                    notify_user(
                        "resident", before["resident_id"],
                        title="Complaint resolved — please confirm",
                        body=f'{before.get("tracking_number")} was marked Resolved. Please confirm and rate.',
                        link=f'/track?tracking={before.get("tracking_number")}',
                        complaint_id=complaint_id, cur=cur,
                    )
            elif action == "update":
                updates, params = [], []
                new_status = None
                if status and status in STATUSES:
                    updates.append("status = %s")
                    params.append(status)
                    new_status = status
                if priority and priority in PRIORITIES:
                    updates.append("priority = %s")
                    params.append(priority)
                    # Recalculate due date from now when priority changes on open cases
                    if old_status not in ("Resolved", "Confirmed"):
                        due = compute_due_at(priority)
                        due_naive = due.replace(tzinfo=None) if getattr(due, "tzinfo", None) else due
                        updates.append("due_at = %s")
                        params.append(due_naive)
                if "assigned_personnel" in request.form:
                    updates.append("assigned_personnel = %s")
                    params.append(assigned)
                    # Resolve staff id
                    cur.execute(
                        "SELECT id FROM staff_users WHERE full_name ILIKE %s AND is_active = TRUE LIMIT 1",
                        (assigned or "",)
                    )
                    srow = cur.fetchone()
                    updates.append("assigned_staff_id = %s")
                    params.append(srow["id"] if srow else None)
                # Optional due_at override from form (YYYY-MM-DD)
                due_raw = sanitize_text(request.form.get("due_at", ""), 20)
                if due_raw:
                    try:
                        due_dt = datetime.strptime(due_raw, "%Y-%m-%d")
                        updates.append("due_at = %s")
                        params.append(due_dt)
                    except ValueError:
                        pass
                if updates:
                    updates.append("updated_at = CURRENT_TIMESTAMP")
                    params.append(complaint_id)
                    cur.execute(
                        f"UPDATE complaints SET {', '.join(updates)} WHERE id = %s",
                        params
                    )
                    if new_status and new_status != old_status:
                        log_complaint_history(
                            complaint_id, old_status, new_status,
                            old_assigned=old_assigned, new_assigned=assigned,
                            note="Manual update", cur=cur
                        )
                    log_activity("complaint.update", "complaint", complaint_id,
                                 details=f"status={new_status or old_status}", cur=cur)
            elif action == "send_message":
                body = sanitize_text(request.form.get("body", ""), 1000)
                if body:
                    cur.execute(
                        """INSERT INTO messages (complaint_id, sender_type, sender_name, sender_id, body)
                           VALUES (%s, 'admin', %s, %s, %s)""",
                        (complaint_id, session.get("staff_name") or session.get("admin_user", "Admin"),
                         session.get("staff_id"), body)
                    )
                    cur.execute(
                        """UPDATE messages SET is_read = TRUE
                           WHERE complaint_id = %s AND sender_type = 'resident'""",
                        (complaint_id,)
                    )
                    log_activity("complaint.message", "complaint", complaint_id, cur=cur)
                    notify_tracking(
                        before.get("tracking_number"),
                        "New message from staff",
                        body=(body[:120] if body else "Staff sent a message."),
                        link=f'/track?tracking={before.get("tracking_number")}',
                        complaint_id=complaint_id,
                        resident_id=before.get("resident_id"),
                        cur=cur,
                    )
            conn.commit()
            cur.close()
            conn.close()
            flash("Updated successfully.", "success")
        except Exception as e:
            flash("Update failed.", "error")
            app.logger.error(e)
        return redirect(url_for("admin_complaint", complaint_id=complaint_id))

    # GET
    history = []
    feedback = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM complaints WHERE id = %s", (complaint_id,))
        complaint = cur.fetchone()
        if not complaint:
            flash("Complaint not found.", "error")
            return redirect(url_for("admin_dashboard"))
        if not staff_can_access_complaint(complaint):
            cur.close()
            conn.close()
            flash("You can only view cases assigned to you.", "error")
            return redirect(url_for("admin_dashboard"))
        cur.execute(
            "SELECT * FROM messages WHERE complaint_id = %s ORDER BY created_at ASC",
            (complaint_id,)
        )
        messages = cur.fetchall()
        cur.execute(
            """
            SELECT * FROM complaint_history
            WHERE complaint_id = %s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (complaint_id,)
        )
        history = cur.fetchall()
        cur.execute(
            "SELECT * FROM complaint_feedback WHERE complaint_id = %s",
            (complaint_id,),
        )
        feedback = cur.fetchone()
        # Mark resident messages as read when admin views
        cur.execute(
            """UPDATE messages SET is_read = TRUE
               WHERE complaint_id = %s AND sender_type = 'resident' AND is_read = FALSE""",
            (complaint_id,)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        flash("Error loading complaint.", "error")
        app.logger.error(e)
        return redirect(url_for("admin_dashboard"))

    return render_template(
        "admin_complaint.html",
        complaint=complaint,
        messages=messages,
        history=history,
        feedback=feedback,
        overdue=is_overdue(complaint),
        statuses=STATUSES,
        priorities=PRIORITIES,
        staff_list=list_active_staff(),
    )



@app.route("/admin/staff", methods=["GET", "POST"])
@admin_role_required
def admin_staff():
    """Admin creates and manages responder / tanod accounts."""
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin_staff"))

        action = sanitize_text(request.form.get("action", ""), 30)

        try:
            conn = get_db()
            cur = conn.cursor()

            if action == "create":
                username = sanitize_text(request.form.get("username", ""), 50).lower()
                full_name = sanitize_text(request.form.get("full_name", ""), 150)
                password = request.form.get("password", "")
                role = sanitize_text(request.form.get("role", "responder"), 20)
                if role not in ("responder", "tanod", "admin"):
                    role = "responder"
                if not username or not full_name or len(password) < 6:
                    flash("Username, full name, and password (min 6 chars) are required.", "error")
                elif not re.match(r"^[a-z0-9._-]{3,50}$", username):
                    flash("Username must be 3–50 chars: letters, numbers, . _ - only.", "error")
                else:
                    cur.execute("SELECT id FROM staff_users WHERE username = %s", (username,))
                    if cur.fetchone():
                        flash("That username is already taken.", "error")
                    else:
                        code = next_staff_code(cur)
                        cur.execute(
                            """
                            INSERT INTO staff_users (staff_code, username, password_hash, full_name, role)
                            VALUES (%s, %s, %s, %s, %s)
                            RETURNING id
                            """,
                            (code, username, generate_password_hash(password), full_name, role)
                        )
                        new_id = cur.fetchone()["id"]
                        log_activity(
                            "staff.create", entity_type="staff", entity_id=new_id,
                            details=f"username={username} role={role} code={code}", cur=cur
                        )
                        conn.commit()
                        flash(f"Account created for {full_name} ({role}) — ID {code}.", "success")

            elif action == "toggle":
                uid = int(request.form.get("user_id", 0))
                cur.execute(
                    """
                    UPDATE staff_users
                    SET is_active = NOT is_active
                    WHERE id = %s AND username <> %s
                    """,
                    (uid, session.get("admin_user", ""))
                )
                conn.commit()
                flash("Account status updated.", "success")

            elif action == "reset_password":
                uid = int(request.form.get("user_id", 0))
                new_pw = request.form.get("new_password", "")
                if len(new_pw) < 6:
                    flash("New password must be at least 6 characters.", "error")
                else:
                    cur.execute(
                        "UPDATE staff_users SET password_hash = %s WHERE id = %s",
                        (generate_password_hash(new_pw), uid)
                    )
                    conn.commit()
                    flash("Password updated.", "success")

            cur.close()
            conn.close()
        except Exception as e:
            flash("Could not update staff accounts.", "error")
            app.logger.error(e)

        return redirect(url_for("admin_staff"))

    users = []
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, staff_code, username, full_name, role, is_active, created_at, last_login_at
            FROM staff_users
            ORDER BY role, full_name
            """
        )
        users = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        flash("Could not load staff list.", "error")
        app.logger.error(e)

    return render_template("admin_staff.html", users=users)


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    """Self-service settings for the logged-in staff member: display name + password."""
    staff_id = session.get("staff_id")

    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin_settings"))

        if not staff_id:
            flash("The built-in admin account can't be edited here. Create a personal staff account instead.", "error")
            return redirect(url_for("admin_settings"))

        action = sanitize_text(request.form.get("action", ""), 30)

        try:
            conn = get_db()
            cur = conn.cursor()

            if action == "update_profile":
                full_name = sanitize_text(request.form.get("full_name", ""), 150)
                if not full_name:
                    flash("Display name is required.", "error")
                else:
                    cur.execute(
                        "UPDATE staff_users SET full_name = %s WHERE id = %s",
                        (full_name, staff_id)
                    )
                    conn.commit()
                    session["staff_name"] = full_name
                    flash("Display name updated.", "success")

            elif action == "change_password":
                current_pw = request.form.get("current_password", "")
                new_pw = request.form.get("new_password", "")
                confirm_pw = request.form.get("confirm_password", "")

                cur.execute("SELECT password_hash FROM staff_users WHERE id = %s", (staff_id,))
                row = cur.fetchone()

                if not row or not check_password_hash(row["password_hash"], current_pw):
                    flash("Current password is incorrect.", "error")
                elif len(new_pw) < 6:
                    flash("New password must be at least 6 characters.", "error")
                elif new_pw != confirm_pw:
                    flash("New password and confirmation do not match.", "error")
                else:
                    cur.execute(
                        "UPDATE staff_users SET password_hash = %s WHERE id = %s",
                        (generate_password_hash(new_pw), staff_id)
                    )
                    conn.commit()
                    flash("Password updated successfully.", "success")

            cur.close()
            conn.close()
        except Exception as e:
            flash("Could not update settings.", "error")
            app.logger.error(e)

        return redirect(url_for("admin_settings"))

    # GET
    account = None
    if staff_id:
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT username, full_name, role, is_active, created_at
                FROM staff_users WHERE id = %s
                """,
                (staff_id,)
            )
            account = cur.fetchone()
            cur.close()
            conn.close()
        except Exception as e:
            flash("Could not load account details.", "error")
            app.logger.error(e)

    return render_template("admin_settings.html", account=account)


# ─── API ───────────────────────────────────────────────────────────────────

@app.route("/api/complaints")
def api_complaints():
    """Public feed: privacy-safe fields only (no names, contacts, exact coords)."""
    ip = client_ip()
    if not check_rate_limit(f"api_comp:{ip}", max_requests=60, window_seconds=60):
        return jsonify({"success": False, "error": "Rate limit exceeded"}), 429

    status = sanitize_text(request.args.get("status", ""), 30)
    try:
        limit = min(int(request.args.get("limit", 50)), 50)
    except ValueError:
        limit = 50
    try:
        conn = get_db()
        cur = conn.cursor()
        # Public: no resident PII, no assigned personnel names, no lat/lng
        if status and status in STATUSES:
            cur.execute(
                """SELECT tracking_number, category, priority, status, created_at, updated_at
                   FROM complaints WHERE status = %s
                   ORDER BY created_at DESC LIMIT %s""",
                (status, limit)
            )
        else:
            cur.execute(
                """SELECT tracking_number, category, priority, status, created_at, updated_at
                   FROM complaints ORDER BY created_at DESC LIMIT %s""",
                (limit,)
            )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        result = []
        for r in rows:
            item = dict(r)
            # Mask tracking partially for extra privacy on public board? keep full for trackability
            for k in ("created_at", "updated_at"):
                if item.get(k):
                    item[k] = item[k].isoformat()
            result.append(item)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/stats")
def api_stats():
    """Public aggregate stats only — no PII."""
    ip = client_ip()
    if not check_rate_limit(f"api_stats:{ip}", max_requests=60, window_seconds=60):
        return jsonify({"success": False, "error": "Rate limit exceeded"}), 429
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'Submitted') AS submitted,
                COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved,
                COUNT(*) FILTER (WHERE status = 'Confirmed') AS confirmed,
                COUNT(*) FILTER (WHERE priority = 'Urgent') AS urgent
            FROM complaints
        """)
        stats = dict(cur.fetchone())
        cur.close()
        conn.close()
        return jsonify({"success": True, "data": stats})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/api/admin/activity")
@login_required
def api_admin_activity():
    """Staff activity log (admin only)."""
    if not role_has_permission("view_activity_logs"):
        return jsonify({"success": False, "error": "Forbidden"}), 403
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
    except ValueError:
        limit = 50
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, actor_type, actor_name, action, entity_type, entity_id,
                   details, ip_address, created_at
            FROM activity_logs
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,)
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        data = []
        for r in rows:
            item = dict(r)
            if item.get("created_at"):
                item["created_at"] = item["created_at"].isoformat()
            data.append(item)
        return jsonify({"success": True, "data": data})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"success": False, "error": "Server error"}), 500



# ─── Admin map, exports, reports ───────────────────────────────────────────

@app.route("/admin/map")
@login_required
def admin_map():
    """Complaint map + optional heatmap of geo-tagged cases."""
    open_only = request.args.get("open", "1") != "0"
    points = []
    try:
        conn = get_db()
        cur = conn.cursor()
        q = """
            SELECT id, tracking_number, category, status, priority, location,
                   latitude, longitude, created_at
            FROM complaints
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        """
        params = []
        if open_only:
            q += " AND status NOT IN ('Resolved', 'Confirmed')"
        if session.get("staff_role") in ("responder", "tanod"):
            if session.get("staff_id"):
                q += " AND assigned_staff_id = %s"
                params.append(session.get("staff_id"))
            else:
                q += " AND assigned_personnel ILIKE %s"
                params.append(f"%{session.get('staff_name', '')}%")
        q += " ORDER BY created_at DESC LIMIT 1000"
        cur.execute(q, params)
        points = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
        flash("Could not load map data.", "error")
    return render_template(
        "admin_map.html",
        points=points,
        open_only=open_only,
        points_json=[
            {
                "id": p["id"],
                "tracking": p["tracking_number"],
                "category": p["category"],
                "status": p["status"],
                "priority": p["priority"],
                "location": p["location"],
                "lat": float(p["latitude"]),
                "lng": float(p["longitude"]),
            }
            for p in points
        ],
    )


def _filtered_complaints_for_export():
    """Shared filter builder for export/report routes."""
    status_filter = sanitize_text(request.args.get("status", ""), 30)
    priority_filter = sanitize_text(request.args.get("priority", ""), 20)
    category_filter = sanitize_text(request.args.get("category", ""), 100)
    date_from = sanitize_text(request.args.get("from", ""), 20)
    date_to = sanitize_text(request.args.get("to", ""), 20)
    year = sanitize_text(request.args.get("year", ""), 10)
    month = sanitize_text(request.args.get("month", ""), 10)

    query = """
        SELECT tracking_number, category, location, description, priority, status,
               assigned_personnel, resident_name, created_at, updated_at, due_at,
               resolution_remarks, resolved_at
        FROM complaints WHERE 1=1
    """
    params = []
    if session.get("staff_role") in ("responder", "tanod"):
        if session.get("staff_id"):
            query += " AND assigned_staff_id = %s"
            params.append(session.get("staff_id"))
        else:
            query += " AND assigned_personnel ILIKE %s"
            params.append(f"%{session.get('staff_name', '')}%")
    if status_filter and status_filter in STATUSES:
        query += " AND status = %s"
        params.append(status_filter)
    if priority_filter and priority_filter in PRIORITIES:
        query += " AND priority = %s"
        params.append(priority_filter)
    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)
    if date_from:
        try:
            datetime.strptime(date_from, "%Y-%m-%d")
            query += " AND created_at >= %s::date"
            params.append(date_from)
        except ValueError:
            pass
    if date_to:
        try:
            datetime.strptime(date_to, "%Y-%m-%d")
            query += " AND created_at < (%s::date + INTERVAL '1 day')"
            params.append(date_to)
        except ValueError:
            pass
    if year and year.isdigit():
        query += " AND EXTRACT(YEAR FROM created_at) = %s"
        params.append(int(year))
    if month and month.isdigit() and 1 <= int(month) <= 12:
        query += " AND EXTRACT(MONTH FROM created_at) = %s"
        params.append(int(month))
    query += " ORDER BY created_at DESC LIMIT 5000"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


@app.route("/admin/export/csv")
@login_required
def admin_export_csv():
    import csv
    import io
    try:
        rows = _filtered_complaints_for_export()
    except Exception as e:
        app.logger.error(e)
        flash("Export failed.", "error")
        return redirect(url_for("admin_dashboard"))

    buf = io.StringIO()
    writer = csv.writer(buf)
    headers = [
        "tracking_number", "category", "location", "description", "priority", "status",
        "assigned_personnel", "resident_name", "created_at", "updated_at", "due_at",
        "resolution_remarks", "resolved_at",
    ]
    writer.writerow(headers)
    for r in rows:
        writer.writerow([
            r.get(h) if not hasattr(r.get(h), "isoformat") else r.get(h).isoformat()
            for h in headers
        ])
    from flask import Response
    log_activity("export.csv", details=f"rows={len(rows)}")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=barangay_complaints.csv"},
    )


@app.route("/admin/export/xlsx")
@login_required
def admin_export_xlsx():
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        flash("Excel export requires openpyxl. Install: pip install openpyxl", "error")
        return redirect(url_for("admin_reports"))
    try:
        rows = _filtered_complaints_for_export()
    except Exception as e:
        app.logger.error(e)
        flash("Export failed.", "error")
        return redirect(url_for("admin_reports"))

    wb = Workbook()
    ws = wb.active
    ws.title = "Complaints"
    headers = [
        "Tracking", "Category", "Location", "Description", "Priority", "Status",
        "Assigned", "Resident", "Created", "Updated", "Due", "Resolution remarks", "Resolved at",
    ]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for r in rows:
        ws.append([
            r.get("tracking_number"),
            r.get("category"),
            r.get("location"),
            r.get("description"),
            r.get("priority"),
            r.get("status"),
            r.get("assigned_personnel"),
            r.get("resident_name"),
            r["created_at"].isoformat() if r.get("created_at") else "",
            r["updated_at"].isoformat() if r.get("updated_at") else "",
            r["due_at"].isoformat() if r.get("due_at") else "",
            r.get("resolution_remarks"),
            r["resolved_at"].isoformat() if r.get("resolved_at") else "",
        ])
    import io
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    from flask import Response
    log_activity("export.xlsx", details=f"rows={len(rows)}")
    return Response(
        buf.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=barangay_complaints.xlsx"},
    )


@app.route("/admin/reports")
@login_required
def admin_reports():
    """Monthly / yearly report hub."""
    year = sanitize_text(request.args.get("year", ""), 10)
    month = sanitize_text(request.args.get("month", ""), 10)
    if not year:
        year = str(now_ph().year)
    summary = {
        "total": 0, "resolved": 0, "confirmed": 0, "open": 0,
        "by_category": [], "by_status": [], "avg_rating": None,
    }
    try:
        conn = get_db()
        cur = conn.cursor()
        params = [int(year)]
        month_clause = ""
        if month and month.isdigit():
            month_clause = " AND EXTRACT(MONTH FROM created_at) = %s"
            params.append(int(month))
        role_clause = ""
        if session.get("staff_role") in ("responder", "tanod"):
            role_clause = " AND assigned_personnel ILIKE %s"
            params.append(f"%{session.get('staff_name', '')}%")

        cur.execute(
            f"""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved,
                COUNT(*) FILTER (WHERE status = 'Confirmed') AS confirmed,
                COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Confirmed')) AS open
            FROM complaints
            WHERE EXTRACT(YEAR FROM created_at) = %s {month_clause} {role_clause}
            """,
            params,
        )
        summary.update(dict(cur.fetchone() or {}))

        cur.execute(
            f"""
            SELECT category, COUNT(*) AS cnt
            FROM complaints
            WHERE EXTRACT(YEAR FROM created_at) = %s {month_clause} {role_clause}
            GROUP BY category ORDER BY cnt DESC
            """,
            params,
        )
        summary["by_category"] = cur.fetchall()

        cur.execute(
            f"""
            SELECT status, COUNT(*) AS cnt
            FROM complaints
            WHERE EXTRACT(YEAR FROM created_at) = %s {month_clause} {role_clause}
            GROUP BY status
            """,
            params,
        )
        summary["by_status"] = cur.fetchall()

        cur.execute(
            f"""
            SELECT ROUND(AVG(f.rating)::numeric, 2) AS avg_rating
            FROM complaint_feedback f
            JOIN complaints c ON c.id = f.complaint_id
            WHERE EXTRACT(YEAR FROM c.created_at) = %s {month_clause.replace('created_at', 'c.created_at') if month_clause else ''}
              {role_clause.replace('assigned_personnel', 'c.assigned_personnel') if role_clause else ''}
            """,
            params,
        )
        summary["avg_rating"] = (cur.fetchone() or {}).get("avg_rating")

        cur.execute(
            "SELECT DISTINCT EXTRACT(YEAR FROM created_at)::int AS y FROM complaints ORDER BY y DESC"
        )
        years = [r["y"] for r in cur.fetchall() if r.get("y")]
        if not years:
            years = [now_ph().year]
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
        years = [now_ph().year]

    return render_template(
        "admin_reports.html",
        summary=summary,
        year=int(year),
        month=int(month) if month and month.isdigit() else None,
        years=years,
        months=list(range(1, 13)),
        categories=get_active_categories(),
        statuses=STATUSES,
        priorities=PRIORITIES,
    )


@app.route("/admin/reports/pdf")
@login_required
def admin_reports_pdf():
    """Generate a simple PDF summary report."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except ImportError:
        flash("PDF export requires reportlab. Install: pip install reportlab", "error")
        return redirect(url_for("admin_reports"))

    year = sanitize_text(request.args.get("year", str(now_ph().year)), 10)
    month = sanitize_text(request.args.get("month", ""), 10)
    # Reuse report summary logic via redirect args
    try:
        conn = get_db()
        cur = conn.cursor()
        params = [int(year)]
        period = year
        month_clause = ""
        if month and month.isdigit():
            month_clause = " AND EXTRACT(MONTH FROM created_at) = %s"
            params.append(int(month))
            period = f"{year}-{int(month):02d}"
        cur.execute(
            f"""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'Resolved') AS resolved,
                COUNT(*) FILTER (WHERE status = 'Confirmed') AS confirmed,
                COUNT(*) FILTER (WHERE status NOT IN ('Resolved', 'Confirmed')) AS open
            FROM complaints
            WHERE EXTRACT(YEAR FROM created_at) = %s {month_clause}
            """,
            params,
        )
        s = dict(cur.fetchone() or {})
        cur.execute(
            f"""
            SELECT category, COUNT(*) AS cnt FROM complaints
            WHERE EXTRACT(YEAR FROM created_at) = %s {month_clause}
            GROUP BY category ORDER BY cnt DESC
            """,
            params,
        )
        cats = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
        flash("Could not build PDF.", "error")
        return redirect(url_for("admin_reports"))

    import io
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("Barangay Care — Complaint Report", styles["Title"]))
    story.append(Paragraph(f"Period: <b>{period}</b>", styles["Normal"]))
    story.append(Paragraph(f"Generated: {format_ph(now_ph())}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        f"Total: {s.get('total', 0)} · Open: {s.get('open', 0)} · "
        f"Resolved: {s.get('resolved', 0)} · Confirmed: {s.get('confirmed', 0)}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("By category", styles["Heading2"]))
    data = [["Category", "Count"]] + [[c["category"], str(c["cnt"])] for c in cats]
    if len(data) == 1:
        data.append(["—", "0"])
    table = Table(data, colWidths=[10 * cm, 4 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d9488")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.Color(0.95, 0.98, 0.97)]),
    ]))
    story.append(table)
    doc.build(story)
    buf.seek(0)
    from flask import Response
    log_activity("export.pdf", details=f"period={period}")
    return Response(
        buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=barangay_report_{period}.pdf"},
    )



# ─── Categories management ─────────────────────────────────────────────────

@app.route("/admin/categories", methods=["GET", "POST"])
@admin_role_required
def admin_categories():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin_categories"))
        action = sanitize_text(request.form.get("action", ""), 30)
        try:
            conn = get_db()
            cur = conn.cursor()
            if action == "create":
                name = sanitize_text(request.form.get("name", ""), 100)
                desc = sanitize_text(request.form.get("description", ""), 255) or None
                if not name:
                    flash("Category name is required.", "error")
                else:
                    cur.execute(
                        """
                        INSERT INTO categories (name, description, sort_order)
                        VALUES (%s, %s, COALESCE((SELECT MAX(sort_order)+1 FROM categories), 0))
                        """,
                        (name, desc),
                    )
                    log_activity("category.create", entity_type="category", details=name, cur=cur)
                    conn.commit()
                    flash(f"Category “{name}” created.", "success")
            elif action == "toggle":
                cid = int(request.form.get("category_id", 0))
                cur.execute(
                    "UPDATE categories SET is_active = NOT is_active WHERE id = %s RETURNING name, is_active",
                    (cid,),
                )
                row = cur.fetchone()
                log_activity("category.toggle", entity_type="category", entity_id=cid,
                             details=str(row), cur=cur)
                conn.commit()
                flash("Category updated.", "success")
            elif action == "delete":
                cid = int(request.form.get("category_id", 0))
                cur.execute("SELECT name FROM categories WHERE id = %s", (cid,))
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "SELECT COUNT(*) AS cnt FROM complaints WHERE category = %s",
                        (row["name"],),
                    )
                    if (cur.fetchone() or {}).get("cnt", 0) > 0:
                        flash("Cannot delete a category still used by complaints. Deactivate it instead.", "error")
                    else:
                        cur.execute("DELETE FROM categories WHERE id = %s", (cid,))
                        log_activity("category.delete", entity_type="category", entity_id=cid,
                                     details=row["name"], cur=cur)
                        conn.commit()
                        flash("Category deleted.", "success")
            cur.close()
            conn.close()
        except Exception as e:
            app.logger.error(e)
            flash("Could not update categories.", "error")
        return redirect(url_for("admin_categories"))

    cats = []
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.*, (
                SELECT COUNT(*) FROM complaints WHERE category = c.name
            ) AS usage_count
            FROM categories c
            ORDER BY c.sort_order, c.name
            """
        )
        cats = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
    return render_template("admin_categories.html", categories=cats)


# ─── Backup / restore ──────────────────────────────────────────────────────

@app.route("/admin/backup")
@admin_role_required
def admin_backup():
    """Download a JSON backup of core tables."""
    import json
    from flask import Response
    tables = [
        "categories", "staff_users", "residents", "complaints",
        "messages", "complaint_history", "complaint_feedback",
        "notifications", "activity_logs",
    ]
    payload = {"version": 1, "exported_at": now_ph().isoformat(), "tables": {}}
    try:
        conn = get_db()
        cur = conn.cursor()
        for table in tables:
            try:
                cur.execute(f"SELECT * FROM {table} ORDER BY 1")
                rows = []
                for r in cur.fetchall():
                    item = dict(r)
                    for k, v in list(item.items()):
                        if hasattr(v, "isoformat"):
                            item[k] = v.isoformat()
                    rows.append(item)
                payload["tables"][table] = rows
            except Exception as te:
                payload["tables"][table] = {"error": str(te)}
        cur.close()
        conn.close()
        log_activity("backup.create", details=f"tables={len(tables)}")
        body = json.dumps(payload, indent=2, default=str)
        return Response(
            body,
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=barangay_backup_{now_ph().strftime('%Y%m%d_%H%M')}.json"
            },
        )
    except Exception as e:
        app.logger.error(e)
        flash("Backup failed.", "error")
        return redirect(url_for("admin_settings"))


@app.route("/admin/restore", methods=["GET", "POST"])
@admin_role_required
def admin_restore():
    """Restore from a JSON backup (upserts categories; does not wipe existing data by default)."""
    if request.method == "GET":
        return render_template("admin_restore.html")

    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token.", "error")
        return redirect(url_for("admin_restore"))

    f = request.files.get("backup_file")
    if not f or not f.filename:
        flash("Please choose a backup JSON file.", "error")
        return redirect(url_for("admin_restore"))

    import json
    try:
        data = json.loads(f.read().decode("utf-8"))
        tables = data.get("tables") or {}
        conn = get_db()
        cur = conn.cursor()
        restored = []

        # Restore categories safely
        for cat in tables.get("categories") or []:
            if isinstance(cat, dict) and cat.get("name"):
                cur.execute(
                    """
                    INSERT INTO categories (name, description, is_active, sort_order)
                    VALUES (%s, %s, COALESCE(%s, TRUE), COALESCE(%s, 0))
                    ON CONFLICT (name) DO UPDATE SET
                        description = EXCLUDED.description,
                        is_active = EXCLUDED.is_active,
                        sort_order = EXCLUDED.sort_order
                    """,
                    (
                        cat.get("name"),
                        cat.get("description"),
                        cat.get("is_active", True),
                        cat.get("sort_order", 0),
                    ),
                )
        restored.append("categories")

        # Restore staff (skip password hashes overwrite if username exists — only insert missing)
        for u in tables.get("staff_users") or []:
            if not isinstance(u, dict) or not u.get("username"):
                continue
            cur.execute("SELECT id FROM staff_users WHERE username = %s", (u["username"],))
            if cur.fetchone():
                continue
            cur.execute(
                """
                INSERT INTO staff_users (staff_code, username, password_hash, full_name, email, role, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, COALESCE(%s, TRUE))
                ON CONFLICT (username) DO NOTHING
                """,
                (
                    u.get("staff_code"),
                    u["username"],
                    u.get("password_hash") or generate_password_hash("ChangeMe123!"),
                    u.get("full_name") or u["username"],
                    u.get("email"),
                    u.get("role") or "responder",
                    u.get("is_active", True),
                ),
            )
        restored.append("staff_users")

        # Residents (by email)
        for res in tables.get("residents") or []:
            if not isinstance(res, dict) or not res.get("email"):
                continue
            cur.execute("SELECT id FROM residents WHERE email = %s", (res["email"],))
            if cur.fetchone():
                continue
            cur.execute(
                """
                INSERT INTO residents (email, password_hash, full_name, contact, address, is_active)
                VALUES (%s, %s, %s, %s, %s, COALESCE(%s, TRUE))
                ON CONFLICT (email) DO NOTHING
                """,
                (
                    res["email"],
                    res.get("password_hash") or generate_password_hash("ChangeMe123!"),
                    res.get("full_name") or "Resident",
                    res.get("contact"),
                    res.get("address"),
                    res.get("is_active", True),
                ),
            )
        restored.append("residents")

        tracking_to_id = {}
        old_id_to_tracking = {}
        for c in tables.get("complaints") or []:
            if not isinstance(c, dict) or not c.get("tracking_number"):
                continue
            if c.get("id"):
                old_id_to_tracking[c["id"]] = c["tracking_number"]
            cur.execute(
                "SELECT id FROM complaints WHERE tracking_number = %s",
                (c["tracking_number"],),
            )
            existing = cur.fetchone()
            if existing:
                tracking_to_id[c["tracking_number"]] = existing["id"]
                continue
            cur.execute(
                """
                INSERT INTO complaints (
                    tracking_number, category, location, description, photo_path,
                    priority, status, assigned_personnel, resident_name, resident_contact,
                    latitude, longitude, is_escalated, escalation_reason,
                    resolution_remarks, resolution_photo_path, after_photo_path
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    COALESCE(%s, FALSE), %s, %s, %s, %s
                )
                RETURNING id
                """,
                (
                    c.get("tracking_number"),
                    c.get("category") or "Other",
                    c.get("location") or "—",
                    c.get("description") or "—",
                    c.get("photo_path"),
                    c.get("priority") or "Normal",
                    c.get("status") or "Submitted",
                    c.get("assigned_personnel"),
                    c.get("resident_name"),
                    c.get("resident_contact"),
                    c.get("latitude"),
                    c.get("longitude"),
                    c.get("is_escalated"),
                    c.get("escalation_reason"),
                    c.get("resolution_remarks"),
                    c.get("resolution_photo_path"),
                    c.get("after_photo_path"),
                ),
            )
            tracking_to_id[c["tracking_number"]] = cur.fetchone()["id"]
        restored.append("complaints")

        msg_count = 0
        for m in tables.get("messages") or []:
            if not isinstance(m, dict):
                continue
            tracking = old_id_to_tracking.get(m.get("complaint_id"))
            new_cid = tracking_to_id.get(tracking) if tracking else None
            if not new_cid:
                continue
            cur.execute(
                """
                INSERT INTO messages (complaint_id, sender_type, sender_name, sender_id, body, is_read)
                VALUES (%s, %s, %s, %s, %s, COALESCE(%s, FALSE))
                """,
                (
                    new_cid,
                    m.get("sender_type") or "resident",
                    m.get("sender_name") or "Unknown",
                    m.get("sender_id"),
                    m.get("body") or "",
                    m.get("is_read"),
                ),
            )
            msg_count += 1
        if msg_count:
            restored.append(f"messages({msg_count})")

        log_activity("backup.restore", details=f"restored={','.join(restored)}", cur=cur)
        conn.commit()
        cur.close()
        conn.close()
        flash(
            f"Restore completed for: {', '.join(restored)}. "
            "Existing tracking numbers were skipped. For wipe-and-restore use a PostgreSQL dump.",
            "success",
        )
    except Exception as e:
        app.logger.error(e)
        flash(f"Restore failed: {e}", "error")
    return redirect(url_for("admin_restore"))



@app.route("/admin/activity")
@admin_role_required
def admin_activity():
    """Administrative activity log browser."""
    action_filter = sanitize_text(request.args.get("action", ""), 80)
    actor_filter = sanitize_text(request.args.get("actor", ""), 150)
    try:
        limit = min(int(request.args.get("limit", 100)), 300)
    except ValueError:
        limit = 100
    logs = []
    try:
        conn = get_db()
        cur = conn.cursor()
        q = """
            SELECT id, actor_type, actor_name, action, entity_type, entity_id,
                   details, ip_address, created_at
            FROM activity_logs WHERE 1=1
        """
        params = []
        if action_filter:
            q += " AND action ILIKE %s"
            params.append(f"%{action_filter}%")
        if actor_filter:
            q += " AND actor_name ILIKE %s"
            params.append(f"%{actor_filter}%")
        q += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        cur.execute(q, params)
        logs = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.error(e)
        flash("Could not load activity logs.", "error")
    return render_template(
        "admin_activity.html",
        logs=logs,
        action_filter=action_filter,
        actor_filter=actor_filter,
        limit=limit,
    )



# ─── Web Push (tracking-number based, no account) ──────────────────────────

@app.route("/api/push/vapid-public-key")
def api_push_vapid_public_key():
    if not VAPID_PUBLIC_KEY:
        return jsonify({"error": "Web Push not configured"}), 503
    return jsonify({"publicKey": VAPID_PUBLIC_KEY})


@app.route("/api/push/subscribe", methods=["POST"])
def api_push_subscribe():
    """Subscribe this browser to push for a tracking number."""
    data = request.get_json(silent=True) or {}
    tracking = sanitize_text(data.get("tracking_number") or data.get("tracking") or "", 50)
    sub = data.get("subscription") or {}
    endpoint = (sub.get("endpoint") or "").strip()
    keys = sub.get("keys") or {}
    p256dh = (keys.get("p256dh") or "").strip()
    auth = (keys.get("auth") or "").strip()
    if not tracking or not endpoint or not p256dh or not auth:
        return jsonify({"error": "tracking_number and subscription keys required"}), 400
    # Verify tracking exists
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM complaints WHERE tracking_number = %s",
            (tracking,),
        )
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Unknown tracking number"}), 404
        cur.execute(
            """
            INSERT INTO push_subscriptions (tracking_number, endpoint, p256dh, auth, user_agent)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (tracking_number, endpoint) DO UPDATE SET
                p256dh = EXCLUDED.p256dh,
                auth = EXCLUDED.auth,
                user_agent = EXCLUDED.user_agent
            """,
            (tracking, endpoint, p256dh, auth, (request.headers.get("User-Agent") or "")[:300]),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": "Could not save subscription"}), 500


@app.route("/api/push/unsubscribe", methods=["POST"])
def api_push_unsubscribe():
    data = request.get_json(silent=True) or {}
    tracking = sanitize_text(data.get("tracking_number") or data.get("tracking") or "", 50)
    endpoint = ((data.get("endpoint") or (data.get("subscription") or {}).get("endpoint")) or "").strip()
    if not tracking or not endpoint:
        return jsonify({"error": "tracking_number and endpoint required"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM push_subscriptions WHERE tracking_number = %s AND endpoint = %s",
            (tracking, endpoint),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": "Could not unsubscribe"}), 500


@app.route("/api/push/status")
def api_push_status():
    """Whether Web Push / FCM is configured on the server."""
    return jsonify({
        "web_push_enabled": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
        "fcm_enabled": bool(FIREBASE_CREDENTIALS_JSON or FCM_SERVER_KEY),
        "enabled": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),  # backward compatible
        "public_base_url": PUBLIC_BASE_URL or None,
    })


@app.route("/api/fcm/register", methods=["POST"])
def api_fcm_register():
    """
    Register an Android (or other) FCM device token for a tracking number.
    Called from the Android Studio app after the user enters a tracking number.
    Body JSON: { "tracking_number": "#2026-00001", "token": "...", "platform": "android", "app_version": "1.0" }
    """
    data = request.get_json(silent=True) or {}
    tracking = sanitize_text(data.get("tracking_number") or data.get("tracking") or "", 50)
    token = (data.get("token") or "").strip()
    platform = sanitize_text(data.get("platform", "android"), 20) or "android"
    app_version = sanitize_text(data.get("app_version", ""), 40) or None
    if not token:
        return jsonify({"error": "token required"}), 400
    if not tracking:
        return jsonify({"error": "tracking_number required"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM complaints WHERE tracking_number = %s",
            (tracking,),
        )
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Unknown tracking number"}), 404
        cur.execute(
            """
            INSERT INTO device_tokens (tracking_number, token, platform, app_version, updated_at)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (token) DO UPDATE SET
                tracking_number = EXCLUDED.tracking_number,
                platform = EXCLUDED.platform,
                app_version = EXCLUDED.app_version,
                updated_at = CURRENT_TIMESTAMP
            """,
            (tracking, token, platform, app_version),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": "Could not register token"}), 500


@app.route("/api/fcm/unregister", methods=["POST"])
def api_fcm_unregister():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "token required"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM device_tokens WHERE token = %s", (token,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": "Could not unregister"}), 500


@app.route("/api/fcm/register-staff", methods=["POST"])
@login_required
def api_fcm_register_staff():
    """Staff Android app registers device token for staff notifications."""
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    platform = sanitize_text(data.get("platform", "android"), 20) or "android"
    if not token:
        return jsonify({"error": "token required"}), 400
    staff_id = session.get("staff_id")
    if not staff_id:
        return jsonify({"error": "Staff session required"}), 401
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO device_tokens (staff_id, token, platform, updated_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (token) DO UPDATE SET
                staff_id = EXCLUDED.staff_id,
                platform = EXCLUDED.platform,
                updated_at = CURRENT_TIMESTAMP
            """,
            (staff_id, token, platform),
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        app.logger.error(e)
        return jsonify({"error": "Could not register staff token"}), 500


@app.route("/sw.js")
def service_worker():
    """Serve service worker from root scope."""
    from flask import send_from_directory
    return send_from_directory(
        os.path.join(app.root_path, "static", "js"),
        "sw.js",
        mimetype="application/javascript",
    )


# ─── Error handlers ────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    flash("File too large. Maximum size is 5 MB.", "error")
    return redirect(request.referrer or url_for("index")), 413


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Internal server error"), 500


# ─── Startup ───────────────────────────────────────────────────────────────

with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"Warning: DB init failed: {e}")


if __name__ == "__main__":
    if not os.getenv("SECRET_KEY"):
        print("WARNING: SECRET_KEY not set — a random key is generated each process restart (sessions will reset).")
    if not os.getenv("DATABASE_URL"):
        print("WARNING: DATABASE_URL not set — using local fallback.")
    if not ADMIN_PASSWORD_HASH and not _allow_default_admin:
        print("WARNING: No ADMIN_PASSWORD / ADMIN_PASSWORD_HASH — env bootstrap login disabled.")
    app.run(host="0.0.0.0", port=5000, debug=False)
