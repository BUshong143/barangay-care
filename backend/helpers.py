"""Shared helpers: time, logging, categories, staff assignment."""
import re
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
    PH_TZ = timezone(timedelta(hours=8))

from flask import session, request, current_app
from backend.config import CATEGORIES, PRIORITY_DUE_DAYS, ROLE_PERMISSIONS
from backend.database import get_db

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
        current_app.logger.error(f"activity log failed: {e}")
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
        current_app.logger.error(f"complaint history failed: {e}")
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
        current_app.logger.error(f"notify failed: {e}")
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
        current_app.logger.error(e)
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
        current_app.logger.error(f"duplicate check: {e}")
    return results



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
        current_app.logger.error(e)
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
            current_app.logger.error(e)
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
            current_app.logger.error(e)
    return None, display


