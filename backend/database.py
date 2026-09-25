"""Database connection and schema migrations."""
import os
from werkzeug.security import generate_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor

from backend.config import (
    DATABASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD_HASH, CATEGORIES,
)

def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not set. Copy .env.example to .env and configure it."
        )
    # Strip channel_binding if present — some psycopg2/ssl builds do not support it
    dsn = DATABASE_URL.replace("&channel_binding=require", "").replace("?channel_binding=require&", "?").replace("?channel_binding=require", "")
    return psycopg2.connect(
        dsn,
        cursor_factory=RealDictCursor,
        connect_timeout=15,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=3,
    )


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


