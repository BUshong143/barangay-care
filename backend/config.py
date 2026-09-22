"""Application configuration from environment."""
import os
import secrets
from datetime import timedelta
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SECURE_COOKIES", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    DATABASE_URL = os.getenv("DATABASE_URL", "").strip() or os.getenv(
        "DATABASE_URL_FALLBACK", "postgresql://localhost:5432/barangay_care"
    )

    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    _admin_pw_hash_env = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
    _admin_pw_env = os.getenv("ADMIN_PASSWORD", "").strip()
    _allow_default_admin = os.getenv("ALLOW_DEFAULT_ADMIN", "").lower() in ("1", "true", "yes")
    _is_dev = os.getenv("FLASK_ENV", "").lower() in ("development", "dev") or os.getenv(
        "ENV", ""
    ).lower() in ("development", "dev")

    if _admin_pw_hash_env:
        ADMIN_PASSWORD_HASH = _admin_pw_hash_env
    elif _admin_pw_env:
        ADMIN_PASSWORD_HASH = generate_password_hash(_admin_pw_env)
    elif _allow_default_admin or _is_dev:
        ADMIN_PASSWORD_HASH = generate_password_hash("BarangayAdmin@2026")
        print(
            "WARNING: Using default admin password. "
            "Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH for production."
        )
    else:
        ADMIN_PASSWORD_HASH = None

    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "uploads"
    )
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
    ALLOWED_MIME = {"image/png", "image/jpeg", "image/gif", "image/webp"}

    VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "").strip()
    VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "").strip()
    VAPID_CLAIM_EMAIL = os.getenv("VAPID_CLAIM_EMAIL", "mailto:admin@barangay.local").strip()
    FIREBASE_CREDENTIALS_JSON = os.getenv("FIREBASE_CREDENTIALS_JSON", "").strip()
    FCM_SERVER_KEY = os.getenv("FCM_SERVER_KEY", "").strip()
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

    STATUSES = [
        "Submitted", "Verified", "Assigned", "In Progress", "Resolved", "Confirmed",
    ]
    PRIORITIES = ["Low", "Normal", "Urgent"]
    CATEGORIES = [
        "Streetlight", "Garbage", "Noise", "Roads", "Drainage", "Public Safety", "Other",
    ]
    PRIORITY_DUE_DAYS = {"Urgent": 1, "Normal": 3, "Low": 7}
    ROLE_PERMISSIONS = {
        "admin": {
            "view_all_cases", "manage_staff", "manage_categories", "view_activity_logs",
            "manage_settings", "view_resident_pii", "reassign", "escalate", "export",
            "backup",
        },
        "responder": {"view_assigned", "update_status", "message", "resolve"},
        "tanod": {"view_assigned", "update_status", "message", "resolve"},
    }


# Module-level aliases used across the package
SECRET_KEY = Config.SECRET_KEY
DATABASE_URL = Config.DATABASE_URL
ADMIN_USERNAME = Config.ADMIN_USERNAME
ADMIN_PASSWORD_HASH = Config.ADMIN_PASSWORD_HASH
UPLOAD_FOLDER = Config.UPLOAD_FOLDER
ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS
ALLOWED_MIME = Config.ALLOWED_MIME
VAPID_PUBLIC_KEY = Config.VAPID_PUBLIC_KEY
VAPID_PRIVATE_KEY = Config.VAPID_PRIVATE_KEY
VAPID_CLAIM_EMAIL = Config.VAPID_CLAIM_EMAIL
FIREBASE_CREDENTIALS_JSON = Config.FIREBASE_CREDENTIALS_JSON
FCM_SERVER_KEY = Config.FCM_SERVER_KEY
PUBLIC_BASE_URL = Config.PUBLIC_BASE_URL
STATUSES = Config.STATUSES
PRIORITIES = Config.PRIORITIES
CATEGORIES = Config.CATEGORIES
PRIORITY_DUE_DAYS = Config.PRIORITY_DUE_DAYS
ROLE_PERMISSIONS = Config.ROLE_PERMISSIONS
