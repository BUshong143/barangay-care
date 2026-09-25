"""CSRF, rate limiting, uploads, auth decorators."""
import os
import re
import uuid
import hashlib
import secrets
from functools import wraps
from datetime import datetime, timedelta

from flask import session, request, redirect, url_for, flash, abort
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.utils import secure_filename
from PIL import Image
import bleach

from backend.config import (
    SECRET_KEY, UPLOAD_FOLDER, ALLOWED_EXTENSIONS, ALLOWED_MIME,
    ROLE_PERMISSIONS, PRIORITY_DUE_DAYS,
)
from backend.helpers import (
    format_ph, now_ph, role_has_permission, is_overdue,
    get_active_categories, unread_notification_count,
)

csrf_serializer = URLSafeTimedSerializer(SECRET_KEY)
_rate_limit_store = {}

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
    filepath = os.path.join(UPLOAD_FOLDER, unique_name)

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
            out_path = os.path.join(UPLOAD_FOLDER, out_name)
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
        return redirect(url_for("admin.admin_dashboard"))
    return None


def permission_required(permission):
    """Require a specific staff permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("admin_logged_in"):
                flash("Please log in.", "error")
                return redirect(url_for("admin.admin_login", next=request.path))
            if not role_has_permission(permission):
                flash("You do not have permission for that action.", "error")
                return redirect(url_for("admin.admin_dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def admin_role_required(f):
    """Only full admins (not responders/tanod) may access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in.", "error")
            return redirect(url_for("admin.admin_login", next=request.path))
        role = session.get("staff_role") or "admin"
        if role != "admin":
            flash("Only administrators can access that page.", "error")
            return redirect(url_for("admin.admin_dashboard"))
        return f(*args, **kwargs)
    return decorated


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in to access the admin panel.", "error")
            return redirect(url_for("admin.admin_login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def resident_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("resident_logged_in"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("public.resident_login", next=request.path))
        return f(*args, **kwargs)
    return decorated


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