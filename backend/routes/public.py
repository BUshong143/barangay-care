"""Route handlers."""
import os
import re
import uuid
import hashlib
import secrets
import csv
import io
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint, render_template, request, jsonify, redirect,
    url_for, flash, session, send_from_directory, abort, Response, current_app
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from backend.config import (
    SECRET_KEY, DATABASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD_HASH,
    UPLOAD_FOLDER, ALLOWED_EXTENSIONS, ALLOWED_MIME, STATUSES, PRIORITIES,
    CATEGORIES, PRIORITY_DUE_DAYS, ROLE_PERMISSIONS,
    VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_CLAIM_EMAIL,
    FIREBASE_CREDENTIALS_JSON, FCM_SERVER_KEY, PUBLIC_BASE_URL,
)
from backend.database import get_db, init_db
from backend.helpers import (
    now_ph, to_ph, format_ph, generate_tracking_number, next_staff_code,
    client_ip, log_activity, log_complaint_history, compute_due_at, is_overdue,
    notify_user, unread_notification_count, get_active_categories,
    find_duplicate_complaints, role_has_permission, staff_can_access_complaint,
    list_active_staff, resolve_staff_assignment, PH_TZ,
)
from backend.services.push import (
    send_web_push_for_tracking, send_fcm_for_tracking, notify_tracking,
    _absolute_url,
)
from backend.security import (
    allowed_file, sanitize_text, generate_csrf_token, validate_csrf_token,
    check_rate_limit, process_and_save_image, admin_only_redirect,
    permission_required, admin_role_required, login_required,
    resident_login_required,
)


bp = Blueprint("public", __name__)

@bp.route("/favicon.ico", endpoint="favicon")
def favicon():
    return redirect(url_for("static", filename="favicon.svg"))

@bp.route("/", endpoint="index")
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
        current_app.logger.error("index stats: %s", e)
    return render_template(
        "index.html",
        categories=get_active_categories(),
        priorities=PRIORITIES,
        public_stats=public_stats,
    )


@bp.route("/submit", methods=["GET", "POST"], endpoint="submit_complaint")
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
        return redirect(url_for("public.submit_complaint"))

    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("public.submit_complaint"))

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
        return redirect(url_for("public.submit_complaint"))
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
                return redirect(url_for("public.submit_complaint"))

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
        current_app.logger.error(f"Submit error: {e}")
        return redirect(url_for("public.submit_complaint"))


@bp.route("/track", methods=["GET", "POST"], endpoint="track")
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
            current_app.logger.error(e)

    return render_template(
        "track.html",
        complaint=complaint,
        messages=messages,
        history=history,
        feedback=feedback,
        tracking=tracking
    )


@bp.route("/track/message", methods=["POST"], endpoint="resident_send_message")
def resident_send_message():
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if not check_rate_limit(f"msg:{ip}", max_requests=15, window_seconds=60):
        flash("Too many messages. Please slow down.", "error")
        return redirect(request.referrer or url_for("public.track"))

    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token.", "error")
        return redirect(request.referrer or url_for("public.track"))

    tracking = sanitize_text(request.form.get("tracking_number", ""), 50)
    body = sanitize_text(request.form.get("body", ""), 1000)
    sender_name = sanitize_text(request.form.get("sender_name", "Resident"), 150) or "Resident"

    if not tracking or not body:
        flash("Message cannot be empty.", "error")
        return redirect(url_for("public.track", tracking=tracking))

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
            return redirect(url_for("public.track"))
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
        current_app.logger.error(e)
    return redirect(url_for("public.track", tracking=tracking))


@bp.route("/confirm/<path:tracking_number>", methods=["POST"], endpoint="confirm_resolution")
def confirm_resolution(tracking_number):
    blocked = admin_only_redirect()
    if blocked:
        return blocked
    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token.", "error")
        return redirect(url_for("public.track", tracking=tracking_number))

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
        current_app.logger.error(e)
    return redirect(url_for("public.track", tracking=tracking_number))


@bp.route("/uploads/<path:filename>", endpoint="serve_upload")
def serve_upload(filename):
    """Serve uploaded images safely (no path traversal)."""
    safe = secure_filename(filename)
    if not safe or ".." in filename or filename.startswith("/"):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, safe)


# ─── Admin auth ────────────────────────────────────────────────────────────


# ─── Resident accounts ─────────────────────────────────────────────────────

@bp.route("/resident/register", methods=["GET", "POST"], endpoint="resident_register")
def resident_register():
    flash("Resident accounts are not used. Track with your number or enable browser alerts.", "success")
    return redirect(url_for("public.track"))

    if session.get("resident_logged_in"):
        return redirect(url_for("public.resident_dashboard"))
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.admin_dashboard"))

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
                return redirect(url_for("public.resident_login"))
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
            return redirect(url_for("public.resident_dashboard"))
        except Exception as e:
            current_app.logger.error(e)
            flash("Registration failed. Please try again.", "error")

    return render_template("resident_register.html")


@bp.route("/resident/login", methods=["GET", "POST"], endpoint="resident_login")
def resident_login():
    flash("Resident accounts are not used. Track with your number or enable browser alerts.", "success")
    return redirect(url_for("admin.admin_login"))

    if session.get("resident_logged_in"):
        return redirect(url_for("public.resident_dashboard"))
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.admin_dashboard"))

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
                next_url = request.args.get("next") or url_for("public.resident_dashboard")
                if not next_url.startswith("/"):
                    next_url = url_for("public.resident_dashboard")
                return redirect(next_url)
            cur.close()
            conn.close()
        except Exception as e:
            current_app.logger.error(e)
        flash("Invalid email or password.", "error")

    return render_template("resident_login.html")


@bp.route("/resident/logout", endpoint="resident_logout")
def resident_logout():
    flash("Resident accounts are not used. Track with your number or enable browser alerts.", "success")
    return redirect(url_for("public.index"))

    try:
        log_activity("resident.logout")
    except Exception:
        pass
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("public.index"))


@bp.route("/resident/dashboard", endpoint="resident_dashboard")
@resident_login_required
def resident_dashboard():
    flash("Resident accounts are not used. Track with your number or enable browser alerts.", "success")
    return redirect(url_for("public.track"))

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
        current_app.logger.error(e)
        flash("Could not load your complaints.", "error")
    return render_template(
        "resident_dashboard.html",
        complaints=complaints,
        stats=stats,
        notifications=notifications,
        current_status=status_filter,
        statuses=STATUSES,
    )


@bp.route("/resident/notifications", endpoint="resident_notifications")
@resident_login_required
def resident_notifications():
    flash("Resident accounts are not used. Track with your number or enable browser alerts.", "success")
    return redirect(url_for("public.track"))

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
        current_app.logger.error(e)
    return render_template("resident_notifications.html", notifications=items)


@bp.route("/resident/notifications/read/<int:nid>", methods=["POST"], endpoint="resident_notification_read")
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
        current_app.logger.error(e)
    return redirect(url_for("public.resident_notifications"))