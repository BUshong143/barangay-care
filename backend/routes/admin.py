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


bp = Blueprint("admin", __name__)

@bp.route("/admin/login", methods=["GET", "POST"], endpoint="admin_login")
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.admin_dashboard"))

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
            current_app.logger.error(e)

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
                current_app.logger.error(e)
            flash(f"Welcome, {full_name}" + (f" ({staff_code})" if staff_code else "") + ".", "success")
            next_url = request.args.get("next") or url_for("admin.admin_dashboard")
            if not next_url.startswith("/"):
                next_url = url_for("admin.admin_dashboard")
            return redirect(next_url)
        flash("Invalid username or password.", "error")

    return render_template("admin_login.html")


@bp.route("/admin/logout", endpoint="admin_logout")
def admin_logout():
    try:
        log_activity("staff.logout")
    except Exception:
        pass
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("public.index"))


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
        current_app.logger.error(e)
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
        current_app.logger.error(e)
    return needs_attention, category_counts, unread_total, overdue_count, overdue_cases


@bp.route("/admin/dashboard", endpoint="admin_stats_dashboard")
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
        current_app.logger.error(e)
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


@bp.route("/admin/search", endpoint="admin_search")
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


@bp.route("/admin", endpoint="admin_dashboard")
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
        current_app.logger.error(e)
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


@bp.route("/admin/complaint/<int:complaint_id>", methods=["GET", "POST"], endpoint="admin_complaint")
@login_required
def admin_complaint(complaint_id):
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))

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
                return redirect(url_for("admin.admin_dashboard"))
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
                    return redirect(url_for("admin.admin_dashboard"))

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
                    return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))
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
                    return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))
                staff_id_raw = request.form.get("assigned_staff_id", "")
                reason = sanitize_text(request.form.get("reassign_reason", ""), 300)
                assigned_staff_id, assigned = resolve_staff_assignment(staff_id_raw, assigned)
                if not assigned_staff_id and not assigned:
                    flash("Please select a staff member to reassign.", "error")
                    return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))
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
                    return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))
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
                    return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))
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
            current_app.logger.error(e)
        return redirect(url_for("admin.admin_complaint", complaint_id=complaint_id))

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
            return redirect(url_for("admin.admin_dashboard"))
        if not staff_can_access_complaint(complaint):
            cur.close()
            conn.close()
            flash("You can only view cases assigned to you.", "error")
            return redirect(url_for("admin.admin_dashboard"))
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
        current_app.logger.error(e)
        return redirect(url_for("admin.admin_dashboard"))

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



@bp.route("/admin/staff", methods=["GET", "POST"], endpoint="admin_staff")
@admin_role_required
def admin_staff():
    """Admin creates and manages responder / tanod accounts."""
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin.admin_staff"))

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
            current_app.logger.error(e)

        return redirect(url_for("admin.admin_staff"))

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
        current_app.logger.error(e)

    return render_template("admin_staff.html", users=users)


@bp.route("/admin/settings", methods=["GET", "POST"], endpoint="admin_settings")
@login_required
def admin_settings():
    """Self-service settings for the logged-in staff member: display name + password."""
    staff_id = session.get("staff_id")

    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("admin.admin_settings"))

        if not staff_id:
            flash("The built-in admin account can't be edited here. Create a personal staff account instead.", "error")
            return redirect(url_for("admin.admin_settings"))

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
            current_app.logger.error(e)

        return redirect(url_for("admin.admin_settings"))

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
            current_app.logger.error(e)

    return render_template("admin_settings.html", account=account)


# ─── API ───────────────────────────────────────────────────────────────────

