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


bp = Blueprint("api", __name__)

@bp.route("/api/complaints", endpoint="api_complaints")
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
        current_app.logger.error(e)
        return jsonify({"success": False, "error": "Server error"}), 500


@bp.route("/api/stats", endpoint="api_stats")
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
        current_app.logger.error(e)
        return jsonify({"success": False, "error": "Server error"}), 500


@bp.route("/api/admin/activity", endpoint="api_admin_activity")
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
        current_app.logger.error(e)
        return jsonify({"success": False, "error": "Server error"}), 500



# ─── Admin map, exports, reports ───────────────────────────────────────────

@bp.route("/admin/map", endpoint="admin_map")
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
        current_app.logger.error(e)
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


@bp.route("/admin/export/csv", endpoint="admin_export_csv")
@login_required
def admin_export_csv():
    import csv
    import io
    try:
        rows = _filtered_complaints_for_export()
    except Exception as e:
        current_app.logger.error(e)
        flash("Export failed.", "error")
        return redirect(url_for("admin.admin_dashboard"))

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


@bp.route("/admin/export/xlsx", endpoint="admin_export_xlsx")
@login_required
def admin_export_xlsx():
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError:
        flash("Excel export requires openpyxl. Install: pip install openpyxl", "error")
        return redirect(url_for("api.admin_reports"))
    try:
        rows = _filtered_complaints_for_export()
    except Exception as e:
        current_app.logger.error(e)
        flash("Export failed.", "error")
        return redirect(url_for("api.admin_reports"))

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


@bp.route("/admin/reports", endpoint="admin_reports")
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
        current_app.logger.error(e)
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


@bp.route("/admin/reports/pdf", endpoint="admin_reports_pdf")
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
        return redirect(url_for("api.admin_reports"))

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
        current_app.logger.error(e)
        flash("Could not build PDF.", "error")
        return redirect(url_for("api.admin_reports"))

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

@bp.route("/admin/categories", methods=["GET", "POST"], endpoint="admin_categories")
@admin_role_required
def admin_categories():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not validate_csrf_token(token):
            flash("Invalid security token.", "error")
            return redirect(url_for("api.admin_categories"))
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
            current_app.logger.error(e)
            flash("Could not update categories.", "error")
        return redirect(url_for("api.admin_categories"))

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
        current_app.logger.error(e)
    return render_template("admin_categories.html", categories=cats)


# ─── Backup / restore ──────────────────────────────────────────────────────

@bp.route("/admin/backup", endpoint="admin_backup")
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
        current_app.logger.error(e)
        flash("Backup failed.", "error")
        return redirect(url_for("admin.admin_settings"))


@bp.route("/admin/restore", methods=["GET", "POST"], endpoint="admin_restore")
@admin_role_required
def admin_restore():
    """Restore from a JSON backup (upserts categories; does not wipe existing data by default)."""
    if request.method == "GET":
        return render_template("admin_restore.html")

    token = request.form.get("csrf_token", "")
    if not validate_csrf_token(token):
        flash("Invalid security token.", "error")
        return redirect(url_for("api.admin_restore"))

    f = request.files.get("backup_file")
    if not f or not f.filename:
        flash("Please choose a backup JSON file.", "error")
        return redirect(url_for("api.admin_restore"))

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
        current_app.logger.error(e)
        flash(f"Restore failed: {e}", "error")
    return redirect(url_for("api.admin_restore"))



@bp.route("/admin/activity", endpoint="admin_activity")
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
        current_app.logger.error(e)
        flash("Could not load activity logs.", "error")
    return render_template(
        "admin_activity.html",
        logs=logs,
        action_filter=action_filter,
        actor_filter=actor_filter,
        limit=limit,
    )



# ─── Web Push (tracking-number based, no account) ──────────────────────────

@bp.route("/api/push/vapid-public-key", endpoint="api_push_vapid_public_key")
def api_push_vapid_public_key():
    if not VAPID_PUBLIC_KEY:
        return jsonify({"error": "Web Push not configured"}), 503
    return jsonify({"publicKey": VAPID_PUBLIC_KEY})


@bp.route("/api/push/subscribe", methods=["POST"], endpoint="api_push_subscribe")
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
        current_app.logger.error(e)
        return jsonify({"error": "Could not save subscription"}), 500


@bp.route("/api/push/unsubscribe", methods=["POST"], endpoint="api_push_unsubscribe")
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
        current_app.logger.error(e)
        return jsonify({"error": "Could not unsubscribe"}), 500


@bp.route("/api/push/status", endpoint="api_push_status")
def api_push_status():
    """Whether Web Push / FCM is configured (reads env at request time)."""
    import os
    vapid_pub = (os.getenv("VAPID_PUBLIC_KEY") or "").strip()
    vapid_priv = (os.getenv("VAPID_PRIVATE_KEY") or "").strip()
    fb = (os.getenv("FIREBASE_CREDENTIALS_JSON") or "").strip()
    fcm_key = (os.getenv("FCM_SERVER_KEY") or "").strip()
    base = (os.getenv("PUBLIC_BASE_URL") or "").rstrip("/")
    return jsonify({
        "web_push_enabled": bool(vapid_pub and vapid_priv),
        "fcm_enabled": bool(fb or fcm_key),
        "enabled": bool(vapid_pub and vapid_priv),
        "public_base_url": base or None,
        # diagnostics (no secrets): whether each var is present
        "env_present": {
            "PUBLIC_BASE_URL": bool(base),
            "FIREBASE_CREDENTIALS_JSON": bool(fb),
            "FCM_SERVER_KEY": bool(fcm_key),
            "VAPID_PUBLIC_KEY": bool(vapid_pub),
            "VAPID_PRIVATE_KEY": bool(vapid_priv),
            "DATABASE_URL": bool((os.getenv("DATABASE_URL") or "").strip()),
            "SECRET_KEY": bool((os.getenv("SECRET_KEY") or "").strip()),
        },
    })


@bp.route("/api/fcm/register", methods=["POST"], endpoint="api_fcm_register")
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
        current_app.logger.error(e)
        return jsonify({"error": "Could not register token"}), 500


@bp.route("/api/fcm/unregister", methods=["POST"], endpoint="api_fcm_unregister")
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
        current_app.logger.error(e)
        return jsonify({"error": "Could not unregister"}), 500


@bp.route("/api/fcm/register-staff", methods=["POST"], endpoint="api_fcm_register_staff")
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
        current_app.logger.error(e)
        return jsonify({"error": "Could not register staff token"}), 500


@bp.route("/sw.js", endpoint="service_worker")
def service_worker():
    """Serve service worker from root scope."""
    from flask import send_from_directory
    return send_from_directory(
        os.path.join(current_app.root_path, "static", "js"),
        "sw.js",
        mimetype="application/javascript",
    )


