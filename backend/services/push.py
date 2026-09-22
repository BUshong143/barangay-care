"""Web Push (VAPID) and FCM (Android) delivery."""
import json
import os
from flask import request, current_app

from backend.config import (
    VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_CLAIM_EMAIL,
    FIREBASE_CREDENTIALS_JSON, FCM_SERVER_KEY, PUBLIC_BASE_URL,
)
from backend.database import get_db
from backend.helpers import notify_user

def send_web_push_for_tracking(tracking_number, title, body=None, url=None):
    """Send free Web Push to all browsers subscribed for this tracking number."""
    if not tracking_number or not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        return 0
    try:
        from pywebpush import webpush, WebPushException
    except ImportError:
        current_app.logger.warning("pywebpush not installed — skip Web Push")
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
                    current_app.logger.warning(f"webpush fail: {e}")
        for did in dead:
            cur.execute("DELETE FROM push_subscriptions WHERE id = %s", (did,))
        if dead:
            conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        current_app.logger.error(f"send_web_push_for_tracking: {e}")
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
    import os
    creds = (os.getenv("FIREBASE_CREDENTIALS_JSON") or FIREBASE_CREDENTIALS_JSON or "").strip()
    if not creds:
        return None
    try:
        import firebase_admin
        from firebase_admin import credentials
        if not firebase_admin._apps:
            path = creds
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
        current_app.logger.error(f"Firebase init failed: {e}")
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
        current_app.logger.error(e)
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
                        current_app.logger.warning(f"FCM send fail: {e}")
        except Exception as e:
            current_app.logger.error(e)

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
                current_app.logger.warning(f"FCM legacy fail: {e}")

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
            current_app.logger.error(e)
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
        current_app.logger.error(e)
    try:
        send_fcm_for_tracking(tracking_number, title, body=body, url=path)
    except Exception as e:
        current_app.logger.error(e)


