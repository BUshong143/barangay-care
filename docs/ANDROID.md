# Android app + push notifications

The web system is the source of truth. Push works in two layers:

| Channel | Who gets it | When |
|---------|-------------|------|
| **Web Push** (VAPID) | Browser / Chrome on Android (and desktop) | Always free; needs **HTTPS** in production |
| **FCM** (Firebase) | Native Android app built in Android Studio | After you register the device token |

Both are keyed by **tracking number** (no resident account required).

```
Staff updates complaint
        ↓
   notify_tracking()
        ↓
   ┌────────────┬────────────┐
   Web Push     FCM          In-app DB notification
   (browser)    (Android app)
```

---

## 1. Production web deployment (required for real push)

Push **does not work on plain HTTP** (except `localhost`).

1. Deploy Flask behind **HTTPS** (Nginx + Let’s Encrypt, Render, Railway, etc.).
2. Set in production `.env`:

```bash
PUBLIC_BASE_URL=https://your-domain.gov.ph
SECURE_COOKIES=true
FLASK_ENV=production

# Web Push
VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...
VAPID_CLAIM_EMAIL=mailto:admin@your-domain.gov.ph

# Android FCM (when ready)
FIREBASE_CREDENTIALS_JSON=/path/to/firebase-service-account.json
# or FCM_SERVER_KEY=...   (legacy)
```

3. Confirm:
   - `https://your-domain/api/push/status` → `"web_push_enabled": true`
   - Track page → **Enable alerts** works on phone Chrome

---

## 2. Firebase project (for Android Studio app)

1. Open [Firebase Console](https://console.firebase.google.com/) → Create project  
2. Add an **Android** app with your package name, e.g. `ph.barangay.care`  
3. Download `google-services.json` → put in Android app module  
4. Project settings → **Service accounts** → Generate new private key → save JSON  
5. On the server:

```bash
# path to the service account file
FIREBASE_CREDENTIALS_JSON=/var/secrets/firebase-adminsdk.json
pip install firebase-admin
```

Restart Gunicorn after setting this.

---

## 3. Android Studio app (outline)

### Option A — Native app (recommended for FCM)

1. New project (Empty Activity), package e.g. `ph.barangay.care`
2. Add Firebase Cloud Messaging via Firebase Assistant or:

```gradle
// app/build.gradle
implementation platform('com.google.firebase:firebase-bom:33.1.0')
implementation 'com.google.firebase:firebase-messaging'
```

3. `AndroidManifest.xml` — internet permission, default notification channel  
4. Create `MyFirebaseMessagingService` extending `FirebaseMessagingService`  
5. On app start / after user enters tracking number:

```kotlin
FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
    val body = JSONObject()
        .put("tracking_number", trackingNumber)  // e.g. "#2026-00042"
        .put("token", token)
        .put("platform", "android")
        .put("app_version", BuildConfig.VERSION_NAME)

    // POST https://your-domain.gov.ph/api/fcm/register
    // Content-Type: application/json
    // body.toString()
}
```

6. When a notification is tapped, open:

`https://your-domain.gov.ph/track?tracking=TRACKING_NUMBER`

or an in-app WebView / native detail screen using the same tracking API.

### Option B — Trusted Web Activity (TWA)

- Wrap the **HTTPS** website with [Bubblewrap](https://github.com/GoogleChromeLabs/bubblewrap) / PWA Builder  
- Uses **Web Push** only (no FCM code needed)  
- User still taps **Enable alerts** once on the Track page  

Good if you mainly want “install on home screen” without native code.

### Option C — WebView only

- Plain WebView often **blocks** Web Push  
- Prefer Option A (FCM) or Option B (TWA), not a raw WebView  

---

## 4. API contract (Android ↔ Flask)

### Register device for a complaint

```http
POST /api/fcm/register
Content-Type: application/json

{
  "tracking_number": "#2026-00042",
  "token": "<FCM registration token>",
  "platform": "android",
  "app_version": "1.0.0"
}
```

### Unregister

```http
POST /api/fcm/unregister
{ "token": "<FCM registration token>" }
```

### Staff app (optional)

```http
POST /api/fcm/register-staff
Cookie: <staff session after login>
{ "token": "...", "platform": "android" }
```

### Check server capability

```http
GET /api/push/status
→ { "web_push_enabled": true, "fcm_enabled": true, "public_base_url": "https://..." }
```

---

## 5. Resident flow (no account)

1. Submit on web or in-app WebView → get tracking number  
2. **Web:** Track → Enable alerts (Web Push)  
3. **Android app:** Enter tracking number → app calls `/api/fcm/register`  
4. Staff changes status → server sends Web Push **and** FCM  

---

## 6. Checklist before launch

| Item | Done |
|------|------|
| Site on HTTPS | |
| `PUBLIC_BASE_URL` set | |
| VAPID keys set, Web Push tested on phone Chrome | |
| Firebase project + `google-services.json` | |
| Service account on server, `firebase-admin` installed | |
| Android app registers token after user enters tracking # | |
| Test: resolve a complaint → notification on phone | |

---

## 7. Troubleshooting

- **No Web Push:** not HTTPS, VAPID missing, or user denied permission  
- **No FCM:** token not registered, wrong tracking number, `FIREBASE_CREDENTIALS_JSON` missing, or app not using the same Firebase project  
- **Clicks open wrong host:** set `PUBLIC_BASE_URL` to the public HTTPS URL  
'''
