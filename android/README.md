# Android (Firebase)

Package name: **`ph.barangay.care`**

## google-services.json

This folder contains `google-services.json` for Firebase project `barangay-care-39dce`.

Copy into your Android Studio project:

```text
YourAndroidApp/app/google-services.json
```

## Backend

The Flask API lives in `../backend/`.  
Register FCM tokens with:

```http
POST https://YOUR-RAILWAY-URL/api/fcm/register
Content-Type: application/json

{
  "tracking_number": "#2026-00001",
  "token": "<FCM_TOKEN>",
  "platform": "android"
}
```

Server-side FCM needs the **service account** JSON on Railway as `FIREBASE_CREDENTIALS_JSON` (not this google-services.json file).
