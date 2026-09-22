# Project structure

```
barangay-complaint-system/
├── app.py                      # Gunicorn entry: app:app
├── backend/
│   ├── __init__.py             # create_app()
│   ├── application.py          # Flask factory + blueprints
│   ├── config.py               # Env / settings
│   ├── database.py             # get_db(), init_db()
│   ├── helpers.py              # Time, logging, staff helpers
│   ├── security.py             # CSRF, rate limit, uploads, auth
│   ├── routes/
│   │   ├── public.py           # Home, submit, track, uploads
│   │   ├── admin.py            # Staff login, cases, staff mgmt
│   │   └── api.py              # JSON APIs, map, reports, push/FCM
│   └── services/
│       └── push.py             # Web Push + FCM
├── android/
│   ├── google-services.json    # Firebase Android config (ph.barangay.care)
│   └── README.md
├── templates/
├── static/
├── docs/ANDROID.md
├── requirements.txt
└── .env.example
```

## Run

```bash
pip install -r requirements.txt
# set .env
gunicorn -w 2 -b 0.0.0.0:$PORT app:app
```
