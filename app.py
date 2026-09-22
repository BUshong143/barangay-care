"""
WSGI entrypoint — Railway / Gunicorn: `gunicorn -w 2 -b 0.0.0.0:$PORT app:app`
"""
from backend import create_app

app = create_app()

if __name__ == "__main__":
    import os
    if not os.getenv("SECRET_KEY"):
        print("WARNING: SECRET_KEY not set — sessions reset on restart.")
    if not os.getenv("DATABASE_URL"):
        print("WARNING: DATABASE_URL not set — using local fallback.")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
