"""
Flask application factory and route registration.
"""
import os
from flask import Flask, render_template, flash, redirect, request, url_for
from dotenv import load_dotenv

load_dotenv()

from backend.config import Config, SECRET_KEY, UPLOAD_FOLDER
from backend.database import init_db
from backend.security import inject_globals, set_security_headers

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(_ROOT, "templates"),
        static_folder=os.path.join(_ROOT, "static"),
    )
    app.config.from_object(Config)
    app.secret_key = SECRET_KEY
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    app.context_processor(inject_globals)
    app.after_request(set_security_headers)

    from backend.routes.public import bp as public_bp
    from backend.routes.admin import bp as admin_bp
    from backend.routes.api import bp as api_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    @app.errorhandler(413)
    def too_large(e):
        flash("File too large.", "error")
        return redirect(request.referrer or url_for("public.index")), 413

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="Page not found"), 404

    @app.errorhandler(500)
    def server_error(e):
        try:
            return render_template("error.html", code=500, message="Internal server error"), 500
        except Exception:
            return ("Internal Server Error", 500)

    with app.app_context():
        try:
            init_db()
        except Exception as e:
            print(f"Warning: DB init failed: {e}")

    return app


app = create_app()
