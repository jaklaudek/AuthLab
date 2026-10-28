from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, render_template

from app.config import Config
from app.extensions import csrf, db, migrate

__version__ = "0.9.0"


def create_app(config_object: type | str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object or Config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    if not os.environ.get("DATABASE_URL") and not app.config.get("TESTING"):
        db_path = Path(app.instance_path) / "app.db"
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path.as_posix()}"

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    from app import models  # noqa: F401
    from app.admin import admin_bp
    from app.auth import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    @app.context_processor
    def inject_globals():
        from app.auth.session_utils import get_current_user

        return {
            "app_name": app.config.get("APP_DISPLAY_NAME", "AuthLab"),
            "current_user": get_current_user(),
        }

    @app.before_request
    def enforce_session_and_load_user():
        from app.auth.session_utils import (
            enforce_idle_timeout,
            get_current_user,
            touch_session_activity,
        )

        idle_response = enforce_idle_timeout()
        if idle_response is not None:
            return idle_response

        user = get_current_user()
        if user is not None:
            touch_session_activity()

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "version": __version__,
            "app": app.config.get("APP_DISPLAY_NAME", "AuthLab"),
        }

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.session.remove()

    return app
