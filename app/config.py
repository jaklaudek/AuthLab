from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{(BASE_DIR / 'instance' / 'app.db').as_posix()}",
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

    DEFAULT_MIN_PASSWORD_LENGTH = 12
    DEFAULT_ENTROPY_POLICY_ENABLED = False
    DEFAULT_ENTROPY_MIN_BITS = 60
    DEFAULT_PASSWORD_MAX_AGE_DAYS = 90
    DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES = 15
    DEFAULT_PASSWORD_HISTORY_SIZE = 5

    ADMIN_LOGIN = "ADMIN"
    APP_DISPLAY_NAME = os.environ.get("APP_DISPLAY_NAME", "AuthLab")
    LOGIN_ERROR_MESSAGE = "Login lub hasło niepoprawne"
