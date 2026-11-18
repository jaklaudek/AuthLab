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

    DEFAULT_LOGIN_ATTEMPT_LIMIT = 5
    DEFAULT_ACCOUNT_LOCKOUT_MINUTES = 15
    DEFAULT_IP_ATTEMPT_LIMIT = 20
    DEFAULT_IP_LOCKOUT_MINUTES = 15
    DEFAULT_CAPTCHA_ENABLED = True

    TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "1x00000000000000000000AA")
    TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "1x0000000000000000000000000AA")

    CANARY_WEBHOOK_URL = os.environ.get("CANARY_WEBHOOK_URL", "")

    ADMIN_LOGIN = "ADMIN"
    APP_DISPLAY_NAME = os.environ.get("APP_DISPLAY_NAME", "AuthLab")
    LOGIN_ERROR_MESSAGE = "Login lub hasło niepoprawne"
