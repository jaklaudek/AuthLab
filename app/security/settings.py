from __future__ import annotations

from flask import current_app

from app.passwords.settings import get_setting, set_setting


def login_attempt_limit() -> int:
    raw = get_setting(
        "login_attempt_limit",
        str(current_app.config["DEFAULT_LOGIN_ATTEMPT_LIMIT"]),
    )
    try:
        return max(3, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_LOGIN_ATTEMPT_LIMIT"])


def account_lockout_minutes() -> int:
    raw = get_setting(
        "account_lockout_minutes",
        str(current_app.config["DEFAULT_ACCOUNT_LOCKOUT_MINUTES"]),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_ACCOUNT_LOCKOUT_MINUTES"])


def ip_attempt_limit() -> int:
    raw = get_setting(
        "ip_attempt_limit",
        str(current_app.config["DEFAULT_IP_ATTEMPT_LIMIT"]),
    )
    try:
        return max(3, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_IP_ATTEMPT_LIMIT"])


def ip_lockout_minutes() -> int:
    raw = get_setting(
        "ip_lockout_minutes",
        str(current_app.config["DEFAULT_IP_LOCKOUT_MINUTES"]),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_IP_LOCKOUT_MINUTES"])


def captcha_enabled() -> bool:
    raw = get_setting(
        "captcha_enabled",
        str(current_app.config["DEFAULT_CAPTCHA_ENABLED"]).lower(),
    )
    return raw.lower() in {"1", "true", "yes", "on"}


def update_bot_defense_settings(
    *,
    login_limit: int,
    lockout_minutes: int,
    ip_limit: int,
    ip_minutes: int,
    captcha_on: bool,
) -> None:
    set_setting("login_attempt_limit", str(int(login_limit)))
    set_setting("account_lockout_minutes", str(int(lockout_minutes)))
    set_setting("ip_attempt_limit", str(int(ip_limit)))
    set_setting("ip_lockout_minutes", str(int(ip_minutes)))
    set_setting("captcha_enabled", "true" if captcha_on else "false")
