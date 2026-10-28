from __future__ import annotations

from flask import current_app

from app.extensions import db
from app.models import AppSetting


def get_setting(key: str, default: str) -> str:
    row = AppSetting.query.filter_by(key=key).one_or_none()
    return row.value if row is not None else default


def set_setting(key: str, value: str) -> None:
    row = AppSetting.query.filter_by(key=key).one_or_none()
    if row is None:
        row = AppSetting(key=key, value=str(value))
        db.session.add(row)
    else:
        row.value = str(value)
    db.session.commit()


def min_password_length() -> int:
    raw = get_setting(
        "min_password_length",
        str(current_app.config["DEFAULT_MIN_PASSWORD_LENGTH"]),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_MIN_PASSWORD_LENGTH"])


def password_history_size() -> int:
    raw = get_setting(
        "password_history_size",
        str(current_app.config["DEFAULT_PASSWORD_HISTORY_SIZE"]),
    )
    try:
        return max(0, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_PASSWORD_HISTORY_SIZE"])


def entropy_policy_enabled() -> bool:
    raw = get_setting(
        "entropy_policy_enabled",
        str(current_app.config["DEFAULT_ENTROPY_POLICY_ENABLED"]).lower(),
    )
    return raw.lower() in {"1", "true", "yes", "on"}


def entropy_min_bits() -> float:
    raw = get_setting(
        "entropy_min_bits",
        str(current_app.config["DEFAULT_ENTROPY_MIN_BITS"]),
    )
    try:
        return float(raw)
    except ValueError:
        return float(current_app.config["DEFAULT_ENTROPY_MIN_BITS"])


def password_max_age_days() -> int:
    raw = get_setting(
        "password_max_age_days",
        str(current_app.config["DEFAULT_PASSWORD_MAX_AGE_DAYS"]),
    )
    try:
        return max(0, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_PASSWORD_MAX_AGE_DAYS"])


def session_idle_timeout_minutes() -> int:
    raw = get_setting(
        "session_idle_timeout_minutes",
        str(current_app.config["DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES"]),
    )
    try:
        return max(1, int(raw))
    except ValueError:
        return int(current_app.config["DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES"])


def set_entropy_policy_enabled(enabled: bool) -> None:
    set_setting("entropy_policy_enabled", "true" if enabled else "false")


def update_policy_settings(
    *,
    min_length: int,
    entropy_enabled: bool,
    min_bits: float,
    max_age_days: int,
    idle_minutes: int,
    history_size: int,
) -> None:
    set_setting("min_password_length", str(int(min_length)))
    set_setting("entropy_policy_enabled", "true" if entropy_enabled else "false")
    bits_value = int(min_bits) if float(min_bits).is_integer() else min_bits
    set_setting("entropy_min_bits", str(bits_value))
    set_setting("password_max_age_days", str(int(max_age_days)))
    set_setting("session_idle_timeout_minutes", str(int(idle_minutes)))
    set_setting("password_history_size", str(int(history_size)))
