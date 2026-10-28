from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable, TypeVar

from flask import flash, g, redirect, request, session, url_for

from app.extensions import db
from app.models import User

F = TypeVar("F", bound=Callable)

IDLE_EXEMPT_ENDPOINTS = {
    "auth.login",
    "auth.otp_login",
    "auth.totp_challenge",
    "static",
    "health",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def login_user(user: User, *, via_otp: bool = False) -> None:
    session.clear()
    session["user_id"] = user.id
    session["login"] = user.login
    session["last_activity"] = utcnow().isoformat()
    session["auth_via_otp"] = bool(via_otp)
    session.permanent = True


def logout_user() -> None:
    session.clear()


def begin_pending_totp(user: User) -> None:
    session.clear()
    session["pending_totp_user_id"] = user.id
    session.permanent = True


def clear_pending_totp() -> None:
    session.pop("pending_totp_user_id", None)


def get_pending_totp_user() -> User | None:
    user_id = session.get("pending_totp_user_id")
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user is None or not user.is_active or not user.totp_enabled:
        clear_pending_totp()
        return None
    return user


def clear_otp_auth_flag() -> None:
    session.pop("auth_via_otp", None)


def authenticated_via_otp() -> bool:
    return bool(session.get("auth_via_otp"))


def _parse_activity(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def idle_timeout_timedelta() -> timedelta:
    from app.passwords.settings import session_idle_timeout_minutes

    return timedelta(minutes=session_idle_timeout_minutes())


def session_idle_expired(now: datetime | None = None) -> bool:
    if not session.get("user_id"):
        return False
    last = _parse_activity(session.get("last_activity"))
    if last is None:
        return True
    current = now or utcnow()
    return current - last >= idle_timeout_timedelta()


def touch_session_activity() -> None:
    if session.get("user_id"):
        session["last_activity"] = utcnow().isoformat()


def get_current_user() -> User | None:
    if hasattr(g, "current_user"):
        return g.current_user

    user_id = session.get("user_id")
    if not user_id:
        g.current_user = None
        return None

    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        logout_user()
        g.current_user = None
        return None

    g.current_user = user
    return user


def login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def enforce_idle_timeout():
    if not session.get("user_id"):
        return None
    if not session_idle_expired():
        return None

    logout_user()
    if hasattr(g, "current_user"):
        g.current_user = None

    if request.endpoint in IDLE_EXEMPT_ENDPOINTS:
        return None

    flash("Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.", "info")
    return redirect(url_for("auth.login"))
