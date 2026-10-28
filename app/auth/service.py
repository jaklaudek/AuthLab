from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.auth.constants import DUMMY_PASSWORD_HASH
from app.extensions import db
from app.models import User
from app.passwords.hashing import verify_password


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    user: User | None = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def apply_password_expiry(user: User) -> None:
    from app.passwords.settings import password_max_age_days

    max_age_days = password_max_age_days()
    if max_age_days <= 0:
        return
    changed_at = _as_utc(user.password_changed_at)
    if utcnow() - changed_at >= timedelta(days=max_age_days):
        user.must_change_password = True


def authenticate(login: str, password: str) -> AuthResult:
    normalized = (login or "").strip()
    user = User.query.filter_by(login=normalized).one_or_none()

    if user is None:
        verify_password(DUMMY_PASSWORD_HASH, password or "")
        return AuthResult(ok=False)

    if not user.is_active:
        verify_password(DUMMY_PASSWORD_HASH, password or "")
        return AuthResult(ok=False)

    if not verify_password(user.password_hash, password or ""):
        return AuthResult(ok=False)

    apply_password_expiry(user)
    db.session.commit()
    return AuthResult(ok=True, user=user)


def mark_successful_login(user: User) -> None:
    user.last_login_at = utcnow()
    db.session.commit()
