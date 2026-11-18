from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import IpLoginAttempt, User
from app.security.settings import (
    account_lockout_minutes,
    ip_attempt_limit,
    ip_lockout_minutes,
    login_attempt_limit,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def check_and_clear_account_lock(user: User) -> int | None:
    if user.locked_until is None:
        return None
    remaining = (_as_utc(user.locked_until) - utcnow()).total_seconds()
    if remaining <= 0:
        user.locked_until = None
        user.failed_login_count = 0
        return None
    return int(remaining) + 1


def register_account_failure(user: User) -> None:
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= login_attempt_limit():
        user.locked_until = utcnow() + timedelta(minutes=account_lockout_minutes())


def reset_account_failures(user: User) -> None:
    user.failed_login_count = 0
    user.locked_until = None


def ip_lock_remaining(ip: str) -> int | None:
    row = IpLoginAttempt.query.filter_by(ip=ip).one_or_none()
    if row is None or row.locked_until is None:
        return None
    remaining = (_as_utc(row.locked_until) - utcnow()).total_seconds()
    if remaining <= 0:
        row.locked_until = None
        row.failed_count = 0
        row.window_started_at = utcnow()
        db.session.commit()
        return None
    return int(remaining) + 1


def register_ip_failure(ip: str) -> None:
    now = utcnow()
    window = timedelta(minutes=ip_lockout_minutes())
    row = IpLoginAttempt.query.filter_by(ip=ip).one_or_none()
    if row is None:
        row = IpLoginAttempt(ip=ip, failed_count=1, window_started_at=now)
        db.session.add(row)
    else:
        window_expired = _as_utc(row.window_started_at) + window <= now
        lock_expired = row.locked_until is None or _as_utc(row.locked_until) <= now
        if window_expired and lock_expired:
            row.failed_count = 0
            row.window_started_at = now
            row.locked_until = None
        row.failed_count += 1
        if row.failed_count >= ip_attempt_limit():
            row.locked_until = now + window
    db.session.commit()


def reset_ip_failures(ip: str) -> None:
    row = IpLoginAttempt.query.filter_by(ip=ip).one_or_none()
    if row is not None:
        row.failed_count = 0
        row.locked_until = None
        db.session.commit()
