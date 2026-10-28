from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import OneTimePassword, User
from app.passwords.hashing import hash_password, verify_password

OTP_LENGTH = 8
OTP_TTL = timedelta(hours=1)
PURPOSE_ACCOUNT_CREATE = "account_create"
PURPOSE_RESET = "reset"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_numeric_code(length: int = OTP_LENGTH) -> str:
    import secrets

    if length <= 0:
        raise ValueError("OTP length must be positive")
    upper = 10**length
    return f"{secrets.randbelow(upper):0{length}d}"


@dataclass(frozen=True)
class IssuedOtp:
    code: str
    expires_at: datetime
    purpose: str
    otp_id: int


def invalidate_active_otps(user: User, *, purpose: str | None = None) -> None:
    query = OneTimePassword.query.filter_by(user_id=user.id, used_at=None)
    if purpose is not None:
        query = query.filter_by(purpose=purpose)
    now = utcnow()
    for row in query.all():
        row.used_at = now


def issue_otp(user: User, *, purpose: str = PURPOSE_RESET) -> IssuedOtp:
    if purpose not in {PURPOSE_ACCOUNT_CREATE, PURPOSE_RESET}:
        raise ValueError(f"Unsupported OTP purpose: {purpose}")

    invalidate_active_otps(user, purpose=purpose)
    code = generate_numeric_code()
    expires_at = utcnow() + OTP_TTL
    row = OneTimePassword(
        user_id=user.id,
        code_hash=hash_password(code),
        purpose=purpose,
        expires_at=expires_at,
    )
    db.session.add(row)
    db.session.commit()
    return IssuedOtp(code=code, expires_at=expires_at, purpose=purpose, otp_id=row.id)


@dataclass(frozen=True)
class OtpAuthResult:
    ok: bool
    user: User | None = None
    error: str | None = None


def consume_otp(login: str, code: str) -> OtpAuthResult:
    neutral = "Login lub kod jednorazowy niepoprawne"
    normalized_login = (login or "").strip()
    normalized_code = (code or "").strip()

    from app.auth.constants import DUMMY_PASSWORD_HASH

    user = User.query.filter_by(login=normalized_login).one_or_none()
    if user is None or not user.is_active:
        verify_password(DUMMY_PASSWORD_HASH, normalized_code or "")
        return OtpAuthResult(ok=False, error=neutral)

    if len(normalized_code) != OTP_LENGTH or not normalized_code.isdigit():
        return OtpAuthResult(ok=False, error=neutral)

    candidates = (
        OneTimePassword.query.filter_by(user_id=user.id, used_at=None)
        .order_by(OneTimePassword.created_at.desc())
        .all()
    )
    matched: OneTimePassword | None = None
    for row in candidates:
        if row.is_expired():
            continue
        if verify_password(row.code_hash, normalized_code):
            matched = row
            break

    if matched is None:
        return OtpAuthResult(ok=False, error=neutral)

    matched.used_at = utcnow()
    user.must_change_password = True
    db.session.commit()
    return OtpAuthResult(ok=True, user=user)
