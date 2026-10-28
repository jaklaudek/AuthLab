from __future__ import annotations

from dataclasses import dataclass

from app.extensions import db
from app.models import PasswordHistory, Role, User
from app.passwords.hashing import hash_password
from app.passwords.otp import PURPOSE_ACCOUNT_CREATE, PURPOSE_RESET, issue_otp


@dataclass(frozen=True)
class CreatedUser:
    user: User
    otp_code: str
    otp_expires_at: object


@dataclass(frozen=True)
class ResetResult:
    user: User
    otp_code: str
    otp_expires_at: object


def create_user(
    *,
    login: str,
    display_name: str,
    role_name: str,
    temporary_password: str | None = None,
) -> CreatedUser:
    normalized = login.strip()
    if User.query.filter_by(login=normalized).one_or_none() is not None:
        raise ValueError("Login jest już zajęty.")

    role = Role.query.filter_by(name=role_name).one_or_none()
    if role is None:
        raise ValueError("Nieznana rola.")

    # tymczasowe hasło — pierwsze wejście przez OTP
    import secrets

    temp = temporary_password or secrets.token_urlsafe(24)
    password_hash = hash_password(temp)
    user = User(
        login=normalized,
        display_name=(display_name or normalized).strip(),
        password_hash=password_hash,
        role=role,
        is_active=True,
        must_change_password=True,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(PasswordHistory(user_id=user.id, password_hash=password_hash))
    db.session.commit()

    issued = issue_otp(user, purpose=PURPOSE_ACCOUNT_CREATE)
    return CreatedUser(user=user, otp_code=issued.code, otp_expires_at=issued.expires_at)


def update_user(
    user: User,
    *,
    display_name: str,
    role_name: str,
    is_active: bool,
) -> User:
    role = Role.query.filter_by(name=role_name).one_or_none()
    if role is None:
        raise ValueError("Nieznana rola.")
    user.display_name = (display_name or user.login).strip()
    user.role = role
    user.is_active = bool(is_active)
    db.session.commit()
    return user


def set_user_active(user: User, active: bool) -> User:
    user.is_active = bool(active)
    db.session.commit()
    return user


def delete_user(user: User) -> None:
    db.session.delete(user)
    db.session.commit()


def reset_user_password(user: User) -> ResetResult:
    user.must_change_password = True
    db.session.commit()
    issued = issue_otp(user, purpose=PURPOSE_RESET)
    return ResetResult(user=user, otp_code=issued.code, otp_expires_at=issued.expires_at)


def count_admins() -> int:
    admin_role = Role.query.filter_by(name="Administrator").one_or_none()
    if admin_role is None:
        return 0
    return User.query.filter_by(role_id=admin_role.id, is_active=True).count()
