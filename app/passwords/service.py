from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.extensions import db
from app.models import PasswordHistory, User
from app.passwords.hashing import hash_password, verify_password
from app.passwords.policy import PolicyResult, validate_new_password
from app.passwords.settings import password_history_size


@dataclass
class PasswordChangeResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _history_hashes(user: User) -> list[str]:
    limit = password_history_size()
    hashes = [user.password_hash]
    if limit <= 0:
        return hashes

    previous = (
        user.password_history.order_by(PasswordHistory.created_at.desc())
        .limit(limit)
        .all()
    )
    for entry in previous:
        if entry.password_hash not in hashes:
            hashes.append(entry.password_hash)
    return hashes


def password_in_history(user: User, password: str) -> bool:
    for stored_hash in _history_hashes(user):
        if verify_password(stored_hash, password):
            return True
    return False


def change_password(
    user: User,
    *,
    current_password: str,
    new_password: str,
    confirm_password: str,
    skip_current_check: bool = False,
) -> PasswordChangeResult:
    errors: list[str] = []
    hints: list[str] = []

    if not skip_current_check:
        if not verify_password(user.password_hash, current_password or ""):
            errors.append("Obecne hasło jest niepoprawne.")
            return PasswordChangeResult(ok=False, errors=errors)

    if (new_password or "") != (confirm_password or ""):
        errors.append("Nowe hasło i potwierdzenie nie są zgodne.")
        return PasswordChangeResult(ok=False, errors=errors)

    user_inputs = [user.login, user.display_name]
    policy: PolicyResult = validate_new_password(
        new_password or "",
        user_inputs=user_inputs,
    )
    errors.extend(policy.errors)
    hints.extend(policy.hints)

    if password_in_history(user, new_password or ""):
        errors.append("Nie można ponownie użyć jednego z poprzednich haseł.")
        hints.append("Wybierz hasło, którego jeszcze nie używałeś na tym koncie.")

    if errors:
        return PasswordChangeResult(ok=False, errors=errors, hints=hints)

    new_hash = hash_password(new_password)
    db.session.add(PasswordHistory(user_id=user.id, password_hash=new_hash))
    user.password_hash = new_hash
    user.must_change_password = False
    user.password_changed_at = utcnow()

    limit = password_history_size()
    if limit >= 0:
        extras = (
            user.password_history.order_by(PasswordHistory.created_at.desc())
            .offset(limit)
            .all()
        )
        for entry in extras:
            db.session.delete(entry)

    db.session.commit()
    return PasswordChangeResult(ok=True)
