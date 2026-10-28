from __future__ import annotations

from flask import abort

from app.models import User


def current_permissions() -> set[str]:
    from app.auth.session_utils import get_current_user

    user = get_current_user()
    if user is None or not user.role:
        return set()
    return {p.code for p in user.role.permissions}


def user_has_permission(user: User | None, code: str) -> bool:
    if user is None:
        return False
    return user.has_permission(code)


def ensure_permission(code: str) -> User:
    from app.auth.session_utils import get_current_user

    user = get_current_user()
    if user is None or not user.has_permission(code):
        abort(403)
    return user
