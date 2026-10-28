from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar

from app.auth.session_utils import login_required
from app.rbac.checks import ensure_permission

F = TypeVar("F", bound=Callable)


def permission_required(*codes: str) -> Callable[[F], F]:

    if not codes:
        raise ValueError("permission_required needs at least one permission code")

    def decorator(view: F) -> F:
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            for code in codes:
                ensure_permission(code)
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorator
