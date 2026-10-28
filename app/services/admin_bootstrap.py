from __future__ import annotations

from dataclasses import dataclass

from flask import Flask, current_app

from app.extensions import db
from app.models import PasswordHistory, Role, User
from app.passwords.hashing import hash_password
from app.services.seed import seed_reference_data


@dataclass(frozen=True)
class BootstrapResult:
    created: bool
    login: str
    message: str


class AdminAlreadyExistsError(RuntimeError):
    pass


def ensure_reference_data(app: Flask | None = None) -> None:
    seed_reference_data(app or current_app)


def create_admin_user(password: str, *, display_name: str = "Administrator") -> BootstrapResult:
    app = current_app
    login = app.config["ADMIN_LOGIN"]

    ensure_reference_data(app)

    existing = User.query.filter_by(login=login).one_or_none()
    if existing is not None:
        raise AdminAlreadyExistsError(
            f"Konto {login} już istnieje (id={existing.id}). Nie nadpisuję hasła."
        )

    admin_role = Role.query.filter_by(name="Administrator").one()
    password_hash = hash_password(password)

    user = User(
        login=login,
        display_name=display_name,
        password_hash=password_hash,
        role=admin_role,
        is_active=True,
        must_change_password=True,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(PasswordHistory(user_id=user.id, password_hash=password_hash))
    db.session.commit()

    return BootstrapResult(
        created=True,
        login=login,
        message=(
            f"Utworzono konto {login}. Przy pierwszym logowaniu wymuszona będzie zmiana hasła."
        ),
    )
