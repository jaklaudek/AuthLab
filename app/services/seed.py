from __future__ import annotations

from flask import Flask

from app.extensions import db
from app.models import AppSetting, Permission, Role
from app.rbac.catalog import PERMISSIONS, ROLE_PERMISSIONS, ROLES


SETTING_DEFAULTS: dict[str, str] = {
    "min_password_length": "12",
    "entropy_policy_enabled": "false",
    "entropy_min_bits": "60",
    "password_max_age_days": "90",
    "session_idle_timeout_minutes": "15",
    "password_history_size": "5",
}


def seed_permissions() -> None:
    for code, description in PERMISSIONS.items():
        permission = Permission.query.filter_by(code=code).one_or_none()
        if permission is None:
            db.session.add(Permission(code=code, description=description))
        else:
            permission.description = description


def seed_roles() -> None:
    for name, description in ROLES.items():
        role = Role.query.filter_by(name=name).one_or_none()
        if role is None:
            role = Role(name=name, description=description)
            db.session.add(role)
        else:
            role.description = description


def seed_role_permissions() -> None:
    permissions = {p.code: p for p in Permission.query.all()}
    for role_name, codes in ROLE_PERMISSIONS.items():
        role = Role.query.filter_by(name=role_name).one()
        role.permissions = [permissions[code] for code in sorted(codes)]


def seed_settings(app: Flask | None = None) -> None:
    defaults = dict(SETTING_DEFAULTS)
    if app is not None:
        defaults["min_password_length"] = str(app.config["DEFAULT_MIN_PASSWORD_LENGTH"])
        defaults["entropy_policy_enabled"] = str(
            app.config["DEFAULT_ENTROPY_POLICY_ENABLED"]
        ).lower()
        defaults["entropy_min_bits"] = str(app.config["DEFAULT_ENTROPY_MIN_BITS"])
        defaults["password_max_age_days"] = str(app.config["DEFAULT_PASSWORD_MAX_AGE_DAYS"])
        defaults["session_idle_timeout_minutes"] = str(
            app.config["DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES"]
        )
        defaults["password_history_size"] = str(app.config["DEFAULT_PASSWORD_HISTORY_SIZE"])

    for key, value in defaults.items():
        setting = AppSetting.query.filter_by(key=key).one_or_none()
        if setting is None:
            db.session.add(AppSetting(key=key, value=value))


def seed_reference_data(app: Flask | None = None) -> None:
    seed_permissions()
    seed_roles()
    db.session.flush()
    seed_role_permissions()
    seed_settings(app)
    db.session.commit()
