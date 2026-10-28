from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(64), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(128), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)

    is_active = db.Column(db.Boolean, nullable=False, default=True)
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)

    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_last_counter = db.Column(db.Integer, nullable=True)

    password_changed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    role = db.relationship("Role", back_populates="users")
    password_history = db.relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    one_time_passwords = db.relationship(
        "OneTimePassword",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def has_permission(self, code: str) -> bool:
        if not self.role:
            return False
        return any(p.code == code for p in self.role.permissions)

    def __repr__(self) -> str:
        return f"<User {self.login}>"
