from __future__ import annotations

from app.extensions import db
from app.models.role import role_permissions


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False, default="")

    roles = db.relationship(
        "Role",
        secondary=role_permissions,
        back_populates="permissions",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<Permission {self.code}>"
