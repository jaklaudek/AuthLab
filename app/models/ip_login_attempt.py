from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IpLoginAttempt(db.Model):
    __tablename__ = "ip_login_attempts"

    ip = db.Column(db.String(45), primary_key=True)
    failed_count = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<IpLoginAttempt {self.ip}>"
