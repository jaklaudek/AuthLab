from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CanaryEvent(db.Model):
    __tablename__ = "canary_events"

    id = db.Column(db.Integer, primary_key=True)
    token_type = db.Column(db.String(32), nullable=False)
    token_name = db.Column(db.String(128), nullable=False)
    triggered_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    source_ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)
    details = db.Column(db.Text, nullable=False, default="")

    def __repr__(self) -> str:
        return f"<CanaryEvent {self.token_type}:{self.token_name}>"
