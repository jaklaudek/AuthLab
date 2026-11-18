from __future__ import annotations

import json
import secrets
import urllib.request
from datetime import datetime, timezone

from flask import current_app, request

from app.extensions import db
from app.models import CanaryEvent, Role, User
from app.passwords.hashing import hash_password

HONEYTOKEN_LOGIN = "svc-backup-sync"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_honeytoken_account() -> User:
    user = User.query.filter_by(login=HONEYTOKEN_LOGIN).one_or_none()
    if user is not None:
        return user

    role = Role.query.filter_by(name="Gość").one_or_none() or Role.query.first()
    user = User(
        login=HONEYTOKEN_LOGIN,
        display_name="Serwis synchronizacji backupu (konto-pułapka)",
        password_hash=hash_password(secrets.token_urlsafe(32)),
        role=role,
        is_active=True,
        must_change_password=False,
        is_honeytoken=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def trigger_canary(token_type: str, *, token_name: str, details: str = "") -> CanaryEvent:
    event = CanaryEvent(
        token_type=token_type,
        token_name=token_name,
        triggered_at=utcnow(),
        source_ip=request.remote_addr if request else None,
        user_agent=(request.headers.get("User-Agent", "") if request else ""),
        details=details,
    )
    db.session.add(event)
    db.session.commit()
    _notify(event)
    return event


def _notify(event: CanaryEvent) -> None:
    message = (
        f"[CANARY] typ={event.token_type} nazwa={event.token_name} "
        f"ip={event.source_ip} ua={event.user_agent!r} szczegóły={event.details}"
    )
    current_app.logger.warning(message)

    webhook = current_app.config.get("CANARY_WEBHOOK_URL")
    if not webhook:
        return
    payload = json.dumps(
        {
            "token_type": event.token_type,
            "token_name": event.token_name,
            "triggered_at": event.triggered_at.isoformat(),
            "source_ip": event.source_ip,
            "user_agent": event.user_agent,
            "details": event.details,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        webhook, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        current_app.logger.warning("Dostarczenie alertu canary (webhook) nieudane")
