from __future__ import annotations

import json
import random
import string
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from flask import current_app, session

CAPTCHA_SESSION_KEY = "login_captcha"
CAPTCHA_TTL_SECONDS = 180

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _build_challenge() -> tuple[str, str]:
    if random.random() < 0.5:
        start = random.randint(1, 10)
        step = random.randint(2, 6)
        terms = [start + i * step for i in range(5)]
        gap_index = random.randint(2, 4)
        display = [str(t) for t in terms]
    else:
        start_idx = random.randint(0, 10)
        step = random.choice([2, 3])
        terms = [string.ascii_uppercase[start_idx + i * step] for i in range(4)]
        gap_index = len(terms) - 1
        display = list(terms)

    answer = str(terms[gap_index])
    display[gap_index] = "?"
    prompt = "Uzupełnij brakujący element ciągu: " + ", ".join(display)
    return prompt, answer


def get_or_create_login_captcha(*, force_new: bool = False) -> dict:
    now = utcnow()
    existing = session.get(CAPTCHA_SESSION_KEY)
    if not force_new and existing:
        try:
            expires_at = datetime.fromisoformat(existing["expires_at"])
        except (KeyError, ValueError, TypeError):
            expires_at = now
        if expires_at > now:
            return {"prompt": existing["prompt"]}

    prompt, answer = _build_challenge()
    expires_at = now + timedelta(seconds=CAPTCHA_TTL_SECONDS)
    session[CAPTCHA_SESSION_KEY] = {
        "prompt": prompt,
        "answer": answer,
        "expires_at": expires_at.isoformat(),
    }
    return {"prompt": prompt}


def verify_login_captcha(user_answer: str | None) -> bool:
    data = session.pop(CAPTCHA_SESSION_KEY, None)
    if not data:
        return False
    try:
        expires_at = datetime.fromisoformat(data["expires_at"])
    except (KeyError, ValueError, TypeError):
        return False
    if utcnow() > expires_at:
        return False
    expected = str(data.get("answer", ""))
    given = (user_answer or "").strip()
    return given.casefold() == expected.casefold()


def verify_turnstile(token: str | None, remote_ip: str | None) -> bool:
    if not token:
        return False
    if current_app.config.get("TESTING"):
        return True

    secret = current_app.config.get("TURNSTILE_SECRET_KEY") or ""
    if not secret:
        return False
    data = urllib.parse.urlencode(
        {"secret": secret, "response": token, "remoteip": remote_ip or ""}
    ).encode()
    request_obj = urllib.request.Request(TURNSTILE_VERIFY_URL, data=data)
    try:
        with urllib.request.urlopen(request_obj, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        current_app.logger.warning("Weryfikacja Turnstile nieudana (sieć/timeout)")
        return False
    return bool(payload.get("success"))
