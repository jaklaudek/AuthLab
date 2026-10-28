from __future__ import annotations

import base64
from dataclasses import dataclass
from io import BytesIO

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

from app.extensions import db
from app.models import User
from app.passwords.hashing import verify_password

TOTP_VALID_WINDOW = 1
TOTP_DIGITS = 6


@dataclass(frozen=True)
class TotpVerifyResult:
    ok: bool
    counter: int | None = None
    error: str | None = None


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(*, secret: str, login: str, issuer: str) -> str:
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS)
    return totp.provisioning_uri(name=login, issuer_name=issuer)


def qr_svg_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=SvgPathImage)
    buf = BytesIO()
    img.save(buf)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _matching_counter(totp: pyotp.TOTP, code: str) -> int | None:
    from datetime import datetime
    from hmac import compare_digest

    now = datetime.now()
    current = totp.timecode(now)
    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        expected = totp.at(now, counter_offset=offset)
        if compare_digest(str(expected), code):
            return current + offset
    return None


def verify_code(
    secret: str,
    code: str,
    *,
    last_counter: int | None = None,
) -> TotpVerifyResult:
    cleaned = (code or "").strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != TOTP_DIGITS:
        return TotpVerifyResult(ok=False, error="Podaj 6-cyfrowy kod z aplikacji.")

    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS)
    counter = _matching_counter(totp, cleaned)
    if counter is None:
        return TotpVerifyResult(ok=False, error="Nieprawidłowy kod TOTP.")

    if last_counter is not None and counter <= last_counter:
        return TotpVerifyResult(ok=False, error="Ten kod został już użyty. Poczekaj na nowy.")

    return TotpVerifyResult(ok=True, counter=int(counter))


def verify_user_totp(user: User, code: str) -> TotpVerifyResult:
    if not user.totp_enabled or not user.totp_secret:
        return TotpVerifyResult(ok=False, error="TOTP nie jest włączone dla tego konta.")
    return verify_code(user.totp_secret, code, last_counter=user.totp_last_counter)


def enable_totp(user: User, secret: str, code: str) -> TotpVerifyResult:
    result = verify_code(secret, code, last_counter=None)
    if not result.ok or result.counter is None:
        return result

    user.totp_secret = secret
    user.totp_enabled = True
    user.totp_last_counter = result.counter
    db.session.commit()
    return result


def disable_totp(user: User, *, password: str, code: str) -> TotpVerifyResult:
    if not user.totp_enabled or not user.totp_secret:
        return TotpVerifyResult(ok=False, error="TOTP nie jest włączone.")

    if not verify_password(user.password_hash, password or ""):
        return TotpVerifyResult(ok=False, error="Nieprawidłowe hasło lub kod TOTP.")

    result = verify_user_totp(user, code)
    if not result.ok:
        return TotpVerifyResult(ok=False, error=result.error or "Nieprawidłowe hasło lub kod TOTP.")

    user.totp_secret = None
    user.totp_enabled = False
    user.totp_last_counter = None
    db.session.commit()
    return TotpVerifyResult(ok=True, counter=result.counter)


def record_totp_success(user: User, counter: int) -> None:
    user.totp_last_counter = counter
    db.session.commit()
