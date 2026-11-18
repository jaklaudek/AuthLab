from __future__ import annotations

from flask import Blueprint, Response, request

from app.security.honeytokens import trigger_canary

bp = Blueprint("security", __name__)


@bp.get("/robots.txt")
def robots_txt():
    body = "User-agent: *\nDisallow: /backup/\nDisallow: /admin-legacy/\n"
    return Response(body, mimetype="text/plain")


@bp.get("/backup/db-export-2024.sql")
def honeytoken_document():
    trigger_canary(
        "honeytoken_document",
        token_name="db-export-2024.sql",
        details=f"Pobranie pliku-pułapki z {request.remote_addr}",
    )
    fake_dump = (
        "-- CANARY-TOKEN: db-export-2024\n"
        "INSERT INTO users (login, password_hash) VALUES "
        "('temp_svc_2024', 'REDACTED');\n"
    )
    return Response(fake_dump, mimetype="application/sql")
