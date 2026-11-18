"""python scripts/reset_admin_password.py [--login X] [--unlock]"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app.extensions import db
from app.models import PasswordHistory, User
from app.passwords.hashing import hash_password


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resetuje hasło konta (domyślnie ADMIN).")
    parser.add_argument(
        "--login", default=None, help="Login konta (domyślnie ADMIN_LOGIN z konfiguracji)."
    )
    parser.add_argument("--password", help="Nowe hasło (prefer env/prompt, nie w historii shella).")
    parser.add_argument(
        "--unlock",
        action="store_true",
        help="Dodatkowo zdejmij blokadę logowania (moduł 2: failed_login_count/locked_until).",
    )
    return parser.parse_args()


def resolve_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    password = getpass.getpass("Nowe hasło: ")
    confirm = getpass.getpass("Powtórz hasło: ")
    if password != confirm:
        raise SystemExit("Hasła nie są zgodne.")
    return password


def main() -> int:
    args = parse_args()
    app = create_app()
    with app.app_context():
        login = args.login or app.config["ADMIN_LOGIN"]
        user = User.query.filter_by(login=login).one_or_none()
        if user is None:
            print(f"Nie znaleziono konta '{login}'.", file=sys.stderr)
            return 2

        try:
            password = resolve_password(args.password)
        except SystemExit as exc:
            print(exc, file=sys.stderr)
            return 1

        if len(password) < 12:
            print("Hasło musi mieć co najmniej 12 znaków (wariant 8).", file=sys.stderr)
            return 1

        password_hash = hash_password(password)
        user.password_hash = password_hash
        user.must_change_password = True
        if args.unlock:
            user.failed_login_count = 0
            user.locked_until = None
        db.session.add(PasswordHistory(user_id=user.id, password_hash=password_hash))
        db.session.commit()

    print(f"Zresetowano hasło konta {login}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
