from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app.services.admin_bootstrap import AdminAlreadyExistsError, create_admin_user


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap the fixed ADMIN account.")
    parser.add_argument(
        "--password",
        help="Admin password (prefer env/prompt). Will not be printed.",
    )
    parser.add_argument(
        "--display-name",
        default="Administrator",
        help="Display name for ADMIN (default: Administrator).",
    )
    return parser.parse_args()


def resolve_password(cli_password: str | None) -> str:
    if cli_password:
        return cli_password
    env_password = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD")
    if env_password:
        return env_password
    password = getpass.getpass("Hasło dla konta ADMIN: ")
    confirm = getpass.getpass("Powtórz hasło: ")
    if password != confirm:
        raise SystemExit("Hasła nie są zgodne.")
    return password


def main() -> int:
    args = parse_args()
    try:
        password = resolve_password(args.password)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1

    if len(password) < 12:
        print("Hasło ADMIN musi mieć co najmniej 12 znaków (wariant 8).", file=sys.stderr)
        return 1

    app = create_app()
    with app.app_context():
        from app.extensions import db

        db.create_all()
        try:
            result = create_admin_user(password, display_name=args.display_name)
        except AdminAlreadyExistsError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"Bootstrap nieudany: {exc}", file=sys.stderr)
            return 1

    print(result.message)
    print("Hasło nie zostało zapisane w repozytorium ani w logach skryptu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
