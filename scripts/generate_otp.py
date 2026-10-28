from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app.models import User
from app.passwords.otp import PURPOSE_ACCOUNT_CREATE, PURPOSE_RESET, issue_otp


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an 8-digit OTP for a user.")
    parser.add_argument("--login", required=True, help="Existing user login")
    parser.add_argument(
        "--purpose",
        choices=[PURPOSE_RESET, PURPOSE_ACCOUNT_CREATE],
        default=PURPOSE_RESET,
    )
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        user = User.query.filter_by(login=args.login).one_or_none()
        if user is None:
            print(f"Nie znaleziono użytkownika: {args.login}", file=sys.stderr)
            return 1
        issued = issue_otp(user, purpose=args.purpose)

    print(f"Login: {args.login}")
    print(f"Kod:   {issued.code}")
    print(f"Ważny do (UTC): {issued.expires_at.isoformat()}")
    print("Kod nie został zapisany w bazie w postaci jawnej.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
