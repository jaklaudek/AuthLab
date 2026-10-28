from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app
from app.extensions import db
from app.models import Role, User
from app.passwords.hashing import hash_password
from app.services.seed import seed_reference_data

DEMO_USERS = [
    ("ADMIN", "Administrator", "Administrator"),
    ("pracownik1", "Pracownik Jeden", "Pracownik"),
    ("pracownik2", "Pracownik Dwa", "Pracownik"),
    ("pracownik3", "Pracownik Trzy", "Pracownik"),
    ("pracownik4", "Pracownik Cztery", "Pracownik"),
    ("pracownik5", "Pracownik Pięć", "Pracownik"),
    ("gosc1", "Gość Jeden", "Gość"),
    ("gosc2", "Gość Dwa", "Gość"),
    ("gosc3", "Gość Trzy", "Gość"),
]


def main() -> int:
    app = create_app()
    created = 0
    with app.app_context():
        db.create_all()
        seed_reference_data(app)
        for login, display_name, role_name in DEMO_USERS:
            if User.query.filter_by(login=login).one_or_none() is not None:
                continue
            if login == "ADMIN":
                print("ADMIN nie istnieje — najpierw uruchom scripts/bootstrap_admin.py")
                continue
            role = Role.query.filter_by(name=role_name).one()
            password_hash = hash_password(f"DemoPass12-{login}")
            user = User(
                login=login,
                display_name=display_name,
                password_hash=password_hash,
                role=role,
                must_change_password=True,
                is_active=True,
            )
            db.session.add(user)
            created += 1
        db.session.commit()
        total = User.query.count()

    print(f"Dodano {created} kont. Łącznie użytkowników: {total}")
    if total < 9:
        print("Uwaga: oczekiwano 9 użytkowników testowych (wariant 8).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
