# AuthLab (wariant 8)

Flask + SQLite: logowanie, hasła (Argon2id), OTP, RBAC, sesja, TOTP.

## Uruchomienie

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:FLASK_APP = "app:create_app"
flask db upgrade
python scripts/bootstrap_admin.py
python scripts/seed_demo_users.py
flask --app app:create_app run
```

Otwórz http://127.0.0.1:5000/login

Skopiuj `.env.example` → `.env` i ustaw `SECRET_KEY`.
