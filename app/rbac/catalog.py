from __future__ import annotations

PERMISSIONS: dict[str, str] = {
    "auth.login": "Logowanie",
    "auth.logout": "Wylogowanie",
    "password.change_own": "Zmiana własnego hasła",
    "dashboard.view": "Widok panelu po zalogowaniu",
    "resources.internal": "Dostęp do zasobów wewnętrznych",
    "admin.panel": "Dostęp do panelu administratora",
    "users.list": "Lista użytkowników",
    "users.create": "Tworzenie użytkownika",
    "users.edit": "Edycja użytkownika",
    "users.block": "Blokowanie / odblokowanie użytkownika",
    "users.delete": "Usuwanie użytkownika",
    "users.reset_password": "Reset hasła / OTP",
    "settings.manage": "Zarządzanie polityką haseł i sesją",
}

ROLES: dict[str, str] = {
    "Administrator": "Pełne zarządzanie kontami i ustawieniami",
    "Pracownik": "Użytkownik roboczy bez zarządzania cudzymi kontami",
    "Gość": "Minimalny dostęp: login, hasło, ograniczony dashboard",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "Administrator": set(PERMISSIONS.keys()),
    "Pracownik": {
        "auth.login",
        "auth.logout",
        "password.change_own",
        "dashboard.view",
        "resources.internal",
    },
    "Gość": {
        "auth.login",
        "auth.logout",
        "password.change_own",
        "dashboard.view",
    },
}
