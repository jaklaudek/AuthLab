"""python scripts/bot_login_simulation.py (serwer musi już działać)"""

from __future__ import annotations

import argparse
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

CSRF_RE = re.compile(r'name="csrf_token"[^>]*\svalue="([^"]+)"')
CAPTCHA_RE = re.compile(r"CAPTCHA:\s*([^<]+)</label>")

MARK_LOCKED_ACCOUNT = "Konto zostało zablokowane po przekroczeniu limitu"
MARK_LOCKED_IP = "Logowanie z tego adresu IP zostało zablokowane"
MARK_CAPTCHA_ERROR = "Nieprawidłowa odpowiedź CAPTCHA"
MARK_INVALID = "Login lub hasło niepoprawne"
MARK_LOGIN_OK = "Witaj"
MARK_FORCED_CHANGE = "Wymagana zmiana hasła"


class BotClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def get(self, path: str) -> tuple[int, str]:
        try:
            with self.opener.open(self.base_url + path, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")

    def post(self, path: str, fields: dict[str, str]) -> tuple[int, str]:
        data = urllib.parse.urlencode(fields).encode("utf-8")
        req = urllib.request.Request(self.base_url + path, data=data, method="POST")
        try:
            with self.opener.open(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace")


def extract_csrf(html: str) -> str:
    match = CSRF_RE.search(html)
    return match.group(1) if match else ""


def extract_captcha_prompt(html: str) -> str | None:
    match = CAPTCHA_RE.search(html)
    return match.group(1).strip() if match else None


def solve_sequence(prompt: str) -> str | None:
    marker = "Uzupełnij brakujący element ciągu:"
    if not prompt.startswith(marker):
        return None
    raw = prompt[len(marker):].strip()
    items = [x.strip() for x in raw.split(",")]
    if "?" not in items:
        return None
    gap = items.index("?")
    known = {i: v for i, v in enumerate(items) if v != "?"}
    if len(known) < 2:
        return None

    numeric = all(v.lstrip("-").isdigit() for v in known.values())
    if numeric:
        values = {i: int(v) for i, v in known.items()}
    else:
        values = {i: ord(v) for i, v in known.items() if len(v) == 1}
        if len(values) < 2:
            return None

    (i1, v1), (i2, v2) = list(values.items())[:2]
    if i2 == i1:
        return None
    step = (v2 - v1) / (i2 - i1)
    start = v1 - i1 * step
    missing = start + gap * step
    return str(int(round(missing))) if numeric else chr(int(round(missing)))


def solve_captcha(prompt: str | None) -> str:
    if prompt is None:
        return ""
    return solve_sequence(prompt) or ""


def classify(html: str) -> str:
    if MARK_LOCKED_ACCOUNT in html:
        return "zablokowane_konto"
    if MARK_LOCKED_IP in html:
        return "zablokowane_ip"
    if MARK_CAPTCHA_ERROR in html:
        return "captcha_odrzucona"
    if MARK_INVALID in html:
        return "odrzucone_dane"
    if MARK_LOGIN_OK in html or MARK_FORCED_CHANGE in html:
        return "zalogowano"
    return "nieznany"


def attempt_login(
    client: BotClient,
    login: str,
    password: str,
    *,
    solve: bool,
    honeypot: str | None = None,
) -> str:
    _, html = client.get("/login")
    if MARK_LOCKED_IP in html:
        return "zablokowane_ip"

    csrf = extract_csrf(html)
    prompt = extract_captcha_prompt(html)
    captcha_answer = solve_captcha(prompt) if solve else ""

    fields = {
        "csrf_token": csrf,
        "login": login,
        "password": password,
        "captcha_answer": captcha_answer,
        "submit": "Zaloguj",
    }
    if honeypot is not None:
        fields["honeypot"] = honeypot

    _, result_html = client.post("/login", fields)
    return classify(result_html)


def run_phase(title: str, outcomes: list[str]) -> dict:
    print(f"\n== {title} ==")
    for i, outcome in enumerate(outcomes, start=1):
        print(f"  próba {i}: {outcome}")
    return {"title": title, "outcomes": outcomes}


def phase_honeytoken_account(client: BotClient, honeytoken_login: str) -> dict:
    # Trzeba przejść CAPTCHA, by próba logowania w ogóle dotarła do warstwy
    # uwierzytelniania, w której wyzwalany jest alert canary.
    outcome = attempt_login(client, honeytoken_login, "haslo-zgadywane-123", solve=True)
    outcomes = [outcome]
    reached_credential_check = outcome in ("odrzucone_dane", "zablokowane_konto", "zablokowane_ip")

    print(f"\n== Faza 1: sondowanie konta-pułapki '{honeytoken_login}' ==")
    print(f"  próby: {outcomes}")
    if reached_credential_check:
        print("  próba dotarła do warstwy uwierzytelniania -> alert canary powinien być zarejestrowany")
    else:
        print("  CAPTCHA zablokowała wszystkie próby, sprawdź panel Incydenty")
    return {
        "title": "Konto-pułapka (canary)",
        "outcomes": outcomes,
        "canary_likely": reached_credential_check,
    }


def phase_honeytoken_document(client: BotClient) -> dict:
    status, html = client.get("/backup/db-export-2024.sql")
    found_bait_in_robots = False
    _, robots = client.get("/robots.txt")
    if "/backup/" in robots:
        found_bait_in_robots = True
    outcome = "pobrano_plik_pulapke" if status == 200 and "CANARY" in html else "brak_pliku"
    print("\n== Faza 2: pobranie pliku-pułapki (honeytoken dokument) ==")
    print(f"  GET /backup/db-export-2024.sql -> HTTP {status} ({outcome})")
    print(f"  wabik w /robots.txt widoczny dla skanera: {found_bait_in_robots}")
    print("  (pobranie jest rejestrowane po stronie serwera jako incydent canary)")
    return {"title": "Dokument-pułapka (canary)", "outcomes": [outcome]}


def phase_naive_bruteforce(client: BotClient, login: str, passwords: list[str]) -> dict:
    outcomes = [attempt_login(client, login, pwd, solve=False) for pwd in passwords]
    return run_phase(f"Faza 4: naiwny bot (ignoruje CAPTCHA) na konto '{login}'", outcomes)


def phase_honeypot_bot(client: BotClient, login: str, password: str) -> dict:
    outcomes = [
        attempt_login(client, login, password, solve=True, honeypot="555-123-456"),
        attempt_login(client, login, password, solve=True, honeypot="test@bot.local"),
    ]
    return run_phase("Faza 5: bot wypełniający pole-pułapkę (honeypot)", outcomes)


def phase_smart_bruteforce(client: BotClient, login: str, max_attempts: int) -> dict:
    outcomes = []
    for i in range(max_attempts):
        outcome = attempt_login(client, login, f"zle-haslo-{i}", solve=True)
        outcomes.append(outcome)
        if outcome in ("zablokowane_konto", "zablokowane_ip"):
            break
    return run_phase(f"Faza 3: bot rozwiązujący CAPTCHA, brute force na '{login}'", outcomes)


def phase_credential_stuffing(client: BotClient, combos: list[tuple[str, str]]) -> dict:
    outcomes = []
    for login, pwd in combos:
        outcome = attempt_login(client, login, pwd, solve=True)
        outcomes.append(outcome)
        if outcome == "zablokowane_ip":
            break
    return run_phase("Faza 6: credential stuffing / password spraying (jeden adres IP)", outcomes)


def build_summary(phases: list[dict]) -> None:
    print("\n" + "=" * 72)
    print("ZESTAWIENIE: które zabezpieczenia zadziałały")
    print("=" * 72)

    all_outcomes = [o for p in phases for o in p["outcomes"]]
    honeypot_phase = next((p for p in phases if "honeypot" in p["title"]), None)
    rows = [
        (
            "Limit błędnych logowań (blokada konta)",
            "zablokowane_konto" in all_outcomes,
        ),
        (
            "Limit logowań z jednego IP (ochrona przed credential stuffing / spraying)",
            "zablokowane_ip" in all_outcomes,
        ),
        (
            "CAPTCHA przy logowaniu (naiwny bot odrzucony)",
            "captcha_odrzucona" in all_outcomes,
        ),
        (
            "Pułapka na boty (honeypot), wynik zawsze odrzucony",
            bool(honeypot_phase) and all(o != "zalogowano" for o in honeypot_phase["outcomes"]),
        ),
        (
            "Honeytoken: konto-pułapka (dotarło do warstwy uwierzytelniania)",
            bool(phases) and bool(phases[0].get("canary_likely")),
        ),
        (
            "Honeytoken: dokument-pułapka (plik pobrany)",
            bool(len(phases) > 1 and "pobrano_plik_pulapke" in phases[1]["outcomes"]),
        ),
        (
            "Bot NIGDY nie uzyskał dostępu (brak 'zalogowano')",
            "zalogowano" not in all_outcomes,
        ),
    ]

    width = max(len(name) for name, _ in rows)
    for name, ok in rows:
        mark = "ZADZIAŁAŁO" if ok else "brak dowodu w tym przebiegu"
        print(f"  {name.ljust(width)} : {mark}")

    print(
        "\nUwaga: zdarzenia canary (konto-pułapka, dokument-pułapka) są potwierdzane"
        " po stronie serwera. Sprawdź panel Administracja -> Incydenty"
        " albo tests/test_bot_defenses.py (automatyczny dowód)."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--target-login", default="pracownik1", help="konto do brute force")
    parser.add_argument(
        "--honeytoken-login", default="svc-backup-sync", help="login konta-pułapki"
    )
    args = parser.parse_args()

    client = BotClient(args.base_url)

    try:
        client.get("/health")
    except urllib.error.URLError as exc:
        print(f"Nie można połączyć się z {args.base_url}: {exc}", file=sys.stderr)
        print("Uruchom najpierw serwer: flask --app app:create_app run", file=sys.stderr)
        return 1

    phases = []
    phases.append(phase_honeytoken_account(client, args.honeytoken_login))
    phases.append(phase_honeytoken_document(client))
    phases.append(phase_smart_bruteforce(client, "pracownik2", max_attempts=8))
    phases.append(
        phase_naive_bruteforce(
            client, args.target_login, ["wrong1", "wrong2", "wrong3", "wrong4"]
        )
    )
    phases.append(phase_honeypot_bot(client, args.target_login, "wrong-but-maybe-right"))
    phases.append(
        phase_credential_stuffing(
            client,
            [
                ("pracownik3", "letmein123456"),
                ("pracownik4", "letmein123456"),
                ("pracownik5", "letmein123456"),
                ("gosc1", "Password123!"),
                ("gosc2", "Password123!"),
                ("gosc3", "Password123!"),
                ("pracownik1", "Password123!"),
                ("pracownik2", "Password123!"),
                ("pracownik3", "qwerty123456"),
                ("pracownik4", "qwerty123456"),
                ("gosc1", "qwerty123456"),
                ("gosc2", "qwerty123456"),
            ],
        )
    )

    build_summary(phases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
