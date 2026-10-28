from __future__ import annotations

import math
from dataclasses import dataclass, field

from zxcvbn import zxcvbn

from app.passwords.settings import entropy_min_bits, min_password_length

# siła = log2(guesses); score 0–4 nie jest progiem


@dataclass
class EntropyEstimate:
    bits: float
    guesses: float
    score: int
    warning: str | None = None
    hints: list[str] = field(default_factory=list)


_HINT_TRANSLATIONS = {
    "use a few words, avoid common phrases": "Użyj kilku niezwiązanych słów zamiast popularnej frazy.",
    "add another word or two. uncommon words are better.": "Dodaj jeszcze jedno lub dwa rzadkie słowa.",
    "add another word or two": "Dodaj jeszcze jedno lub dwa rzadkie słowa.",
    "uncommon words are better": "Rzadsze słowa dają lepszą ochronę.",
    "avoid repeated words and characters": "Unikaj powtórzeń słów i znaków.",
    "avoid sequences": "Unikaj sekwencji (np. 1234, abcd, qwerty).",
    "avoid recent years": "Unikaj aktualnych i niedawnych lat.",
    "avoid years that are associated with you": "Unikaj lat powiązanych z Tobą.",
    "avoid dates and years that are associated with you": "Unikaj dat i lat powiązanych z Tobą.",
    "capitalization doesn't help very much": "Sama wielka litera na początku niewiele pomaga.",
    "all-uppercase is almost as easy to guess as all-lowercase": "SAME WIELKIE LITERY są prawie tak łatwe do odgadnięcia jak same małe.",
    "reversed words aren't much harder to guess": "Odwrócone słowa nie są dużo trudniejsze do odgadnięcia.",
    "predictable substitutions like '@' instead of 'a' don't help very much": "Przewidywalne zamiany (np. @ zamiast a) niewiele pomagają.",
    "this is a top-10 common password": "To jedno z najczęściej używanych haseł.",
    "this is a top-100 common password": "To bardzo popularne hasło.",
    "this is a very common password": "To bardzo popularne hasło.",
    "this is similar to a commonly used password": "Hasło jest podobne do często używanych haseł.",
    "a word by itself is easy to guess": "Pojedyncze słowo jest łatwe do odgadnięcia.",
    "names and surnames by themselves are easy to guess": "Same imiona i nazwiska są łatwe do odgadnięcia.",
    "common names and surnames are easy to guess": "Popularne imiona i nazwiska są łatwe do odgadnięcia.",
}


def _translate_hint(text: str) -> str:
    key = (text or "").strip().lower()
    return _HINT_TRANSLATIONS.get(key, text)


def estimate_entropy_bits(
    password: str,
    user_inputs: list[str] | None = None,
) -> EntropyEstimate:
    value = password or ""
    cleaned_inputs = [item for item in (user_inputs or []) if item]
    result = zxcvbn(value, user_inputs=cleaned_inputs) if value else {
        "guesses": 1,
        "score": 0,
        "feedback": {"warning": "", "suggestions": []},
    }

    guesses = float(result.get("guesses") or 1)
    bits = math.log2(max(guesses, 1.0))
    score = int(result.get("score") or 0)
    feedback = result.get("feedback") or {}
    warning_raw = (feedback.get("warning") or "").strip() or None
    suggestions = feedback.get("suggestions") or []

    hints: list[str] = []
    if warning_raw:
        hints.append(_translate_hint(warning_raw))
    for suggestion in suggestions:
        translated = _translate_hint(suggestion)
        if translated and translated not in hints:
            hints.append(translated)

    try:
        minimum = min_password_length()
        threshold = entropy_min_bits()
    except RuntimeError:
        minimum = 12
        threshold = 60.0

    if len(value) < minimum:
        length_hint = f"Hasło musi mieć co najmniej {minimum} znaków."
        if length_hint not in hints:
            hints.insert(0, length_hint)

    if value and bits < threshold:
        bits_hint = (
            f"Szacowana siła wynosi około {bits:.1f} bitów; wymagane jest co najmniej "
            f"{threshold} bitów. Wydłuż hasło lub użyj mniej przewidywalnej frazy."
        )
        if bits_hint not in hints:
            hints.append(bits_hint)

    return EntropyEstimate(
        bits=bits,
        guesses=guesses,
        score=score,
        warning=_translate_hint(warning_raw) if warning_raw else None,
        hints=hints,
    )
