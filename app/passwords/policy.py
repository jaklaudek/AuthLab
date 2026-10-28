from __future__ import annotations

from dataclasses import dataclass, field

from app.passwords.entropy import EntropyEstimate, estimate_entropy_bits
from app.passwords.settings import (
    entropy_min_bits,
    entropy_policy_enabled,
    min_password_length,
)


@dataclass
class PolicyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    entropy_bits: float | None = None
    entropy_required: bool = False


def validate_new_password(
    password: str,
    *,
    user_inputs: list[str] | None = None,
) -> PolicyResult:
    errors: list[str] = []
    hints: list[str] = []
    minimum = min_password_length()
    value = password or ""
    entropy_required = entropy_policy_enabled()
    estimate: EntropyEstimate | None = None

    if len(value) < minimum:
        errors.append(f"Hasło musi mieć co najmniej {minimum} znaków.")
        hints.append(f"Dodaj znaki, aż hasło osiągnie długość {minimum}.")

    if entropy_required:
        estimate = estimate_entropy_bits(value, user_inputs=user_inputs)
        threshold = entropy_min_bits()
        for hint in estimate.hints:
            if hint not in hints:
                hints.append(hint)
        if value and estimate.bits < threshold:
            errors.append(
                f"Hasło jest zbyt słabe (ok. {estimate.bits:.1f} bitów). "
                f"Wymagane minimum to {threshold:g} bitów."
            )
    elif value:
        estimate = estimate_entropy_bits(value, user_inputs=user_inputs)
        for hint in estimate.hints:
            if hint not in hints and "wymagane jest co najmniej" not in hint.lower():
                hints.append(hint)

    return PolicyResult(
        ok=not errors,
        errors=errors,
        hints=hints,
        entropy_bits=estimate.bits if estimate else None,
        entropy_required=entropy_required,
    )
