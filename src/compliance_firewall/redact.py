"""Redaction utilities for scrubbing PII from action payloads."""

from __future__ import annotations

from typing import Any

from .models import Action

# Map of data categories to payload keys that should be redacted
_CATEGORY_TO_KEYS: dict[str, tuple[str, ...]] = {
    "email": ("email", "user_email", "contact_email", "email_address"),
    "phone": ("phone", "phone_number", "tel", "mobile"),
    "national_id": ("national_id", "ssn", "sin", "nino", "passport", "id_number"),
    "name": ("name", "full_name", "first_name", "last_name", "display_name"),
    "address": ("address", "street", "city", "postal_code", "zip", "home_address"),
    "health": ("health_data", "medical_record", "diagnosis", "treatment"),
    "financial": ("bank_account", "credit_card", "iban", "card_number"),
    "biometric": ("fingerprint", "face_id", "iris_scan", "biometric_data"),
}

# Keys that are always redacted regardless of category
_ALWAYS_REDACT = frozenset(
    {
        "password",
        "api_key",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
    }
)

REDACTED_PLACEHOLDER = "[REDACTED]"


def _keys_for_categories(categories: list[str]) -> set[str]:
    """Return the set of payload keys that should be redacted for given categories."""
    keys: set[str] = set()
    for cat in categories:
        cat_lower = cat.lower()
        if cat_lower in _CATEGORY_TO_KEYS:
            keys.update(_CATEGORY_TO_KEYS[cat_lower])
        else:
            # Unknown category: treat the category name itself as a key
            keys.add(cat_lower)
    return keys


def redact_payload(
    payload: dict[str, Any],
    data_categories: list[str],
    *,
    always_redact: bool = True,
) -> dict[str, Any]:
    """Return a copy of payload with PII fields replaced by placeholders.

    Args:
        payload: The original payload dict.
        data_categories: Categories of data present (e.g. ["email", "phone"]).
        always_redact: If True, also redact secrets like passwords and API keys.

    Returns:
        New dict with matching keys replaced by "[REDACTED]".
    """
    keys_to_redact = _keys_for_categories(data_categories)
    if always_redact:
        keys_to_redact |= set(_ALWAYS_REDACT)

    def _scrub(value: Any, key_path: str = "") -> Any:
        if isinstance(value, dict):
            result = {}
            for k, v in value.items():
                if k.lower() in keys_to_redact or k.lower() in _ALWAYS_REDACT:
                    result[k] = REDACTED_PLACEHOLDER
                else:
                    result[k] = _scrub(v, f"{key_path}.{k}" if key_path else k)
            return result
        if isinstance(value, list):
            return [_scrub(item, key_path) for item in value]
        return value

    return _scrub(payload)


def redact_action(action: Action) -> Action:
    """Return a new Action with PII fields scrubbed from the payload.

    The original action is not modified.
    """
    scrubbed_payload = redact_payload(action.payload, action.data_categories)
    return Action(
        action_type=action.action_type,
        destination_region=action.destination_region,
        source_region=action.source_region,
        contains_pii=False,  # PII has been removed
        purpose=action.purpose,
        data_categories=[],  # Categories no longer present
        payload=scrubbed_payload,
        actor=action.actor,
    )
