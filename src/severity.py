from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Verdict:
    """The security meaning of a single detected change.

    ``severity`` only ever escalates as rules fire, so the order in which a
    monitor evaluates its rules does not affect the result.
    """

    severity: str = "info"
    suppression: bool = False
    reasons: list[str] = field(default_factory=list)

    def note(self, severity: str, reason: str, suppression: bool = True) -> Verdict:
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Unknown severity: {severity}")
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[self.severity]:
            self.severity = severity
        self.suppression = self.suppression or suppression
        self.reasons.append(reason)
        return self


def get_path(data: Any, path: str, default: Any = None) -> Any:
    """Look up a dotted path, returning ``default`` if any segment is absent."""
    current = data
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return default
        current = current[segment]
    return current


def transition(old: Any, new: Any, path: str) -> tuple[Any, Any]:
    """Return the (old, new) values of a dotted path across a change."""
    return get_path(old, path), get_path(new, path)


def turned_off(old_value: Any, new_value: Any) -> bool:
    """True when a value moved from enabled-ish to disabled-ish.

    Treats the string forms Azure and Graph use ("On"/"Off", "enabled"/
    "disabled", "true"/"false") the same as real booleans.
    """
    return _is_on(old_value) and _is_off(new_value)


def _is_on(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"on", "enabled", "true", "enable"}
    return False


def _is_off(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return value.strip().lower() in {
            "off",
            "disabled",
            "false",
            "disable",
            "enabledforreportingbutnotenforced",
        }
    return False


def removed(old_value: Any, new_value: Any) -> bool:
    """True when a previously populated value became empty or absent."""
    was_set = old_value not in (None, "", [], {})
    now_unset = new_value in (None, "", [], {})
    return was_set and now_unset
