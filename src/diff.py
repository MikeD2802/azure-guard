from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

VOLATILE_FIELDS = {
    "etag",
    "eTag",
    "lastModified",
    "timeCreated",
    "createdDateTime",
    "modifiedDateTime",
    "systemData",
}

ROOT_FIELD = "<root>"


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        normalized = {}
        for key in sorted(value.keys()):
            if key in VOLATILE_FIELDS:
                continue
            normalized[key] = _normalize(value[key])
        return normalized
    if isinstance(value, list):
        normalized_list = [_normalize(item) for item in value]
        return sorted(
            normalized_list,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    return value


def normalize_item(item: Any) -> Any:
    return _normalize(item)


def values_equal(old: Any, new: Any) -> bool:
    """Equality that refuses to treat booleans as numbers.

    Python considers ``True == 1``, which would hide a provider changing an
    ``enabled`` flag from ``true`` to ``1`` -- exactly the kind of quiet
    representation change this tool exists to surface.
    """
    if isinstance(old, bool) != isinstance(new, bool):
        return False
    if isinstance(old, dict) and isinstance(new, dict):
        if old.keys() != new.keys():
            return False
        return all(values_equal(old[key], new[key]) for key in old)
    if isinstance(old, list) and isinstance(new, list):
        if len(old) != len(new):
            return False
        return all(values_equal(a, b) for a, b in zip(old, new, strict=True))
    return old == new


def _diff_fields(old: Any, new: Any, prefix: str = "") -> list[str]:
    if type(old) is not type(new):
        return [prefix.rstrip(".") or ROOT_FIELD]
    if isinstance(old, dict):
        fields: list[str] = []
        keys = set(old.keys()) | set(new.keys())
        for key in sorted(keys):
            old_val = old.get(key)
            new_val = new.get(key)
            if values_equal(old_val, new_val):
                continue
            fields.extend(_diff_fields(old_val, new_val, f"{prefix}{key}."))
        return fields
    if isinstance(old, list):
        if not values_equal(old, new):
            return [prefix.rstrip(".") or ROOT_FIELD]
        return []
    if not values_equal(old, new):
        return [prefix.rstrip(".") or ROOT_FIELD]
    return []


def index_items(
    items: list[dict[str, Any]],
    id_key: str = "id",
    warn: Callable[[str], None] | None = None,
    label: str = "snapshot",
) -> dict[str, dict[str, Any]]:
    """Index items by id, skipping malformed entries instead of crashing.

    A single collected object missing its ``id`` used to raise ``KeyError`` and
    take the whole monitor down for that cycle, leaving it silently blind. Bad
    entries are now dropped with a warning so the remaining objects still get
    compared.
    """
    indexed: dict[str, dict[str, Any]] = {}
    skipped = 0
    duplicates = 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        item_id = item.get(id_key)
        if not item_id or not isinstance(item_id, str):
            skipped += 1
            continue
        if item_id in indexed:
            duplicates += 1
        indexed[item_id] = item
    if warn:
        if skipped:
            warn(f"{label}: skipped {skipped} item(s) with a missing or non-string '{id_key}'")
        if duplicates:
            warn(f"{label}: {duplicates} duplicate '{id_key}' value(s); only the last was kept")
    return indexed


def _data_of(item: dict[str, Any]) -> Any:
    return normalize_item(item.get("data", {}))


def diff_snapshots(
    old_items: list[dict[str, Any]],
    new_items: list[dict[str, Any]],
    id_key: str = "id",
    warn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    old_map = index_items(old_items, id_key, warn, label="baseline")
    new_map = index_items(new_items, id_key, warn, label="current")
    changes = []

    for item_id, new_item in new_map.items():
        old_item = old_map.get(item_id)
        new_data = _data_of(new_item)
        if old_item is None:
            changes.append(
                {
                    "changeType": "Created",
                    "id": item_id,
                    "old": None,
                    "new": {**new_item, "data": new_data},
                    "changedFields": [],
                    "baselineHash": None,
                    "currentHash": stable_hash(new_data),
                }
            )
            continue

        old_data = _data_of(old_item)
        if not values_equal(old_data, new_data):
            changes.append(
                {
                    "changeType": "Updated",
                    "id": item_id,
                    "old": {**old_item, "data": old_data},
                    "new": {**new_item, "data": new_data},
                    "changedFields": _diff_fields(old_data, new_data),
                    "baselineHash": stable_hash(old_data),
                    "currentHash": stable_hash(new_data),
                }
            )

    for item_id, old_item in old_map.items():
        if item_id in new_map:
            continue
        old_data = _data_of(old_item)
        changes.append(
            {
                "changeType": "Deleted",
                "id": item_id,
                "old": {**old_item, "data": old_data},
                "new": None,
                "changedFields": [],
                "baselineHash": stable_hash(old_data),
                "currentHash": None,
            }
        )

    return changes
