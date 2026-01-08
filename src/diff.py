import hashlib
import json
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


def normalize_item(item: dict[str, Any]) -> dict[str, Any]:
    return _normalize(item)


def _diff_fields(old: Any, new: Any, prefix: str = "") -> list[str]:
    if type(old) != type(new):
        return [prefix.rstrip(".")]
    if isinstance(old, dict):
        fields = []
        keys = set(old.keys()) | set(new.keys())
        for key in sorted(keys):
            old_val = old.get(key)
            new_val = new.get(key)
            path = f"{prefix}{key}."
            if old_val == new_val:
                continue
            fields.extend(_diff_fields(old_val, new_val, path))
        return fields
    if isinstance(old, list):
        if old != new:
            return [prefix.rstrip(".")]
        return []
    if old != new:
        return [prefix.rstrip(".")]
    return []


def diff_snapshots(
    old_items: list[dict[str, Any]],
    new_items: list[dict[str, Any]],
    id_key: str = "id",
) -> list[dict[str, Any]]:
    old_map = {item[id_key]: item for item in old_items}
    new_map = {item[id_key]: item for item in new_items}
    changes = []

    for item_id, new_item in new_map.items():
        old_item = old_map.get(item_id)
        if old_item is None:
            changes.append(
                {
                    "changeType": "Created",
                    "id": item_id,
                    "old": None,
                    "new": new_item,
                    "changedFields": [],
                    "baselineHash": None,
                    "currentHash": stable_hash(normalize_item(new_item["data"])),
                }
            )
            continue

        old_data = normalize_item(old_item["data"])
        new_data = normalize_item(new_item["data"])
        if old_data != new_data:
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
        changes.append(
            {
                "changeType": "Deleted",
                "id": item_id,
                "old": old_item,
                "new": None,
                "changedFields": [],
                "baselineHash": stable_hash(normalize_item(old_item["data"])),
                "currentHash": None,
            }
        )

    return changes
