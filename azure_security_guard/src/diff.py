from __future__ import annotations

from typing import Any, Dict, List


def _compare(path: str, before: Any, after: Any, diffs: List[Dict[str, Any]]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        keys = sorted(set(before.keys()) | set(after.keys()))
        for key in keys:
            _compare(f"{path}/{key}", before.get(key), after.get(key), diffs)
        return
    if isinstance(before, list) and isinstance(after, list):
        max_len = max(len(before), len(after))
        for idx in range(max_len):
            before_item = before[idx] if idx < len(before) else None
            after_item = after[idx] if idx < len(after) else None
            _compare(f"{path}/{idx}", before_item, after_item, diffs)
        return
    if before != after:
        diffs.append({"path": path or "/", "before": before, "after": after})


def build_diff(before: Any, after: Any) -> List[Dict[str, Any]]:
    diffs: List[Dict[str, Any]] = []
    _compare("", before, after, diffs)
    return diffs
