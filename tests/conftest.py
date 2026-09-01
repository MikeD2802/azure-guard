from typing import Any


class RecordingLogger:
    """Collects log lines so tests can assert on warnings."""

    def __init__(self) -> None:
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.events: list[dict[str, Any]] = []

    def info(self, message: str) -> None:
        self.infos.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def log_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def flush_spool(self) -> None:
        return None


class FakeToken:
    token = "fake-token"


class FakeCredential:
    def get_token(self, *_scopes):
        return FakeToken()


def make_item(item_id: str, scope: str = "scope", type: str = "test", **data: Any) -> dict[str, Any]:
    """Build a collected item. ``type`` is the item's own field, not part of data."""
    return {
        "id": item_id,
        "name": item_id,
        "type": type,
        "scope": scope,
        "subscriptionId": "sub",
        "tenantId": "tenant",
        "data": data,
    }


def change_between(monitor, old_data: dict, new_data: dict, item_id: str = "obj", **item_kwargs):
    """Build the single change produced by moving one object old -> new."""
    from src.diff import diff_snapshots

    old = [make_item(item_id, **{**item_kwargs, **old_data})]
    new = [make_item(item_id, **{**item_kwargs, **new_data})]
    changes = diff_snapshots(old, new)
    assert len(changes) == 1, changes
    return changes[0]
