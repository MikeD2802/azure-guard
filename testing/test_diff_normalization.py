from src.diff import diff_snapshots, normalize_item


def test_normalize_drops_volatile_fields_and_sorts_lists():
    payload = {
        "etag": "abc",
        "name": "resource",
        "items": [
            {"id": "b", "value": 2},
            {"id": "a", "value": 1},
        ],
    }
    normalized = normalize_item(payload)
    assert "etag" not in normalized
    assert normalized["items"][0]["id"] == "a"


def test_diff_detects_created_deleted_updated():
    old = [
        {"id": "one", "data": {"enabled": True}},
        {"id": "two", "data": {"enabled": True}},
    ]
    new = [
        {"id": "two", "data": {"enabled": False}},
        {"id": "three", "data": {"enabled": True}},
    ]
    changes = diff_snapshots(old, new)
    change_types = {change["id"]: change["changeType"] for change in changes}
    assert change_types["one"] == "Deleted"
    assert change_types["two"] == "Updated"
    assert change_types["three"] == "Created"
