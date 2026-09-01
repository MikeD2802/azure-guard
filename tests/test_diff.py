from src.diff import ROOT_FIELD, _diff_fields, diff_snapshots, index_items, normalize_item, values_equal


def test_normalize_drops_volatile_fields_and_sorts_lists():
    payload = {
        "etag": "abc",
        "name": "resource",
        "items": [{"id": "b", "value": 2}, {"id": "a", "value": 1}],
    }
    normalized = normalize_item(payload)
    assert "etag" not in normalized
    assert normalized["items"][0]["id"] == "a"


def test_diff_detects_created_deleted_updated():
    old = [{"id": "one", "data": {"enabled": True}}, {"id": "two", "data": {"enabled": True}}]
    new = [{"id": "two", "data": {"enabled": False}}, {"id": "three", "data": {"enabled": True}}]
    changes = {c["id"]: c["changeType"] for c in diff_snapshots(old, new)}
    assert changes == {"one": "Deleted", "two": "Updated", "three": "Created"}


def test_changed_fields_names_the_exact_field():
    old = [{"id": "r", "data": {"enabled": True, "severity": "High"}}]
    new = [{"id": "r", "data": {"enabled": False, "severity": "High"}}]
    assert diff_snapshots(old, new)[0]["changedFields"] == ["enabled"]


def test_item_without_id_is_skipped_not_fatal():
    warnings: list[str] = []
    changes = diff_snapshots([], [{"name": "x", "data": {}}], warn=warnings.append)
    assert changes == []
    assert any("missing or non-string" in w for w in warnings)


def test_item_without_data_is_tolerated():
    changes = diff_snapshots([], [{"id": "x"}])
    assert changes[0]["changeType"] == "Created"


def test_duplicate_ids_are_reported():
    warnings: list[str] = []
    index_items([{"id": "a", "data": {}}, {"id": "a", "data": {}}], warn=warnings.append)
    assert any("duplicate" in w for w in warnings)


def test_booleans_are_not_equal_to_numbers():
    assert not values_equal(True, 1)
    assert diff_snapshots([{"id": "a", "data": {"enabled": True}}],
                          [{"id": "a", "data": {"enabled": 1}}])


def test_root_level_type_change_is_named():
    assert _diff_fields({"a": 1}, ["a"]) == [ROOT_FIELD]


def test_reordered_lists_do_not_produce_a_change():
    old = [{"id": "a", "data": {"tags": [{"k": 1}, {"k": 2}]}}]
    new = [{"id": "a", "data": {"tags": [{"k": 2}, {"k": 1}]}}]
    assert diff_snapshots(old, new) == []
