import json

from src.state_manager import SnapshotStatus, StateManager


def test_first_run_reports_first_run(tmp_path):
    state = StateManager(str(tmp_path))
    assert state.load_snapshot("m") == (None, SnapshotStatus.FIRST_RUN)


def test_round_trip(tmp_path):
    state = StateManager(str(tmp_path))
    state.save_snapshot("m", [{"id": "a", "data": {"x": 1}}])
    snapshot, status = state.load_snapshot("m")
    assert status == SnapshotStatus.OK
    assert snapshot == [{"id": "a", "data": {"x": 1}}]


def test_deleted_baseline_is_reported_not_treated_as_first_run(tmp_path):
    state = StateManager(str(tmp_path))
    state.save_snapshot("m", [{"id": "a", "data": {"x": 1}}])
    (tmp_path / "m.json").unlink()
    assert StateManager(str(tmp_path)).load_snapshot("m") == (None, SnapshotStatus.MISSING)


def test_edited_baseline_is_detected(tmp_path):
    state = StateManager(str(tmp_path))
    state.save_snapshot("m", [{"id": "a", "data": {"x": 1}}])
    (tmp_path / "m.json").write_text(json.dumps([{"id": "a", "data": {"x": 999}}]))
    assert StateManager(str(tmp_path)).load_snapshot("m")[1] == SnapshotStatus.TAMPERED


def test_corrupt_baseline_is_detected(tmp_path):
    state = StateManager(str(tmp_path))
    state.save_snapshot("m", [{"id": "a", "data": {}}])
    (tmp_path / "m.json").write_text("{ not json")
    assert StateManager(str(tmp_path)).load_snapshot("m")[1] == SnapshotStatus.CORRUPT


def test_save_leaves_no_temp_files_behind(tmp_path):
    state = StateManager(str(tmp_path))
    state.save_snapshot("m", [{"id": "a", "data": {}}])
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_items_without_id_do_not_break_sorting(tmp_path):
    state = StateManager(str(tmp_path))
    state.save_snapshot("m", [{"id": None, "data": {}}, {"id": "a", "data": {}}])
    assert state.load_snapshot("m")[1] == SnapshotStatus.OK
