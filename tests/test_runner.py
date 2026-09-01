import pytest
from conftest import FakeCredential, RecordingLogger, make_item

from src.cli import (
    build_config,
    expand_env,
    load_config,
    main,
    parse_args,
    partition_baseline,
    run_once,
    validate_config,
)
from src.monitors.base import MonitorBase
from src.state_manager import StateManager


class StubMonitor(MonitorBase):
    name = "stub_monitor"
    items: list = []
    covered: set = {"scope-a"}
    failed: set = set()

    def collect(self):
        self.covered_scopes = set(type(self).covered)
        self.failed_scopes = set(type(self).failed)
        return list(type(self).items)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    logger = RecordingLogger()
    state = StateManager(str(tmp_path / "state"))
    monkeypatch.setattr("src.cli.AVAILABLE_MONITORS", {"stub_monitor": StubMonitor})
    config = {"enabled_monitors": ["stub_monitor"]}
    return config, logger, state


def cycle(wired):
    config, logger, state = wired
    run_once(config, FakeCredential(), logger, state, verbose=False)
    return logger, state


# ------------------------------------------------------------- config
def test_env_expansion():
    import os

    os.environ["ASG_TEST_SECRET"] = "s3cret"
    assert expand_env({"a": ["${ASG_TEST_SECRET}"]}) == {"a": ["s3cret"]}


def test_missing_env_var_is_an_error():
    with pytest.raises(KeyError):
        expand_env("${ASG_DEFINITELY_NOT_SET}")


def test_unknown_monitor_is_rejected():
    config = build_config(parse_args(["--subscriptions", "s"]), {"enabled_monitors": ["nope"]})
    assert any("Unknown monitor" in e for e in validate_config(config))


def test_valid_monitor_is_accepted():
    config = build_config(parse_args(["--subscriptions", "s"]), {"enabled_monitors": ["rbac_monitor"]})
    assert validate_config(config) == []


def test_missing_subscriptions_is_rejected():
    config = build_config(parse_args([]), {})
    assert any("No subscriptions" in e for e in validate_config(config))


def test_entra_only_config_needs_no_subscription():
    config = build_config(parse_args([]), {"enabled_monitors": ["entraid_monitor"]})
    assert validate_config(config) == []


def test_fluency_without_credentials_is_rejected():
    config = build_config(parse_args(["--subscriptions", "s"]), {"fluency": {"enabled": True}})
    assert any("Fluency" in e for e in validate_config(config))


def test_disabling_tls_verification_is_rejected():
    config = build_config(
        parse_args(["--subscriptions", "s"]),
        {"fluency": {"enabled": True, "url": "https://x", "api_key": "k", "verify_tls": False}},
    )
    assert any("verify_tls" in e for e in validate_config(config))


def test_bad_interval_is_rejected():
    config = build_config(parse_args(["--subscriptions", "s"]), {"interval_seconds": 0})
    assert any("interval_seconds" in e for e in validate_config(config))


def test_config_file_root_must_be_a_mapping(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(ValueError):
        load_config(str(path))


def test_bad_config_exits_two(capsys):
    assert main(["--enabled-monitors", "bogus", "--subscriptions", "s"]) == 2
    assert "Unknown monitor" in capsys.readouterr().err


def test_list_monitors_exits_zero():
    assert main(["--list-monitors"]) == 0


# ------------------------------------------------------- baseline behaviour
def test_first_cycle_emits_no_events(wired):
    StubMonitor.items = [make_item("a", scope="scope-a", enabled=True)]
    logger, _ = cycle(wired)
    assert logger.events == []


def test_second_cycle_emits_the_change(wired):
    StubMonitor.items = [make_item("a", scope="scope-a", enabled=True)]
    cycle(wired)
    StubMonitor.items = [make_item("a", scope="scope-a", enabled=False)]
    logger, _ = cycle(wired)
    assert len(logger.events) == 1
    assert logger.events[0]["changeType"] == "Updated"
    assert logger.events[0]["monitor"] == "stub_monitor"


def test_deleted_baseline_raises_a_baseline_reset_event(wired):
    config, logger, state = wired
    StubMonitor.items = [make_item("a", scope="scope-a", enabled=True)]
    cycle(wired)
    (state.state_path / "stub_monitor.json").unlink()
    logger, _ = cycle(wired)
    assert [e["changeType"] for e in logger.events] == ["BaselineReset"]
    assert logger.events[0]["severity"] == "critical"
    assert logger.events[0]["suppressionIndicator"] is True


def test_uncollected_scope_does_not_produce_false_deletions(wired):
    """The trap in per-scope error isolation: a scope that failed to collect
    must not make its objects look deleted."""
    StubMonitor.covered = {"scope-a", "scope-b"}
    StubMonitor.items = [
        make_item("a", scope="scope-a", enabled=True),
        make_item("b", scope="scope-b", enabled=True),
    ]
    cycle(wired)

    # scope-b now fails; only scope-a comes back.
    StubMonitor.covered = {"scope-a"}
    StubMonitor.failed = {"scope-b"}
    StubMonitor.items = [make_item("a", scope="scope-a", enabled=True)]
    logger, state = cycle(wired)

    assert logger.events == []
    snapshot, _ = state.load_snapshot("stub_monitor")
    assert {item["id"] for item in snapshot} == {"a", "b"}

    StubMonitor.covered = {"scope-a", "scope-b"}
    StubMonitor.failed = set()


def test_total_collection_failure_skips_the_cycle(wired):
    StubMonitor.covered = {"scope-a"}
    StubMonitor.items = [make_item("a", scope="scope-a", enabled=True)]
    cycle(wired)

    StubMonitor.covered = set()
    StubMonitor.failed = {"scope-a"}
    StubMonitor.items = []
    logger, state = cycle(wired)

    assert logger.events == []
    assert any("every scope failed" in e for e in logger.errors)
    snapshot, _ = state.load_snapshot("stub_monitor")
    assert len(snapshot) == 1

    StubMonitor.covered = {"scope-a"}
    StubMonitor.failed = set()


def test_partition_baseline_splits_on_coverage():
    baseline = [make_item("a", scope="s1"), make_item("b", scope="s2")]
    comparable, retained = partition_baseline(baseline, {"s1"})
    assert [i["id"] for i in comparable] == ["a"]
    assert [i["id"] for i in retained] == ["b"]
