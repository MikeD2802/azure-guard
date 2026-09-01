import json
from unittest import mock

import requests

from src.logger import AuditLogger


def make_logger(tmp_path, **fluency):
    return AuditLogger(
        log_file=str(tmp_path / "audit.log"),
        fluency={"enabled": True, "url": "https://sink", "api_key": "k", **fluency},
    )


class Resp:
    def __init__(self, status_code=200):
        self.status_code = status_code


def read_events(tmp_path):
    text = (tmp_path / "audit.log").read_text().strip()
    return [json.loads(line) for line in text.splitlines() if line]


def test_event_is_written_as_one_json_line(tmp_path):
    logger = AuditLogger(log_file=str(tmp_path / "audit.log"), fluency={})
    logger.log_event({"eventName": "x"})
    events = read_events(tmp_path)
    assert len(events) == 1
    assert events[0]["eventName"] == "x"
    assert "eventTime" in events[0]


def test_failed_delivery_is_spooled_then_retried(tmp_path):
    logger = make_logger(tmp_path)
    with mock.patch("requests.post", side_effect=requests.ConnectionError("network down")):
        logger.log_event({"eventName": "dropped"})
    assert logger.spool_path.exists()

    with mock.patch("requests.post", return_value=Resp(200)) as post:
        logger.flush_spool()
    assert post.call_count == 1
    assert not logger.spool_path.exists()


def test_event_survives_in_the_local_log_even_when_forwarding_fails(tmp_path):
    logger = make_logger(tmp_path)
    with mock.patch("requests.post", side_effect=requests.ConnectionError("down")):
        logger.log_event({"eventName": "x"})
    assert read_events(tmp_path)[0]["eventName"] == "x"


def test_spool_order_is_preserved_when_flush_fails_midway(tmp_path):
    logger = make_logger(tmp_path)
    with mock.patch("requests.post", side_effect=requests.ConnectionError("down")):
        logger.log_event({"eventName": "first"})
        logger.log_event({"eventName": "second"})

    with mock.patch("requests.post", side_effect=[Resp(200), requests.ConnectionError("down")]):
        logger.flush_spool()

    remaining = [json.loads(line) for line in logger.spool_path.read_text().splitlines() if line]
    assert [e["eventName"] for e in remaining] == ["second"]


def test_http_error_response_counts_as_failure(tmp_path):
    logger = make_logger(tmp_path)
    with mock.patch("requests.post", return_value=Resp(500)):
        logger.log_event({"eventName": "x"})
    assert logger.spool_path.exists()


def test_rotation_is_configured(tmp_path):
    logger = AuditLogger(
        log_file=str(tmp_path / "audit.log"), fluency={}, max_bytes=200, backup_count=2
    )
    for i in range(50):
        logger.log_event({"eventName": f"event-{i}", "padding": "x" * 50})
    rotated = list(tmp_path.glob("audit.log.*"))
    assert rotated, "expected the audit log to rotate"
    assert len(rotated) <= 2
