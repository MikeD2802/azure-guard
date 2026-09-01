from unittest import mock

import pytest
import requests
from conftest import FakeCredential, RecordingLogger

from src.monitors.base import MonitorBase


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.content = b"{}"

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def make_monitor():
    return MonitorBase(config={}, credential=FakeCredential(), logger=RecordingLogger())


def test_arm_paged_follows_next_link():
    """Reading only page one made later objects look deleted next cycle."""
    pages = [
        FakeResponse(payload={"value": [{"id": "a"}], "nextLink": "https://arm/page2"}),
        FakeResponse(payload={"value": [{"id": "b"}], "nextLink": "https://arm/page3"}),
        FakeResponse(payload={"value": [{"id": "c"}]}),
    ]
    with mock.patch("requests.request", side_effect=pages) as request:
        items = make_monitor()._arm_paged("https://arm/page1")
    assert [item["id"] for item in items] == ["a", "b", "c"]
    assert request.call_count == 3


def test_arm_paged_stops_on_repeated_next_link():
    """A server echoing the same nextLink must not spin forever."""
    looping = FakeResponse(payload={"value": [{"id": "a"}], "nextLink": "https://arm/same"})
    with mock.patch("requests.request", return_value=looping):
        items = make_monitor()._arm_paged("https://arm/same")
    assert len(items) == 2


def test_graph_paged_stops_on_repeated_next_link():
    looping = FakeResponse(payload={"value": [{"id": "a"}], "@odata.nextLink": "https://graph/same"})
    with mock.patch("requests.request", return_value=looping):
        items = make_monitor()._graph_paged("https://graph/page1")
    assert len(items) == 2


def test_retry_after_header_is_honoured():
    responses = [FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, {"value": []})]
    with mock.patch("requests.request", side_effect=responses), \
         mock.patch("time.sleep") as sleep:
        make_monitor()._arm_get("https://arm/x")
    sleep.assert_called_once()
    assert sleep.call_args[0][0] == pytest.approx(7.0)


def test_retry_after_is_capped():
    responses = [FakeResponse(503, headers={"Retry-After": "99999"}), FakeResponse(200, {"value": []})]
    with mock.patch("requests.request", side_effect=responses), mock.patch("time.sleep") as sleep:
        make_monitor()._arm_get("https://arm/x")
    assert sleep.call_args[0][0] <= 60


def test_malformed_retry_after_falls_back_to_backoff():
    responses = [FakeResponse(429, headers={"Retry-After": "soon"}), FakeResponse(200, {"value": []})]
    with mock.patch("requests.request", side_effect=responses), mock.patch("time.sleep") as sleep:
        make_monitor()._arm_get("https://arm/x")
    assert 0 < sleep.call_args[0][0] <= 60


def test_non_retryable_status_raises_immediately():
    with mock.patch("requests.request", return_value=FakeResponse(403)) as request:
        with pytest.raises(requests.HTTPError):
            make_monitor()._arm_get("https://arm/x")
    assert request.call_count == 1


def test_retries_are_bounded_and_then_raise():
    with mock.patch("requests.request", return_value=FakeResponse(429)) as request, \
         mock.patch("time.sleep"):
        with pytest.raises(requests.HTTPError):
            make_monitor()._request("GET", "https://arm/x", max_retries=3)
    assert request.call_count == 3


def test_single_attempt_does_not_crash_on_unbound_response():
    with mock.patch("requests.request", return_value=FakeResponse(500)):
        with pytest.raises(requests.HTTPError):
            make_monitor()._request("GET", "https://arm/x", max_retries=0)


def test_collect_scope_isolates_failure():
    monitor = make_monitor()
    ok = monitor.collect_scope("/subscriptions/a", "probe", lambda: [{"id": "x"}])
    bad = monitor.collect_scope("/subscriptions/b", "probe", _raise)
    assert ok == [{"id": "x"}]
    assert bad == []
    assert monitor.covered_scopes == {"/subscriptions/a"}
    assert monitor.failed_scopes == {"/subscriptions/b"}
    assert monitor.logger.warnings


def _raise():
    raise requests.HTTPError("403 Forbidden")
