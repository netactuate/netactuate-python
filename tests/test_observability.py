"""Tests for the observability gona-parity methods (gona's observability.go).

get_contract_usage is vAPI2 (Client); the statistics and metric names
methods are vAPI3 (V3Client).
"""

from __future__ import annotations

from netactuate import Client, V3Client
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


def test_get_contract_usage_decodes_response() -> None:
    session = RecordedSession([response({"id": 1, "mb_id": 9, "contract_type": "postpaid"})])

    usage = _client(session).get_contract_usage()

    assert usage.id == 1
    assert usage.mb_id == 9
    assert usage.contract_type == "postpaid"
    call = session.calls[0]
    assert call["method"] == "GET"
    assert "cloud/contract/usage" in call["url"]


def test_query_statistics_builds_metrics_body_and_decodes_rows() -> None:
    payload = [
        {
            "metric": {"cpu.usage": {}},
            "service": "compute",
            "data": [{"count": 1, "resources": 2, "avg": 3.5, "sum": 7}],
        }
    ]
    session = RecordedSession([response(payload)])

    results = _v3(session).query_statistics(["cpu.usage"])

    assert len(results) == 1
    assert results[0].metric == "cpu.usage"
    assert results[0].service == "compute"
    assert results[0].data[0].sum == 7
    call = session.calls[0]
    assert "/cloud/statistics" in call["url"]
    assert call["kwargs"]["json"] == {"metrics": [{"metric": {"cpu.usage": {}}}]}


def test_query_statistics_picks_first_sorted_metric_key() -> None:
    payload = [{"metric": {"zeta": {}, "alpha": {}}, "service": "svc", "data": []}]
    session = RecordedSession([response(payload)])

    results = _v3(session).query_statistics(["zeta", "alpha"])

    assert results[0].metric == "alpha"


def test_query_networking_statistics_posts_networking_path() -> None:
    session = RecordedSession([response([])])

    _v3(session).query_networking_statistics(["bandwidth"])

    assert "/cloud/networking/statistics" in session.calls[0]["url"]


def test_query_anycast_statistics_posts_anycast_path() -> None:
    session = RecordedSession([response([])])

    _v3(session).query_anycast_statistics(["bandwidth"])

    assert "/cloud/networking/anycast/statistics" in session.calls[0]["url"]


def test_get_metric_names_decodes_time_window_and_sorts_metrics() -> None:
    payload = {
        "__timeWindow": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z", "seconds": 86400},
        "zeta.metric": {
            "service": "svc-z",
            "resources": 2,
            "avg": {"sum": 1, "avg": 1, "min": 0, "max": 2},
            "last": {"sum": 1, "avg": 1, "min": 0, "max": 2},
            "sum": {"sum": 4, "avg": 2, "min": 1, "max": 3},
        },
        "alpha.metric": {
            "service": "svc-a",
            "resources": 5,
            "avg": {"sum": 1, "avg": 1, "min": 0, "max": 2},
            "last": {"sum": 1, "avg": 1, "min": 0, "max": 2},
            "sum": {"sum": 4, "avg": 2, "min": 1, "max": 3},
        },
    }
    session = RecordedSession([response(payload)])

    names = _v3(session).get_metric_names()

    assert names.time_window is not None
    assert names.time_window.seconds == 86400
    assert [metric.metric for metric in names.metrics] == ["alpha.metric", "zeta.metric"]
    assert names.metrics[1].service == "svc-z"
    assert session.calls[0]["kwargs"]["json"] == {}
    assert "/cloud/statistics/views/all-metrics" in session.calls[0]["url"]
