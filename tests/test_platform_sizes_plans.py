"""Tests for small single-method vAPI2 gona-parity domains.

Covers gona's datacenters.go, sizes.go and plans.go.
"""

from __future__ import annotations

from netactuate import Client
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def test_get_datacenter_by_iata_returns_id() -> None:
    session = RecordedSession([response({"id": 42, "name": "Amsterdam", "iata": "AMS"})])

    datacenter_id = _client(session).get_datacenter_by_iata("AMS")

    assert datacenter_id == 42
    assert "platform/datacenters-by-iata/AMS" in session.calls[0]["url"]


def test_list_sizes_decodes_rows() -> None:
    payload = [
        {
            "plan_id": 1,
            "plan": "value.m1",
            "ram": "1024",
            "disk": "25",
            "transfer": "1000",
            "price": "5.00",
            "cpu": 1,
            "port": "100",
            "available": 10,
        }
    ]
    session = RecordedSession([response(payload)])

    sizes = _client(session).list_sizes()

    assert len(sizes) == 1
    assert sizes[0].plan_id == 1
    assert sizes[0].cpu == 1
    assert "cloud/sizes" in session.calls[0]["url"]


def test_list_plans_decodes_rows_without_cpu_field() -> None:
    payload = [
        {
            "plan_id": 2,
            "plan": "value.m2",
            "ram": "2048",
            "disk": "50",
            "transfer": "2000",
            "price": "10.00",
            "available": 5,
        }
    ]
    session = RecordedSession([response(payload)])

    plans = _client(session).list_plans()

    assert len(plans) == 1
    assert plans[0].id == 2
    assert plans[0].name == "value.m2"
    assert plans[0].available == 5.0
    assert "cloud/sizes" in session.calls[0]["url"]
