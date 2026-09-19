"""Tests for the servers, services and platform vAPI2 gona-parity methods."""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import parse_qs, urlsplit

import pytest

from netactuate import Client, NetActuateError
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def test_create_server_omits_zero_fields_and_sets_script_type() -> None:
    session = RecordedSession([response({"mbpkgid": 1, "status": "queued", "build": 1})])

    build = _client(session).create_server(plan="value.vc1", location=5, script_content="#cloud-config")

    assert build.server_id == 1
    assert build.status == "queued"
    values = session.calls[0]["kwargs"]["data"]
    assert values == {
        "plan": "value.vc1",
        "location": 5,
        "script_content": "#cloud-config",
        "script_type": "user-data",
    }
    assert session.calls[0]["method"] == "POST"
    assert "cloud/server/buy_build" in session.calls[0]["url"]


def test_create_server_sends_single_tag() -> None:
    session = RecordedSession([response({"mbpkgid": 1, "status": "queued", "build": 1})])

    _client(session).create_server(plan="value.vc1", tag="prod")

    assert session.calls[0]["kwargs"]["data"]["tag"] == "prod"


def test_create_server_tag_list_sends_repeated_field() -> None:
    session = RecordedSession([response({"mbpkgid": 1, "status": "queued", "build": 1})])

    _client(session).create_server(plan="value.vc1", tag_list=["a", "b"])

    assert session.calls[0]["kwargs"]["data"]["tag_list[]"] == ["a", "b"]


def test_create_server_empty_tag_list_clears_tags() -> None:
    session = RecordedSession([response({"mbpkgid": 1, "status": "queued", "build": 1})])

    _client(session).create_server(plan="value.vc1", tag_list=[])

    assert session.calls[0]["kwargs"]["data"]["tag_list[]"] == [""]


def test_build_server_posts_to_build_path_without_tag_field() -> None:
    session = RecordedSession([response({"mbpkgid": 7, "status": "queued", "build": 2})])

    build = _client(session).build_server(7, plan="value.vc2", tag_list=["x"])

    assert build.build == 2
    assert "cloud/server/build/7" in session.calls[0]["url"]
    values = session.calls[0]["kwargs"]["data"]
    assert "tag" not in values
    assert values["tag_list[]"] == ["x"]


def test_delete_server_returns_deleted_id() -> None:
    session = RecordedSession([response({"id": 42})])

    deleted_id = _client(session).delete_server(42, cancel_billing=True)

    assert deleted_id == 42
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "cloud/server/42/delete" in call["url"]
    assert call["kwargs"]["json"] == {"cancel_billing": True}


def test_delete_server_omits_cancel_billing_when_false() -> None:
    session = RecordedSession([response({"id": 42})])

    _client(session).delete_server(42)

    assert session.calls[0]["kwargs"]["json"] == {}


def test_delete_server_raises_when_response_has_no_id() -> None:
    session = RecordedSession([response({})])

    with pytest.raises(NetActuateError):
        _client(session).delete_server(42)


def test_unlink_server_posts_with_no_body() -> None:
    session = RecordedSession([response(None)])

    _client(session).unlink_server(9)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "cloud/server/9/unlink" in call["url"]
    assert call["kwargs"]["data"] == {}


def test_start_and_stop_server_post_json() -> None:
    session = RecordedSession([response(None), response(None)])
    client = _client(session)

    client.start_server(3)
    client.stop_server(3)

    assert "cloud/server/3/start" in session.calls[0]["url"]
    assert "cloud/server/3/shutdown" in session.calls[1]["url"]
    assert session.calls[0]["kwargs"]["json"] == {}
    assert session.calls[1]["kwargs"]["json"] == {}


def test_scale_server_returns_job_id() -> None:
    session = RecordedSession([response(4321)])

    job_id = _client(session).scale_server(3, pkg_name="value.vc2", allow_reboot=True)

    assert job_id == 4321
    call = session.calls[0]
    assert "cloud/scale/3" in call["url"]
    assert call["kwargs"]["json"] == {"allow_reboot": True, "pkg_name": "value.vc2"}


def test_get_job_status_decodes_payload() -> None:
    session = RecordedSession(
        [response({"id": 4321, "ts_insert": "2026-01-01", "command": "scale_vm", "status": 1})]
    )

    job = _client(session).get_job_status("scale_vm", 4321)

    assert job.id == 4321
    assert job.command == "scale_vm"
    assert "cloud/jobs/scale_vm/4321" in session.calls[0]["url"]


def test_list_services_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "description": "colo"}])])

    services = _client(session).list_services()

    assert services[0].id == 1
    assert services[0].description == "colo"


def test_list_colocation_services_adds_filter_query() -> None:
    session = RecordedSession([response([{"id": 1, "service_id": 9}])])

    services = _client(session).list_colocation_services(service_id=9)

    assert services[0].service_id == 9
    query = parse_qs(urlsplit(session.calls[0]["url"]).query)
    assert query["service_id"] == ["9"]


def test_list_colocation_services_without_filter_has_no_query() -> None:
    session = RecordedSession([response([])])

    _client(session).list_colocation_services()

    assert urlsplit(session.calls[0]["url"]).query.replace("key=secret", "") in ("", "&")


def test_get_colocation_service_by_id() -> None:
    session = RecordedSession([response({"id": 2, "rack_identifier": "R1"})])

    service = _client(session).get_colocation_service(2)

    assert service.rack_identifier == "R1"
    assert "services/colocation/2" in session.calls[0]["url"]


def test_iptransit_services_and_children() -> None:
    session = RecordedSession(
        [
            response([{"id": 1, "bgp_group_id": 5}]),
            response({"id": 1, "bgp_group_id": 5}),
            response([{"id": 10, "ip": "192.0.2.1"}]),
            response([{"id": 11, "name": "eth0"}]),
        ]
    )
    client = _client(session)

    services = client.list_iptransit_services()
    single = client.get_iptransit_service(1)
    addresses = client.list_iptransit_ip_addresses(service_iptransit_id=1)
    ports = client.list_iptransit_ports(service_iptransit_id=1)

    assert services[0].bgp_group_id == 5
    assert single.id == 1
    assert addresses[0].ip == "192.0.2.1"
    assert ports[0].name == "eth0"
    assert "service_iptransit_id=1" in session.calls[2]["url"]
    assert "service_iptransit_id=1" in session.calls[3]["url"]


def test_transport_services_and_ports() -> None:
    session = RecordedSession(
        [
            response([{"id": 1, "datacenter_id": 3}]),
            response({"id": 1, "datacenter_id": 3}),
            response([{"id": 5, "name": "port-1"}]),
        ]
    )
    client = _client(session)

    services = client.list_transport_services(service_id=1)
    single = client.get_transport_service(1)
    ports = client.list_transport_ports(service_transport_id=1)

    assert services[0].datacenter_id == 3
    assert single.id == 1
    assert ports[0].name == "port-1"


def test_get_platform_status_sorts_services_and_locations() -> None:
    payload = {
        "web": {
            "component_id": "c2",
            "locations": {
                "nyc": {"status": "operational", "last_updated": "t2"},
                "atl": {"status": "degraded", "last_updated": "t1"},
            },
        },
        "api": {"component_id": "c1", "locations": {}},
    }
    session = RecordedSession([response(payload)])

    statuses = _client(session).get_platform_status()

    assert [s.service for s in statuses] == ["api", "web"]
    web = statuses[1]
    assert [loc.location for loc in web.locations] == ["atl", "nyc"]
    assert web.locations[0].status == "degraded"


def test_list_platform_change_log_and_entry_coerce_numeric_id() -> None:
    session = RecordedSession(
        [
            response([{"id": 7, "title": "t", "short_description": "s", "status": "done"}]),
            response({"id": 7, "title": "t", "short_description": "s", "status": "done"}),
        ]
    )
    client = _client(session)

    entries = client.list_platform_change_log()
    entry = client.get_platform_change_log_entry(7)

    assert entries[0].change_log_id == "7"
    assert entry.change_log_id == "7"
    assert "platform/change-log/7" in session.calls[1]["url"]


def test_list_platform_datacenters() -> None:
    session = RecordedSession([response([{"id": 1, "name": "Atlanta", "iata": "ATL"}])])

    datacenters = _client(session).list_platform_datacenters("atlanta")

    assert datacenters[0].iata == "ATL"
    assert "platform/datacenters/atlanta" in session.calls[0]["url"]


def test_platform_looking_glass_init_and_execute() -> None:
    session = RecordedSession([response({"targets": ["ping"]}), response({"output": "ok"})])
    client = _client(session)

    init = client.get_platform_looking_glass_init()
    result = client.execute_platform_looking_glass(action="ping", target="1.1.1.1", full=1)

    assert init.raw == {"targets": ["ping"]}
    assert result.raw == {"output": "ok"}
    query = parse_qs(urlsplit(session.calls[1]["url"]).query)
    assert query["action"] == ["ping"]
    assert query["target"] == ["1.1.1.1"]
    assert query["full"] == ["1"]


def test_get_platform_maintenance_info() -> None:
    session = RecordedSession([response({"detail": "scheduled"})])

    info = _client(session).get_platform_maintenance_info(3)

    assert info.raw == {"detail": "scheduled"}
    assert "platform/maintenance-info/3" in session.calls[0]["url"]


def test_platform_events_endpoints_decode_active_upcoming_historic() -> None:
    payload: Dict[str, Any] = {
        "active": [{"event_id": "1", "type": "incident", "name": "n", "status": "open"}],
        "upcoming": [],
        "historic": [],
    }
    session = RecordedSession([response(payload), response(payload), response(payload), response(payload)])
    client = _client(session)

    incidents = client.get_platform_incidents("atlanta")
    history = client.get_platform_incident_history("atlanta")
    maintenance = client.get_platform_maintenance("atlanta")
    maintenance_history = client.get_platform_maintenance_history("atlanta")

    assert incidents.active[0].event_id == "1"
    assert history.active[0].name == "n"
    assert maintenance.active[0].status == "open"
    assert maintenance_history.active[0].type == "incident"
    assert "platform/incidents/atlanta" in session.calls[0]["url"]
    assert "platform/incidents/history/atlanta" in session.calls[1]["url"]
    assert "platform/maintenance/atlanta" in session.calls[2]["url"]
    assert "platform/maintenance/history/atlanta" in session.calls[3]["url"]
