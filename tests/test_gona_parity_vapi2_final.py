"""Tests for the final vAPI2 gona-parity domains.

Covers gona's ddos.go, access_control_subnet.go, metal.go, bgp.go (session
methods), capacity.go, non_cloud_packages.go, packages.go, longtail.go,
locations.go, os.go and ip.go.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from netactuate import Client, NotFoundError
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def _query(url: str) -> dict:
    return parse_qs(urlsplit(url).query)


# --- ddos.go -----------------------------------------------------------


def test_list_ddos_attacks_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"id": 1, "ip": "192.0.2.1", "status": 1, "pps": 500}])]
    )

    attacks = _client(session).list_ddos_attacks()

    assert attacks[0].attack_id == 1
    assert attacks[0].ip == "192.0.2.1"
    assert attacks[0].pps == 500
    assert "ddos/attacks" in session.calls[0]["url"]
    assert "ddos/attacks/active" not in session.calls[0]["url"]


def test_list_active_ddos_attacks_hits_active_path() -> None:
    session = RecordedSession([response([])])

    attacks = _client(session).list_active_ddos_attacks()

    assert attacks == []
    assert "ddos/attacks/active" in session.calls[0]["url"]


def test_get_ddos_dashboard_applies_optional_filters() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "total_attacks": 3,
                    "active_rules": 1,
                    "longest_attack_seconds": 60,
                    "top_attacks": [{}],
                    "period": 86400,
                }
            )
        ]
    )

    dashboard = _client(session).get_ddos_dashboard(period=86400, include_ended=True, limit=5)

    assert dashboard.total_attacks == 3
    assert len(dashboard.top_attacks) == 1
    query = _query(session.calls[0]["url"])
    assert query["period"] == ["86400"]
    assert query["include_ended"] == ["true"]
    assert query["limit"] == ["5"]


def test_get_ddos_dashboard_omits_filters_when_unset() -> None:
    session = RecordedSession(
        [response({"total_attacks": 0, "active_rules": 0, "longest_attack_seconds": 0, "top_attacks": [], "period": 0})]
    )

    _client(session).get_ddos_dashboard()

    query = _query(session.calls[0]["url"])
    assert "period" not in query
    assert "include_ended" not in query
    assert "limit" not in query


def test_list_ddos_rules_decodes_nested_prefixes_and_actions() -> None:
    session = RecordedSession(
        [
            response(
                [
                    {
                        "id": 9,
                        "rule_name": "r9",
                        "description": "d",
                        "prefixes": [{"id": 1, "prefix": "10.0.0.0/8"}],
                        "rules": [{"name": "n", "action_type": "drop"}],
                    }
                ]
            )
        ]
    )

    rules = _client(session).list_ddos_rules()

    assert rules[0].rule_id == 9
    assert rules[0].prefixes[0].prefix == "10.0.0.0/8"
    assert rules[0].rules[0].action_type == "drop"


def test_get_ddos_rule_builds_path() -> None:
    session = RecordedSession([response({"id": 4, "rule_name": "r4"})])

    rule = _client(session).get_ddos_rule(4)

    assert rule.rule_id == 4
    assert "ddos/rule/4" in session.calls[0]["url"]


def test_get_ddos_rule_raises_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_ddos_rule(404)


# --- access_control_subnet.go -------------------------------------------


def test_list_access_control_subnets_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "label": "office", "subnet": "203.0.113.0/24"}])])

    subnets = _client(session).list_access_control_subnets()

    assert subnets[0].id == 1
    assert subnets[0].subnet == "203.0.113.0/24"
    assert "account/user-access-control-subnet-list" in session.calls[0]["url"]


def test_get_access_control_subnet_builds_path() -> None:
    session = RecordedSession([response({"id": 2, "label": "home", "subnet": "198.51.100.0/24"})])

    subnet = _client(session).get_access_control_subnet(2)

    assert subnet.label == "home"
    assert "account/user-access-control-subnet/2" in session.calls[0]["url"]


def test_create_access_control_subnet_sends_json_body() -> None:
    session = RecordedSession([response({"id": 3, "label": "new", "subnet": "192.0.2.0/24"})])

    subnet = _client(session).create_access_control_subnet("new", "192.0.2.0/24")

    assert subnet.id == 3
    assert session.calls[0]["kwargs"]["json"] == {"label": "new", "subnet": "192.0.2.0/24"}


def test_update_access_control_subnet_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"id": 3, "label": "renamed", "subnet": "192.0.2.0/24"})])

    _client(session).update_access_control_subnet(3, label="renamed")

    assert session.calls[0]["kwargs"]["json"] == {"label": "renamed"}


def test_get_access_control_subnet_raises_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_access_control_subnet(404)


def test_delete_access_control_subnet_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _client(session).delete_access_control_subnet(3)

    assert session.calls[0]["method"] == "DELETE"
    assert "account/user-access-control-subnet/3" in session.calls[0]["url"]


# --- metal.go ------------------------------------------------------------


def test_get_metal_build_status_builds_path() -> None:
    session = RecordedSession(
        [response({"mbpkgid": 5, "response": "ok", "status": "building", "percent": 50, "image_name": "centos"})]
    )

    status = _client(session).get_metal_build_status(5)

    assert status.percent == 50
    assert "dedicated/server/build_status/5" in session.calls[0]["url"]


def test_create_metal_server_form_encodes_and_omits_empty_fields() -> None:
    session = RecordedSession([response({"mbpkgid": 10, "status": "queued", "build": 1})])

    build = _client(session).create_metal_server(location=3, device=99, profile=7, hostname="host.example.com")

    assert build.mbpkgid == 10
    assert "dedicated/server/buy_build" in session.calls[0]["url"]
    values = session.calls[0]["kwargs"]["data"]
    assert values == {"location": 3, "device_id": 99, "profile": 7, "fqdn": "host.example.com"}


def test_create_metal_server_includes_optional_credentials() -> None:
    session = RecordedSession([response({"mbpkgid": 11, "status": "queued", "build": 2})])

    _client(session).create_metal_server(
        device=1, profile=1, ssh_key="ssh-ed25519 AAA", ssh_key_id=42, password="hunter2", build_script="#!/bin/sh"
    )

    values = session.calls[0]["kwargs"]["data"]
    assert values["ssh_key"] == "ssh-ed25519 AAA"
    assert values["ssh_key_id"] == 42
    assert values["root_password"] == "hunter2"
    assert values["build_script"] == "#!/bin/sh"


def test_build_metal_server_always_sends_mbpkgid() -> None:
    session = RecordedSession([response({"mbpkgid": 20, "status": "queued", "build": 3})])

    build = _client(session).build_metal_server(device_id=77, mbpkgid=20, profile=1)

    assert build.mbpkgid == 20
    assert "dedicated/server/re_build/77" in session.calls[0]["url"]
    assert session.calls[0]["kwargs"]["data"]["mbpkgid"] == 20


def test_get_metal_server_reuses_dedicated_server_model() -> None:
    session = RecordedSession(
        [response({"id": 1, "mbpkgid": 55, "hostname": "h", "primary_ip": "203.0.113.5", "location": "AMS"})]
    )

    server = _client(session).get_metal_server(1)

    assert server.mbpkgid == 55
    assert "dedicated/servers/1" in session.calls[0]["url"]


# --- bgp.go (session methods) --------------------------------------------


def test_get_bgp_session_builds_path() -> None:
    session = RecordedSession([response({"id": 3, "customer_peer_ip": "192.0.2.9"})])

    bgp_session = _client(session).get_bgp_session(3)

    assert bgp_session.customer_ip == "192.0.2.9"
    assert "bgp/bgpsession/3" in session.calls[0]["url"]


def test_bgp_session_is_locked_and_ip_type_properties() -> None:
    session = RecordedSession(
        [response({"id": 1, "locked": 1, "provider_ip_type": "ipv4", "provider_asn": "65000", "customer_asn": "65001"})]
    )

    bgp_session = _client(session).get_bgp_session(1)

    assert bgp_session.is_locked is True
    assert bgp_session.is_provider_ip_type_v4 is True
    assert bgp_session.provider_asn == 65000
    assert bgp_session.customer_asn == 65001


def test_list_bgp_sessions_filters_by_package_ips_and_refetches_detail() -> None:
    session = RecordedSession(
        [
            response([{"id": 1, "customer_peer_ip": "192.0.2.5"}, {"id": 2, "customer_peer_ip": "192.0.2.6"}]),
            response(
                {
                    "IPv4": [{"id": 1, "primary": 1, "reverse": "", "ip": "192.0.2.5", "gateway": "", "netmask": "", "broadcast": ""}],
                    "IPv6": [],
                }
            ),
            response({"id": 1, "customer_peer_ip": "192.0.2.5", "description": "matched"}),
        ]
    )

    sessions = _client(session).list_bgp_sessions(mbpkgid=42)

    assert [s.id for s in sessions] == [1]
    assert sessions[0].description == "matched"
    assert "cloud/networkips/42" in session.calls[1]["url"]
    assert "bgp/bgpsession/1" in session.calls[2]["url"]


def test_list_bgp_sessions_returns_empty_when_no_sessions_exist() -> None:
    session = RecordedSession([response([])])

    sessions = _client(session).list_bgp_sessions(mbpkgid=1)

    assert sessions == []
    assert len(session.calls) == 1


def test_list_bgp_sessions_matches_expanded_ipv6_form() -> None:
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
    session = RecordedSession(
        [
            response([{"id": 1, "customer_peer_ip": expanded}]),
            response({"IPv4": [], "IPv6": [{"id": 1, "primary": 0, "reverse": "", "ip": "2001:db8::1", "gateway": "", "netmask": "", "broadcast": ""}]}),
            response({"id": 1, "customer_peer_ip": expanded}),
        ]
    )

    sessions = _client(session).list_bgp_sessions(mbpkgid=1)

    assert [s.id for s in sessions] == [1]


def test_create_bgp_session_sends_form_flags_only_when_true() -> None:
    session = RecordedSession([response({"id": 1, "customer_peer_ip": "192.0.2.1"})])

    _client(session).create_bgp_session(mbpkgid=5, group_id=9, ipv6=True)

    values = session.calls[0]["kwargs"]["data"]
    assert values == {"mbpkgid": 5, "group_id": 9, "ipv6": "1"}


def test_create_bgp_session_omits_flags_when_false() -> None:
    session = RecordedSession([response({"id": 1, "customer_peer_ip": "192.0.2.1"})])

    _client(session).create_bgp_session(mbpkgid=5, group_id=9)

    values = session.calls[0]["kwargs"]["data"]
    assert values == {"mbpkgid": 5, "group_id": 9}


def test_delete_bgp_session_posts_without_body() -> None:
    session = RecordedSession([response(None)])

    _client(session).delete_bgp_session(7)

    assert session.calls[0]["method"] == "POST"
    assert "bgp/bgpsession/7/delete" in session.calls[0]["url"]
    assert session.calls[0]["kwargs"]["json"] is None


# --- capacity.go -----------------------------------------------------------


def test_list_billing_packages_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "pkg", "packageid": 2}])])

    packages = _client(session).list_billing_packages()

    assert packages[0].name == "pkg"
    assert "cloud/billing-packages" in session.calls[0]["url"]


def test_list_cloud_pools_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "default"}])])

    pools = _client(session).list_cloud_pools()

    assert pools[0].name == "default"
    assert "cloud/pools" in session.calls[0]["url"]


def test_get_cloud_capacity_builds_query() -> None:
    session = RecordedSession([response([{"pkg_id": 1, "pkg_name": "s1", "monthly_price": 9.5, "available": 3}])])

    capacity = _client(session).get_cloud_capacity(cloud_pool_id=4, location_id=7)

    assert capacity[0].package_name == "s1"
    assert capacity[0].monthly_price == 9.5
    query = _query(session.calls[0]["url"])
    assert query["cloud_pool_id"] == ["4"]
    assert query["location_id"] == ["7"]


def test_list_dedicated_capacity_decodes_rows() -> None:
    session = RecordedSession([response([{"device_id": 1, "location_id": 2, "mbpkgid": 3, "name": "n"}])])

    capacity = _client(session).list_dedicated_capacity()

    assert capacity[0].device_id == 1
    assert "dedicated/capacity" in session.calls[0]["url"]


# --- non_cloud_packages.go --------------------------------------------------


def test_list_colocation_packages_sorts_by_mbpkgid() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "2": {"mbpkgid": 2, "fqdn": "b.example.com", "details": {"dc_name": "dc"}},
                    "1": {"mbpkgid": 1, "fqdn": "a.example.com", "details": {"dc_name": "dc"}},
                }
            )
        ]
    )

    packages = _client(session).list_colocation_packages()

    assert [p.mbpkgid for p in packages] == [1, 2]
    assert packages[0].details.dc_name == "dc"


def test_get_colocation_package_builds_path() -> None:
    session = RecordedSession([response({"mbpkgid": 5, "fqdn": "c.example.com", "details": {}})])

    package = _client(session).get_colocation_package(5)

    assert package.fqdn == "c.example.com"
    assert "colo/package/5" in session.calls[0]["url"]


def test_list_transit_packages_sorts_by_mbpkgid() -> None:
    session = RecordedSession(
        [response({"9": {"mbpkgid": 9, "details": {}}, "3": {"mbpkgid": 3, "details": {}}})]
    )

    packages = _client(session).list_transit_packages()

    assert [p.mbpkgid for p in packages] == [3, 9]


def test_get_transit_package_builds_path() -> None:
    session = RecordedSession([response({"mbpkgid": 6, "details": {}})])

    package = _client(session).get_transit_package(6)

    assert package.mbpkgid == 6
    assert "transit/package/6" in session.calls[0]["url"]


def test_list_colocation_packages_rejects_non_object_response() -> None:
    from netactuate import NetActuateError

    session = RecordedSession([response([1, 2, 3])])

    with pytest.raises(NetActuateError):
        _client(session).list_colocation_packages()


# --- packages.go -------------------------------------------------------


def test_list_packages_decodes_rows() -> None:
    session = RecordedSession([response([{"mbpkgid": 1, "package_status": "Active", "name": "plan"}])])

    packages = _client(session).list_packages()

    assert packages[0].id == 1
    assert packages[0].plan_name == "plan"
    assert "cloud/packages" in session.calls[0]["url"]


def test_get_package_builds_path() -> None:
    session = RecordedSession([response({"mbpkgid": 2, "package_status": "Active", "name": "p2"})])

    package = _client(session).get_package(2)

    assert package.id == 2
    assert "cloud/package/2" in session.calls[0]["url"]


def test_cancel_package_sends_json_body_and_returns_mapping() -> None:
    session = RecordedSession([response({"ok": True})])

    result = _client(session).cancel_package(mbpkgid=9, cancel_type="immediate", agree=1, password="secret")

    assert result == {"ok": True}
    assert session.calls[0]["kwargs"]["json"] == {
        "mbpkgid": 9,
        "cancel_type": "immediate",
        "agree": 1,
        "password": "secret",
    }
    assert "cloud/package/cancel/" in session.calls[0]["url"]


# --- longtail.go ---------------------------------------------------------


def test_get_location_by_current_ip_decodes_response() -> None:
    session = RecordedSession([response({"ip": "203.0.113.9", "location": "AMS"})])

    location = _client(session).get_location_by_current_ip()

    assert location.ip == "203.0.113.9"
    assert location.location == "AMS"
    assert "location" in session.calls[0]["url"]


def test_get_graph_builds_query_and_returns_raw_payload() -> None:
    session = RecordedSession([response({"series": [1, 2, 3]})])

    graph = _client(session).get_graph(port=4, time_range="daily")

    assert graph == {"series": [1, 2, 3]}
    query = _query(session.calls[0]["url"])
    assert query["port"] == ["4"]
    assert query["time"] == ["daily"]


# --- locations.go and os.go -------------------------------------------------


def test_list_cloud_locations_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"id": 1, "name": "Amsterdam", "iata_code": "AMS", "continent": "EU", "flag": "nl", "disabled": 0}])]
    )

    locations = _client(session).list_cloud_locations()

    assert locations[0].name == "Amsterdam"
    assert locations[0].continent == "EU"
    assert "cloud/locations" in session.calls[0]["url"]


def test_list_operating_systems_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"id": 1, "os": "Ubuntu 22.04", "type": "linux", "subtype": "ubuntu", "size": "small", "bits": "64", "tech": "kvm"}])]
    )

    systems = _client(session).list_operating_systems()

    assert systems[0].os == "Ubuntu 22.04"
    assert "cloud/images" in session.calls[0]["url"]
    assert "cloud/images/" not in session.calls[0]["url"]


# --- ip.go ---------------------------------------------------------------


def test_get_cloud_network_ips_decodes_both_families() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "IPv4": [{"id": 1, "primary": 1, "reverse": "", "ip": "192.0.2.1", "gateway": "192.0.2.254", "netmask": "255.255.255.0", "broadcast": "192.0.2.255"}],
                    "IPv6": [{"id": 2, "primary": 0, "reverse": "", "ip": "2001:db8::1", "gateway": "", "netmask": "", "broadcast": ""}],
                }
            )
        ]
    )

    ips = _client(session).get_cloud_network_ips(mbpkgid=5)

    assert ips.ipv4[0].ip == "192.0.2.1"
    assert ips.ipv6[0].ip == "2001:db8::1"
    assert "cloud/networkips/5" in session.calls[0]["url"]
