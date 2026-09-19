"""Tests for the router-core (vAPI3) gona-parity methods.

Covers cloud router, VRF, VRF BGP, VRF BGP neighbor, static route, prefix
list, NTP and routing view methods on V3Client.
"""

from __future__ import annotations

import pytest

from netactuate import NetActuateError, NotFoundError, V3Client
from test_client import RecordedSession, response


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


# --- Router --------------------------------------------------------------


def test_list_routers_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"name": "r1", "hasDefaultVrf": True, "canJoinMagicMesh": False, "build": []}])]
    )

    routers = _v3(session).list_routers()

    assert [r.name for r in routers] == ["r1"]
    assert routers[0].ready_on is None
    assert "limit=1000" in session.calls[0]["url"]


def test_get_router_builds_path() -> None:
    session = RecordedSession([response({"name": "r1", "readyOn": "2026-01-01T00:00:00Z"})])

    router = _v3(session).get_router(9)

    assert router.ready_on == "2026-01-01T00:00:00Z"
    assert "/cloud-routing/routers/9" in session.calls[0]["url"]


def test_get_router_raises_not_found() -> None:
    session = RecordedSession([response({"message": "not found"}, code=404)])

    with pytest.raises(NotFoundError):
        _v3(session).get_router(99)


def test_get_router_config_decodes_metadata_and_vrfs() -> None:
    payload = {
        "defaultVrfId": 1,
        "service": {"ntp": {"enabled": True}},
        "prefixLists": [],
        "vrf": {
            "1": {
                "vrfId": 1,
                "name": "default",
                "description": "",
                "dnatRules": [],
                "snatRules": [],
                "services": {},
                "tunnels": [],
                "bgp": {"routerId": "1.2.3.4", "networks": [], "neighbors": []},
                "routes": {"static": []},
                "interfaces": [],
                "ipSec": {"peers": []},
            }
        },
        "ipSec": None,
        "metadata": {
            "status": "Running",
            "name": "r1",
            "version": 3,
            "ipv4Address": 16909060,
            "location": {"id": 5, "name": "Atlanta", "flag": None},
            "hasDefaultVrf": True,
            "canJoinMagicMesh": False,
        },
    }
    session = RecordedSession([response(payload)])

    config = _v3(session).get_router_config(9)

    assert config.default_vrf_id == 1
    assert config.vrf["1"].name == "default"
    assert config.vrf["1"].bgp.router_id == "1.2.3.4"
    assert config.metadata.ipv4_address == "1.2.3.4"
    assert config.metadata.location is not None
    assert config.metadata.location.name == "Atlanta"
    assert "/cloud-routing/routers/9/config" in session.calls[0]["url"]


def test_list_router_config_interfaces_returns_raw() -> None:
    session = RecordedSession([response({"interfaces": []})])

    data = _v3(session).list_router_config_interfaces(9)

    assert data == {"interfaces": []}
    assert "/cloud-routing/routers/9/config/interfaces" in session.calls[0]["url"]


def test_invalidate_router_config_cache_posts_no_body() -> None:
    session = RecordedSession([response(None)])

    _v3(session).invalidate_router_config_cache(9)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/cloud-routing/routers/9/config/invalidate-cache" in call["url"]
    assert call["kwargs"]["json"] is None


def test_create_router_sends_required_fields_only() -> None:
    session = RecordedSession([response({"routerId": 3})])

    router_id = _v3(session).create_router(package_id=10, location_id=20)

    assert router_id == 3
    assert session.calls[0]["kwargs"]["json"] == {"packageId": 10, "locationId": 20}


def test_create_router_rejects_missing_package_id() -> None:
    session = RecordedSession([])

    with pytest.raises(ValueError):
        _v3(session).create_router(package_id=0, location_id=20)


def test_update_router_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"name": "renamed"})])

    router = _v3(session).update_router(9, name="renamed")

    assert router.name == "renamed"
    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"name": "renamed"}


def test_delete_router_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router(9)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9" in session.calls[0]["url"]


def test_wait_for_router_ready_returns_once_ready_on_is_set() -> None:
    session = RecordedSession([response({"name": "r1", "readyOn": "2026-01-01T00:00:00Z", "build": []})])

    router = _v3(session).wait_for_router_ready(9, interval=0.01, timeout=1.0)

    assert router.ready_on == "2026-01-01T00:00:00Z"


def test_wait_for_router_ready_raises_when_build_stalls() -> None:
    build = [{"text": "step one", "date": ""}]
    session = RecordedSession([response({"name": "r1", "build": build}) for _ in range(5)])

    with pytest.raises(NetActuateError, match="no progress"):
        _v3(session).wait_for_router_ready(9, interval=0.01, timeout=1.0, stall_after=0.02)


# --- Router VRF ------------------------------------------------------------


def test_list_router_vrfs_decodes_map() -> None:
    payload = {
        "1": {
            "vrfId": 1,
            "name": "default",
            "description": "",
            "bgp": {"networks": [], "neighbors": []},
            "routes": {},
            "services": {},
            "ipSec": {},
        }
    }
    session = RecordedSession([response(payload)])

    vrfs = _v3(session).list_router_vrfs(9)

    assert set(vrfs.keys()) == {"1"}
    assert vrfs["1"].vrf_id == 1
    assert "/cloud-routing/routers/9/config/vrfs" in session.calls[0]["url"]


def test_create_router_vrf_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"vrfId": 2})])

    vrf_id = _v3(session).create_router_vrf(9, name="v2")

    assert vrf_id == 2
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {"name": "v2"}


def test_get_router_vrf_builds_path() -> None:
    session = RecordedSession(
        [response({"vrfId": 2, "name": "v2", "bgp": {}, "routes": {}, "services": {}, "ipSec": {}})]
    )

    vrf = _v3(session).get_router_vrf(9, 2)

    assert vrf.vrf_id == 2
    assert "/cloud-routing/routers/9/config/vrfs/2" in session.calls[0]["url"]


def test_update_router_vrf_uses_put() -> None:
    session = RecordedSession([response({"vrfId": 2})])

    vrf_id = _v3(session).update_router_vrf(9, 2, description="updated")

    assert vrf_id == 2
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {"description": "updated"}


def test_delete_router_vrf_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf(9, 2)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2" in session.calls[0]["url"]


# --- Router VRF BGP ---------------------------------------------------------


def test_get_router_vrf_bgp_builds_path() -> None:
    session = RecordedSession([response({"routerId": "1.1.1.1", "networks": [], "neighbors": []})])

    bgp = _v3(session).get_router_vrf_bgp(9, 2)

    assert bgp.router_id == "1.1.1.1"
    assert "/cloud-routing/routers/9/config/vrfs/2/bgp" in session.calls[0]["url"]


def test_update_router_vrf_bgp_omits_empty_networks_and_asn() -> None:
    session = RecordedSession([response({"routerId": 9, "networks": [], "neighbors": []})])

    _v3(session).update_router_vrf_bgp(9, 2)

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {}


def test_update_router_vrf_bgp_sends_networks_and_local_asn() -> None:
    session = RecordedSession([response({"routerId": 9, "networks": [], "neighbors": []})])

    result = _v3(session).update_router_vrf_bgp(9, 2, networks=["10.0.0.0/24"], local_asn="65000")

    assert result.router_id == 9
    call = session.calls[0]
    assert call["kwargs"]["json"] == {
        "networks": [{"subnet": "10.0.0.0/24"}],
        "asn": {"local": "65000"},
    }


# --- Router VRF BGP neighbor -------------------------------------------------


def test_list_router_vrf_bgp_neighbors_decodes_rows() -> None:
    payload = [
        {
            "neighborId": 1,
            "address": "10.0.0.1",
            "enabledIpVersion": {"ipv4": True, "ipv6": False},
            "asn": {"remote": 65001},
        }
    ]
    session = RecordedSession([response(payload)])

    neighbors = _v3(session).list_router_vrf_bgp_neighbors(9, 2)

    assert [n.neighbor_id for n in neighbors] == [1]
    assert neighbors[0].asn.remote == 65001
    assert "/cloud-routing/routers/9/config/vrfs/2/bgp/neighbors" in session.calls[0]["url"]


def test_create_router_vrf_bgp_neighbor_sends_required_fields_only() -> None:
    session = RecordedSession([response({"neighborId": 5})])

    neighbor_id = _v3(session).create_router_vrf_bgp_neighbor(9, 2, address="10.0.0.1", remote_asn=65001)

    assert neighbor_id == 5
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {
        "address": "10.0.0.1",
        "isShutdown": False,
        "doAsOverride": False,
        "doNextHelpSelf": False,
        "enabledIpVersion": {"ipv4": False, "ipv6": False},
        "asn": {"remote": 65001},
    }


def test_create_router_vrf_bgp_neighbor_sends_optional_fields_when_given() -> None:
    session = RecordedSession([response({"neighborId": 5})])

    _v3(session).create_router_vrf_bgp_neighbor(
        9,
        2,
        address="10.0.0.1",
        remote_asn=65001,
        source_address="10.0.0.2",
        ebgp_multihop=2,
        md5_secret="s3cret",
        import_route_map={"doDefaultDrop": True, "rules": []},
        export_route_map={"doDefaultDrop": False, "rules": []},
        name="n1",
        description="d1",
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["source"] == {"address": "10.0.0.2"}
    assert body["ebgpMultihop"] == 2
    assert body["md5Secret"] == "s3cret"
    assert body["import"] == {"doDefaultDrop": True, "rules": []}
    assert body["export"] == {"doDefaultDrop": False, "rules": []}
    assert body["name"] == "n1"
    assert body["description"] == "d1"


def test_get_router_vrf_bgp_neighbor_raises_not_found() -> None:
    session = RecordedSession([response({"message": "not found"}, code=404)])

    with pytest.raises(NotFoundError):
        _v3(session).get_router_vrf_bgp_neighbor(9, 2, 99)


def test_update_router_vrf_bgp_neighbor_uses_put() -> None:
    session = RecordedSession([response({"neighborId": 5})])

    neighbor_id = _v3(session).update_router_vrf_bgp_neighbor(9, 2, 5, address="10.0.0.1", remote_asn=65001)

    assert neighbor_id == 5
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_vrf_bgp_neighbor_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_bgp_neighbor(9, 2, 5)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/bgp/neighbors/5" in session.calls[0]["url"]


# --- Router static route -----------------------------------------------------


def test_list_router_static_routes_decodes_rows() -> None:
    payload = [{"staticRouteId": 1, "network": "10.0.0.0/24", "via": {"nextHop": "10.0.0.1"}}]
    session = RecordedSession([response(payload)])

    routes = _v3(session).list_router_static_routes(9, 2)

    assert [r.route_id for r in routes] == [1]
    assert routes[0].via.next_hop == "10.0.0.1"


def test_create_router_static_route_builds_via() -> None:
    session = RecordedSession([response({"staticRouteId": 3})])

    route_id = _v3(session).create_router_static_route(
        9, 2, network="10.0.0.0/24", via_next_hop="10.0.0.1", description="d", distance=5
    )

    assert route_id == 3
    call = session.calls[0]
    assert call["kwargs"]["json"] == {
        "network": "10.0.0.0/24",
        "via": {"nextHop": "10.0.0.1"},
        "description": "d",
        "distance": 5,
    }


def test_get_router_static_route_returns_match() -> None:
    payload = [
        {"staticRouteId": 1, "network": "10.0.0.0/24", "via": {}},
        {"staticRouteId": 2, "network": "10.0.1.0/24", "via": {}},
    ]
    session = RecordedSession([response(payload)])

    route = _v3(session).get_router_static_route(9, 2, 2)

    assert route.route_id == 2


def test_get_router_static_route_raises_not_found_when_missing() -> None:
    session = RecordedSession([response([{"staticRouteId": 1, "network": "10.0.0.0/24", "via": {}}])])

    with pytest.raises(NotFoundError):
        _v3(session).get_router_static_route(9, 2, 99)


def test_update_router_static_route_uses_put() -> None:
    session = RecordedSession([response({"staticRouteId": 1})])

    route_id = _v3(session).update_router_static_route(9, 2, 1, network="10.0.0.0/24")

    assert route_id == 1
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_static_route_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_static_route(9, 2, 1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/static-routes/1" in session.calls[0]["url"]


# --- Router prefix list ------------------------------------------------------


def test_create_router_prefix_list_always_sends_rules_key() -> None:
    session = RecordedSession([response({"prefixListId": 1})])

    prefix_list_id = _v3(session).create_router_prefix_list(9, name="pl1", ip_version=4)

    assert prefix_list_id == 1
    assert session.calls[0]["kwargs"]["json"] == {"name": "pl1", "ipVersion": 4, "rules": []}


def test_create_router_prefix_list_sends_given_rules() -> None:
    session = RecordedSession([response({"prefixListId": 1})])

    _v3(session).create_router_prefix_list(
        9, name="pl1", ip_version=4, rules=[{"action": "permit", "prefix": "10.0.0.0/24"}]
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["rules"] == [{"action": "permit", "prefix": "10.0.0.0/24"}]


def test_list_router_prefix_lists_decodes_rows() -> None:
    payload = [{"prefixListId": 1, "name": "pl1", "ipVersion": 4, "rules": []}]
    session = RecordedSession([response(payload)])

    lists = _v3(session).list_router_prefix_lists(9)

    assert [pl.prefix_list_id for pl in lists] == [1]


def test_get_router_prefix_list_returns_match() -> None:
    payload = [
        {"prefixListId": 1, "name": "pl1", "ipVersion": 4, "rules": []},
        {"prefixListId": 2, "name": "pl2", "ipVersion": 4, "rules": []},
    ]
    session = RecordedSession([response(payload)])

    prefix_list = _v3(session).get_router_prefix_list(9, 2)

    assert prefix_list.name == "pl2"


def test_get_router_prefix_list_raises_not_found_when_missing() -> None:
    session = RecordedSession([response([{"prefixListId": 1, "name": "pl1", "ipVersion": 4, "rules": []}])])

    with pytest.raises(NotFoundError):
        _v3(session).get_router_prefix_list(9, 99)


def test_update_router_prefix_list_uses_put() -> None:
    session = RecordedSession([response({"prefixListId": 1})])

    prefix_list_id = _v3(session).update_router_prefix_list(9, 1, name="pl1", ip_version=4)

    assert prefix_list_id == 1
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_prefix_list_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_prefix_list(9, 1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/prefix-lists/1" in session.calls[0]["url"]


# --- Router NTP --------------------------------------------------------------


def test_get_router_ntp_config_decodes_upstreams() -> None:
    payload = {"enabled": True, "interfaceId": None, "upstreams": [{"domain": "pool.ntp.org"}]}
    session = RecordedSession([response(payload)])

    config = _v3(session).get_router_ntp_config(9)

    assert config.enabled is True
    assert [u.domain for u in config.upstreams] == ["pool.ntp.org"]


def test_update_router_ntp_config_always_sends_all_three_keys() -> None:
    session = RecordedSession([response({"routerId": 9})])

    router_id = _v3(session).update_router_ntp_config(9)

    assert router_id == 9
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {"enabled": None, "interfaceId": None, "upstreams": None}


def test_update_router_ntp_config_sends_given_values() -> None:
    session = RecordedSession([response({"routerId": 9})])

    _v3(session).update_router_ntp_config(9, enabled=True, interface_id=3, upstreams=["pool.ntp.org"])

    body = session.calls[0]["kwargs"]["json"]
    assert body == {"enabled": True, "interfaceId": 3, "upstreams": [{"domain": "pool.ntp.org"}]}


# --- Router routing view ------------------------------------------------------


def test_get_router_routing_views_posts_selectors() -> None:
    session = RecordedSession([response({"views": []})])

    data = _v3(session).get_router_routing_views(9, 2, [{"ipVersion": 4, "name": "bgp"}])

    assert data == {"views": []}
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {"views": [{"ipVersion": 4, "name": "bgp"}]}
    assert "/cloud-routing/routers/9/view/routing/2" in call["url"]


def test_get_router_routing_overview_returns_raw() -> None:
    session = RecordedSession([response({"summary": {}})])

    data = _v3(session).get_router_routing_overview(9, 2)

    assert data == {"summary": {}}
    assert "/cloud-routing/routers/9/view/routing/2/overview" in session.calls[0]["url"]
