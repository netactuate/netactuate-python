"""Tests for the BGP (vAPI2) and magic mesh (vAPI3) gona-parity methods."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from netactuate import Client, NotFoundError, V3Client
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


def _query(url: str) -> dict:
    return parse_qs(urlsplit(url).query)


# --- BGP groups --------------------------------------------------------


def test_create_bgp_group_sends_json_body() -> None:
    session = RecordedSession([response({"id": 1, "name": "g1", "description": "d", "group_type": "anycast"})])

    group = _client(session).create_bgp_group("g1", description="d", group_type="anycast")

    assert group.id == 1
    assert session.calls[0]["kwargs"]["json"] == {"name": "g1", "description": "d", "group_type": "anycast"}


def test_create_bgp_group_omits_group_type_when_unset() -> None:
    session = RecordedSession([response({"id": 1, "name": "g1"})])

    _client(session).create_bgp_group("g1")

    assert session.calls[0]["kwargs"]["json"] == {"name": "g1", "description": ""}


def test_get_bgp_group_builds_path() -> None:
    session = RecordedSession([response({"id": 7, "name": "g7"})])

    group = _client(session).get_bgp_group(7)

    assert group.id == 7
    assert "bgp/bgpgroup/7" in session.calls[0]["url"]


def test_get_bgp_group_raises_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_bgp_group(99)


def test_list_bgp_groups_applies_group_type_filter() -> None:
    session = RecordedSession([response([{"id": 1, "name": "g1"}])])

    groups = _client(session).list_bgp_groups(group_type="unicast")

    assert [g.id for g in groups] == [1]
    assert _query(session.calls[0]["url"])["group_type"] == ["unicast"]


def test_list_bgp_groups_omits_filter_when_unset() -> None:
    session = RecordedSession([response([])])

    _client(session).list_bgp_groups()

    assert "group_type" not in _query(session.calls[0]["url"])


def test_bind_bgp_group_firewall_set_sends_json_body() -> None:
    session = RecordedSession(
        [response({"id": 2, "bgp2_group_id": 1, "firewall_set_id": 3, "interface_number": 0, "set_priority": 1})]
    )

    binding = _client(session).bind_bgp_group_firewall_set(1, identifier=2, firewall_set_id=3, interface_number=0, set_priority=1)

    assert binding.bgp_group_id == 1
    assert binding.firewall_set_id == 3
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "bgp/bgp-groups/1/firewall-sets" in call["url"]
    assert call["kwargs"]["json"] == {
        "id": 2,
        "firewall_set_id": 3,
        "interface_number": 0,
        "set_priority": 1,
    }


def test_unbind_bgp_group_firewall_set_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _client(session).unbind_bgp_group_firewall_set(1, 3)

    assert session.calls[0]["method"] == "DELETE"
    assert "bgp/bgp-groups/1/firewall-sets/3" in session.calls[0]["url"]


@pytest.mark.parametrize(
    ("method", "path_suffix"),
    [
        ("refresh_bgp_group_sessions", "refresh"),
        ("start_bgp_group_sessions", "start"),
        ("stop_bgp_group_sessions", "stop"),
    ],
)
def test_bgp_group_session_actions_post_form_without_body(method: str, path_suffix: str) -> None:
    session = RecordedSession([response(None)])

    getattr(_client(session), method)(5)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert f"bgp/bgpgroup/5/{path_suffix}" in call["url"]
    assert call["kwargs"]["data"] == {}


@pytest.mark.parametrize(
    ("method", "path_suffix"),
    [
        ("refresh_bgp_session", "refresh"),
        ("start_bgp_session", "start"),
        ("stop_bgp_session", "stop"),
    ],
)
def test_bgp_session_actions_post_form_without_body(method: str, path_suffix: str) -> None:
    session = RecordedSession([response(None)])

    getattr(_client(session), method)(9)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert f"bgp/bgpsession/9/{path_suffix}" in call["url"]
    assert call["kwargs"]["data"] == {}


# --- BGP summary and dashboard ------------------------------------------


def test_get_bgp_summary_returns_raw_mapping() -> None:
    session = RecordedSession([response({"anycast": {"sessions": 2}})])

    summary = _client(session).get_bgp_summary()

    assert summary == {"anycast": {"sessions": 2}}


def test_get_bgp_dashboard_applies_optional_filters() -> None:
    session = RecordedSession([response({"groups": []})])

    dashboard = _client(session).get_bgp_dashboard(group_type="anycast", flap_window=3600)

    assert dashboard == {"groups": []}
    query = _query(session.calls[0]["url"])
    assert query["group_type"] == ["anycast"]
    assert query["flap_window"] == ["3600"]


def test_get_bgp_dashboard_omits_filters_when_unset() -> None:
    session = RecordedSession([response({})])

    _client(session).get_bgp_dashboard()

    query = _query(session.calls[0]["url"])
    assert "group_type" not in query
    assert "flap_window" not in query


# --- BGP prefixes, ASNs, agreements --------------------------------------


def test_buy_bgp_prefixes_always_sends_name_and_agreement_id() -> None:
    session = RecordedSession([response({"id": 1, "name": "p1", "agreement_id": 4})])

    prefix = _client(session).buy_bgp_prefixes("p1", agreement_id=4)

    assert prefix.id == 1
    assert session.calls[0]["kwargs"]["json"] == {"name": "p1", "agreement_id": 4}


def test_buy_bgp_prefixes_includes_optional_fields_when_set() -> None:
    session = RecordedSession([response({"id": 1, "name": "p1"})])

    _client(session).buy_bgp_prefixes("p1", agreement_id=4, group_id=2, asn_id=3, anycast_profile=1)

    assert session.calls[0]["kwargs"]["json"] == {
        "name": "p1",
        "agreement_id": 4,
        "group_id": 2,
        "asn_id": 3,
        "anycast_profile": 1,
    }


def test_get_bgp_prefix_builds_path() -> None:
    session = RecordedSession([response({"id": 8, "name": "p8"})])

    prefix = _client(session).get_bgp_prefix(8)

    assert prefix.id == 8
    assert "bgp/bgpprefix/8" in session.calls[0]["url"]


def test_list_bgp_prefixes_applies_group_type_filter() -> None:
    session = RecordedSession([response([{"id": 1, "name": "p1"}])])

    prefixes = _client(session).list_bgp_prefixes(group_type="unicast")

    assert [p.id for p in prefixes] == [1]
    assert _query(session.calls[0]["url"])["group_type"] == ["unicast"]


def test_list_bgp_asns_applies_group_type_filter() -> None:
    session = RecordedSession([response([{"id": 1, "asn": 65000, "name": "a1"}])])

    asns = _client(session).list_bgp_asns(group_type="unicast")

    assert [a.asn for a in asns] == [65000]
    assert _query(session.calls[0]["url"])["group_type"] == ["unicast"]


def test_get_bgp_asn_builds_query_path() -> None:
    session = RecordedSession([response({"id": 3, "asn": 65001, "name": "a3"})])

    asn = _client(session).get_bgp_asn(3)

    assert asn.asn == 65001
    assert "bgp/bgpasn" in session.calls[0]["url"]
    assert _query(session.calls[0]["url"])["id"] == ["3"]


def test_get_bgp_asn_raises_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_bgp_asn(99)


def test_list_account_agreements_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "tos", "title": "Terms", "description": "d", "version": "1"}])])

    agreements = _client(session).list_account_agreements()

    assert [agreement.name for agreement in agreements] == ["tos"]
    assert "account/agreements" in session.calls[0]["url"]


# --- Magic mesh (vAPI3) ---------------------------------------------------


def test_list_magic_meshes_decodes_rows() -> None:
    session = RecordedSession([response([{"meshId": 1, "name": "m1", "description": None}])])

    meshes = _v3(session).list_magic_meshes()

    assert [m.mesh_id for m in meshes] == [1]
    assert meshes[0].description is None
    assert "limit=1000" in session.calls[0]["url"]


def test_create_magic_mesh_sends_routers_when_given() -> None:
    session = RecordedSession([response({"meshId": 5})])

    mesh_id = _v3(session).create_magic_mesh("m1", description="d", router_ids=[1, 2])

    assert mesh_id == 5
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {
        "name": "m1",
        "description": "d",
        "routers": [{"routerId": 1}, {"routerId": 2}],
    }


def test_create_magic_mesh_omits_optional_fields_when_unset() -> None:
    session = RecordedSession([response({"meshId": 5})])

    _v3(session).create_magic_mesh("m1")

    assert session.calls[0]["kwargs"]["json"] == {"name": "m1"}


def test_get_magic_mesh_builds_path() -> None:
    session = RecordedSession([response({"meshId": 9, "name": "m9"})])

    mesh = _v3(session).get_magic_mesh(9)

    assert mesh.mesh_id == 9
    assert "/cloud-routing/meshes/9" in session.calls[0]["url"]


def test_get_magic_mesh_raises_not_found() -> None:
    session = RecordedSession([response({"message": "not found"}, code=404)])

    with pytest.raises(NotFoundError):
        _v3(session).get_magic_mesh(99)


def test_update_magic_mesh_sends_only_provided_fields() -> None:
    session = RecordedSession([response(None)])

    _v3(session).update_magic_mesh(9, name="renamed")

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"name": "renamed"}


def test_delete_magic_mesh_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_magic_mesh(9)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/meshes/9" in session.calls[0]["url"]


def test_list_mesh_routers_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"routerId": 1, "name": "r1", "description": "d", "ipv4Address": "10.0.0.1"}])]
    )

    routers = _v3(session).list_mesh_routers(9)

    assert [r.router_id for r in routers] == [1]
    assert routers[0].ipv4_address == "10.0.0.1"
    assert "/cloud-routing/meshes/9/routers" in session.calls[0]["url"]


def test_add_router_to_mesh_sends_json_body() -> None:
    session = RecordedSession([response(None)])

    _v3(session).add_router_to_mesh(9, 4)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/cloud-routing/meshes/9/routers" in call["url"]
    assert call["kwargs"]["json"] == {"routerId": 4}


def test_remove_router_from_mesh_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).remove_router_from_mesh(9, 4)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/meshes/9/routers/4" in session.calls[0]["url"]
