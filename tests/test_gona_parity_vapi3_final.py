"""Tests for the final vAPI3 gona-parity domains.

Covers gona's http_loadbalancer.go, vpc_nameservers.go and account_limits.go.
"""

from __future__ import annotations

import pytest

from netactuate import NotFoundError, V3Client
from test_client import RecordedSession, response


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


def _group_payload(**overrides: object) -> dict:
    payload = {
        "httpGroupId": 1,
        "name": "web",
        "description": "",
        "algorithm": "round-robin",
        "stickySessionsEnabled": False,
        "sslToBackendEnabled": False,
        "internalPort": 8080,
        "isOnline": True,
        "match": {"address": "0.0.0.0", "ports": "80,443"},
        "healthCheck": {"active": {"enabled": True}, "passive": {"enabled": False}},
        "rules": [
            {
                "httpRuleId": 1,
                "httpsRedirectEnabled": True,
                "match": {"domain": "example.com", "path": "/"},
                "ssl": {"enabled": True, "sslCertificateId": 5},
            }
        ],
        "backends": [{"name": "web-1", "internalAddress": "10.0.0.1", "isOnline": True, "httpBackendId": 2}],
    }
    payload.update(overrides)
    return payload


# --- http_loadbalancer.go -------------------------------------------------


def test_create_http_lb_group_sends_full_body() -> None:
    session = RecordedSession([response(_group_payload())])

    group = _v3(session).create_http_lb_group(
        http_lb_id=10,
        name="web",
        algorithm="round-robin",
        internal_port=8080,
        match={"address": "0.0.0.0", "ports": "80,443"},
        health_check={"active": {"enabled": True}, "passive": {"enabled": False}},
        rules=[{"httpsRedirectEnabled": True, "match": {"domain": "example.com", "path": "/"}, "ssl": {"enabled": True}}],
        backends=[{"name": "web-1", "internalAddress": "10.0.0.1"}],
    )

    assert group.http_group_id == 1
    assert group.rules[0].match == {"domain": "example.com", "path": "/"}
    assert group.backends[0].name == "web-1"
    call = session.calls[0]
    assert "/http-loadbalancers/10/groups" in call["url"]
    body = call["kwargs"]["json"]
    assert body["name"] == "web"
    assert body["internalPort"] == 8080
    assert body["stickySessionsEnabled"] is False
    assert "description" not in body


def test_create_http_lb_group_includes_description_when_set() -> None:
    session = RecordedSession([response(_group_payload())])

    _v3(session).create_http_lb_group(
        http_lb_id=10,
        name="web",
        algorithm="round-robin",
        internal_port=8080,
        match={},
        health_check={},
        rules=[],
        backends=[],
        description="edge group",
        sticky_sessions_enabled=True,
        ssl_to_backend_enabled=True,
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["description"] == "edge group"
    assert body["stickySessionsEnabled"] is True
    assert body["sslToBackendEnabled"] is True


def test_list_http_lb_groups_decodes_rows() -> None:
    session = RecordedSession([response([_group_payload()])])

    groups = _v3(session).list_http_lb_groups(10)

    assert groups[0].http_group_id == 1
    assert "/http-loadbalancers/10/groups" in session.calls[0]["url"]


def test_get_http_lb_group_builds_path() -> None:
    session = RecordedSession([response(_group_payload(httpGroupId=2))])

    group = _v3(session).get_http_lb_group(10, 2)

    assert group.http_group_id == 2
    assert "/http-loadbalancers/10/groups/2" in session.calls[0]["url"]


def test_replace_http_lb_group_puts_full_body() -> None:
    session = RecordedSession([response(_group_payload(httpGroupId=2))])

    group = _v3(session).replace_http_lb_group(
        http_lb_id=10,
        group_id=2,
        name="web",
        algorithm="least-connections",
        internal_port=8080,
        match={},
        health_check={},
        rules=[],
        backends=[],
    )

    assert group.algorithm == "round-robin"
    assert session.calls[0]["method"] == "PUT"
    assert session.calls[0]["kwargs"]["json"]["algorithm"] == "least-connections"


def test_get_http_lb_group_raises_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _v3(session).get_http_lb_group(10, 99)


def test_delete_http_lb_group_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_http_lb_group(10, 2)

    assert session.calls[0]["method"] == "DELETE"
    assert "/http-loadbalancers/10/groups/2" in session.calls[0]["url"]


# --- vpc_nameservers.go ----------------------------------------------------


def test_get_vpc_nameservers_reads_from_vpc_dhcp_block() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "vpcId": 1,
                    "metadata": {"label": "vpc1"},
                    "dhcp": {"nameservers": {"ipv4": ["8.8.8.8", "8.8.4.4"], "ipv6": ["2001:4860:4860::8888"]}},
                }
            )
        ]
    )

    nameservers = _v3(session).get_vpc_nameservers(1)

    assert [n.server for n in nameservers.ipv4] == ["8.8.8.8", "8.8.4.4"]
    assert [n.server for n in nameservers.ipv6] == ["2001:4860:4860::8888"]
    assert "/vpcs/1" in session.calls[0]["url"]


def test_get_vpc_nameservers_returns_empty_when_dhcp_absent() -> None:
    session = RecordedSession([response({"vpcId": 1, "metadata": {"label": "vpc1"}})])

    nameservers = _v3(session).get_vpc_nameservers(1)

    assert nameservers.ipv4 == []
    assert nameservers.ipv6 == []


def test_replace_vpc_nameservers_sends_flat_list() -> None:
    session = RecordedSession([response({"nameservers": [{"server": "9.9.9.9"}, {"server": "1.1.1.1"}]})])

    result = _v3(session).replace_vpc_nameservers(1, ["9.9.9.9", "1.1.1.1"])

    assert [n.server for n in result] == ["9.9.9.9", "1.1.1.1"]
    assert session.calls[0]["method"] == "PUT"
    assert session.calls[0]["kwargs"]["json"] == {"nameservers": [{"server": "9.9.9.9"}, {"server": "1.1.1.1"}]}
    assert "/vpcs/1/dhcp/nameservers" in session.calls[0]["url"]


def test_update_vpc_nameservers_sends_only_provided_families() -> None:
    session = RecordedSession([response({"ipv4": [{"server": "9.9.9.9"}], "ipv6": []})])

    result = _v3(session).update_vpc_nameservers(1, ipv4=["9.9.9.9"])

    assert [n.server for n in result.ipv4] == ["9.9.9.9"]
    assert session.calls[0]["method"] == "PATCH"
    assert session.calls[0]["kwargs"]["json"] == {"ipv4": [{"server": "9.9.9.9"}]}


# --- account_limits.go -----------------------------------------------------


def test_get_account_limits_decodes_map() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "vpcs": {"used": 1, "max": 5, "allowedPlans": ["standard"]},
                    "routers": {"used": 0, "max": 2, "allowedPlans": []},
                }
            )
        ]
    )

    limits = _v3(session).get_account_limits()

    assert limits["vpcs"].used == 1
    assert limits["vpcs"].max == 5
    assert limits["vpcs"].allowed_plans == ["standard"]
    assert limits["routers"].max == 2
    assert "/account-limits" in session.calls[0]["url"]
