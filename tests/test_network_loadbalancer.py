"""Tests for the network load balancer group (vAPI3) gona-parity methods.

Covers gona's network_loadbalancer.go.
"""

from __future__ import annotations

import pytest

from netactuate import NotFoundError, V3Client
from test_client import RecordedSession, response


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


def _group_payload(group_id: int = 7) -> dict:
    return {
        "networkGroupId": group_id,
        "name": "web",
        "description": "web tier",
        "ipVersion": 4,
        "algorithm": "round-robin",
        "isOnline": True,
        "match": {"address": "203.0.113.10"},
        "healthCheck": {
            "enabled": True,
            "method": "tcp",
            "interval": 10,
            "retries": 3,
            "delay": 2,
            "timeout": 5,
        },
        "rules": [
            {
                "protocol": "tcp",
                "networkRuleId": 1,
                "ports": {"match": 443, "internal": 8443},
            }
        ],
        "backends": [
            {
                "name": "web-1",
                "internalAddress": "10.0.0.5",
                "isOnline": True,
                "networkBackendId": 11,
            }
        ],
    }


def test_create_nlb_group_posts_body_and_decodes_response() -> None:
    session = RecordedSession([response(_group_payload())])

    group = _v3(session).create_nlb_group(
        1,
        "web",
        4,
        "round-robin",
        match={"address": "203.0.113.10"},
        health_check={"enabled": True, "method": "tcp", "interval": 10, "retries": 3, "delay": 2, "timeout": 5},
        rules=[{"protocol": "tcp", "ports": {"match": 443, "internal": 8443}}],
        backends=[{"name": "web-1", "internalAddress": "10.0.0.5"}],
        description="web tier",
    )

    assert group.network_group_id == 7
    assert group.rules[0].protocol == "tcp"
    assert group.rules[0].ports == {"match": 443, "internal": 8443}
    assert group.backends[0].network_backend_id == 11
    call = session.calls[0]
    assert "/network-loadbalancers/1/groups" in call["url"]
    body = call["kwargs"]["json"]
    assert body["name"] == "web"
    assert body["description"] == "web tier"
    assert body["rules"] == [{"protocol": "tcp", "ports": {"match": 443, "internal": 8443}}]


def test_create_nlb_group_omits_description_when_unset() -> None:
    session = RecordedSession([response(_group_payload())])

    _v3(session).create_nlb_group(
        1,
        "web",
        4,
        "round-robin",
        match={"address": "203.0.113.10"},
        health_check={"enabled": True, "method": "tcp", "interval": 10, "retries": 3, "delay": 2, "timeout": 5},
        rules=[],
        backends=[],
    )

    assert "description" not in session.calls[0]["kwargs"]["json"]


def test_get_nlb_group_decodes_response() -> None:
    session = RecordedSession([response(_group_payload(group_id=9))])

    group = _v3(session).get_nlb_group(1, 9)

    assert group.network_group_id == 9
    assert "/network-loadbalancers/1/groups/9" in session.calls[0]["url"]


def test_get_nlb_group_raises_not_found() -> None:
    session = RecordedSession([response({"message": "not found"}, code=404)])

    with pytest.raises(NotFoundError):
        _v3(session).get_nlb_group(1, 999)


def test_list_nlb_groups_decodes_rows() -> None:
    session = RecordedSession([response([_group_payload(group_id=3), _group_payload(group_id=4)])])

    groups = _v3(session).list_nlb_groups(1)

    assert [g.network_group_id for g in groups] == [3, 4]
    assert "/network-loadbalancers/1/groups" in session.calls[0]["url"]


def test_replace_nlb_group_puts_body() -> None:
    session = RecordedSession([response(_group_payload(group_id=7))])

    group = _v3(session).replace_nlb_group(
        1,
        7,
        "web",
        4,
        "least-connections",
        match={"address": "203.0.113.10"},
        health_check={"enabled": True, "method": "tcp", "interval": 10, "retries": 3, "delay": 2, "timeout": 5},
        rules=[],
        backends=[],
    )

    assert group.network_group_id == 7
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "/network-loadbalancers/1/groups/7" in call["url"]
    assert call["kwargs"]["json"]["algorithm"] == "least-connections"


def test_delete_nlb_group_sends_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_nlb_group(1, 7)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/network-loadbalancers/1/groups/7" in call["url"]
