"""Tests for the router-extras (vAPI3) gona-parity methods.

Covers router IPsec, router VRF interfaces, VRF interface wireguard peers,
VRF SNAT and DNAT rules, VRF tunnels and VRF DHCP on V3Client.
"""

from __future__ import annotations

import pytest

from netactuate import NotFoundError, V3Client
from test_client import RecordedSession, response


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


# --- Router IPsec config -----------------------------------------------------


def test_get_router_ipsec_config_decodes_groups() -> None:
    payload = {
        "ikeGroup": {
            "doAutoRenegotiation": True,
            "keyExchangeVersion": 2,
            "lifetimeSeconds": 3600,
            "dhGroupNumber": 14,
            "encryption": "aes256",
            "hash": "sha256",
            "prf": "sha256",
        },
        "espGroup": {"lifetimeSeconds": 1800, "encryption": "aes256", "hash": "sha256"},
    }
    session = RecordedSession([response(payload)])

    config = _v3(session).get_router_ipsec_config(9)

    assert config.ike_group.key_exchange_version == 2
    assert config.esp_group.lifetime_seconds == 1800
    assert "/cloud-routing/routers/9/config/ipSec" in session.calls[0]["url"]


def test_update_router_ipsec_config_sends_full_body() -> None:
    session = RecordedSession([response(None)])

    _v3(session).update_router_ipsec_config(
        9,
        ike_do_auto_renegotiation=True,
        ike_key_exchange_version=2,
        ike_lifetime_seconds=3600,
        ike_dh_group_number=14,
        ike_encryption="aes256",
        ike_hash="sha256",
        ike_prf="sha256",
        esp_lifetime_seconds=1800,
        esp_encryption="aes256",
        esp_hash="sha256",
    )

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {
        "ikeGroup": {
            "doAutoRenegotiation": True,
            "keyExchangeVersion": 2,
            "lifetimeSeconds": 3600,
            "dhGroupNumber": 14,
            "encryption": "aes256",
            "hash": "sha256",
            "prf": "sha256",
        },
        "espGroup": {"lifetimeSeconds": 1800, "encryption": "aes256", "hash": "sha256"},
    }


# --- Router VRF IPsec peers ---------------------------------------------------


def _ipsec_peer_payload(peer_id: int) -> dict:
    return {
        "ipSecPeerId": peer_id,
        "name": f"peer-{peer_id}",
        "description": None,
        "remoteId": "remote@example.com",
        "pskSecret": "secret",
        "doInitiateConnection": True,
        "peerAddress": "203.0.113.1",
        "localId": "local@example.com",
        "overlayNetwork": {"ipv4": "10.10.0.0/30", "ipv6": None},
    }


def test_list_router_vrf_ipsec_peers_decodes_rows() -> None:
    session = RecordedSession([response([_ipsec_peer_payload(1)])])

    peers = _v3(session).list_router_vrf_ipsec_peers(9, 2)

    assert [p.ip_sec_peer_id for p in peers] == [1]
    assert peers[0].overlay_network.ipv4 == "10.10.0.0/30"
    assert "/cloud-routing/routers/9/config/vrfs/2/ipSec/peers" in session.calls[0]["url"]


def test_get_router_vrf_ipsec_peer_returns_match() -> None:
    session = RecordedSession([response([_ipsec_peer_payload(1), _ipsec_peer_payload(2)])])

    peer = _v3(session).get_router_vrf_ipsec_peer(9, 2, 2)

    assert peer.name == "peer-2"


def test_get_router_vrf_ipsec_peer_raises_not_found_when_missing() -> None:
    session = RecordedSession([response([_ipsec_peer_payload(1)])])

    with pytest.raises(NotFoundError):
        _v3(session).get_router_vrf_ipsec_peer(9, 2, 99)


def test_create_router_vrf_ipsec_peer_sends_required_fields_only() -> None:
    session = RecordedSession([response({"ipSecPeerId": 3})])

    peer_id = _v3(session).create_router_vrf_ipsec_peer(
        9, 2, name="p1", remote_id="r1", psk_secret="s1", do_initiate_connection=True
    )

    assert peer_id == 3
    assert session.calls[0]["kwargs"]["json"] == {
        "name": "p1",
        "remoteId": "r1",
        "pskSecret": "s1",
        "doInitiateConnection": True,
        "overlayNetwork": {},
    }


def test_create_router_vrf_ipsec_peer_includes_optional_fields() -> None:
    session = RecordedSession([response({"ipSecPeerId": 3})])

    _v3(session).create_router_vrf_ipsec_peer(
        9,
        2,
        name="p1",
        remote_id="r1",
        psk_secret="s1",
        do_initiate_connection=True,
        description="d",
        peer_address="203.0.113.1",
        overlay_ipv4="10.10.0.0/30",
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["description"] == "d"
    assert body["peerAddress"] == "203.0.113.1"
    assert body["overlayNetwork"] == {"ipv4": "10.10.0.0/30"}


def test_update_router_vrf_ipsec_peer_uses_put() -> None:
    session = RecordedSession([response({"ipSecPeerId": 2})])

    peer_id = _v3(session).update_router_vrf_ipsec_peer(
        9, 2, 2, name="p1", remote_id="r1", psk_secret="s1", do_initiate_connection=False
    )

    assert peer_id == 2
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_vrf_ipsec_peer_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_ipsec_peer(9, 2, 5)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/ipSec/peers/5" in session.calls[0]["url"]


# --- Router VRF interfaces ----------------------------------------------------


def test_list_router_vrf_interfaces_decodes_map() -> None:
    payload = {"1": {"interfaceId": 1, "vrfId": 2, "type": "ethernet", "name": "eth0"}}
    session = RecordedSession([response(payload)])

    interfaces = _v3(session).list_router_vrf_interfaces(9, 2)

    assert interfaces["1"].interface_id == 1
    assert "/cloud-routing/routers/9/config/vrfs/2/interfaces" in session.calls[0]["url"]


def test_create_router_vrf_interface_sends_required_fields_only() -> None:
    session = RecordedSession([response({"interfaceId": 4})])

    interface_id = _v3(session).create_router_vrf_interface(9, 2, interface_type="wireguard", name="wg0")

    assert interface_id == 4
    assert session.calls[0]["kwargs"]["json"] == {"type": "wireguard", "name": "wg0"}


def test_create_router_vrf_interface_includes_optional_fields() -> None:
    session = RecordedSession([response({"interfaceId": 4})])

    _v3(session).create_router_vrf_interface(
        9, 2, interface_type="wireguard", name="wg0", wireguard_port=51820, description="d"
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["wireguardPort"] == 51820
    assert body["description"] == "d"


def test_get_router_vrf_interface_builds_path() -> None:
    session = RecordedSession([response({"interfaceId": 4, "vrfId": 2, "type": "ethernet", "name": "eth0"})])

    interface = _v3(session).get_router_vrf_interface(9, 2, 4)

    assert interface.interface_id == 4
    assert "/cloud-routing/routers/9/config/vrfs/2/interfaces/4" in session.calls[0]["url"]


def test_update_router_vrf_interface_uses_put() -> None:
    session = RecordedSession([response({"interfaceId": 4})])

    interface_id = _v3(session).update_router_vrf_interface(9, 2, 4, interface_type="ethernet", name="eth0")

    assert interface_id == 4
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_vrf_interface_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_interface(9, 2, 4)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/interfaces/4" in session.calls[0]["url"]


# --- Router VRF interface wireguard peers ------------------------------------


def test_create_router_vrf_interface_wireguard_peer_sends_null_optionals() -> None:
    session = RecordedSession([response({"wireguardPeerId": 7})])

    peer_id = _v3(session).create_router_vrf_interface_wireguard_peer(9, 2, 4)

    assert peer_id == 7
    assert session.calls[0]["kwargs"]["json"] == {
        "allowedIps": None,
        "publicKey": None,
        "preSharedKey": None,
        "name": None,
        "description": None,
        "remote": None,
    }


def test_create_router_vrf_interface_wireguard_peer_sends_allowed_ips() -> None:
    session = RecordedSession([response({"wireguardPeerId": 7})])

    _v3(session).create_router_vrf_interface_wireguard_peer(
        9, 2, 4, allowed_ips=["10.0.0.0/24"], public_key="pk", name="peer1"
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["allowedIps"] == [{"network": "10.0.0.0/24"}]
    assert body["publicKey"] == "pk"
    assert body["name"] == "peer1"


def test_get_router_vrf_interface_wireguard_peer_builds_path() -> None:
    payload = {
        "wireguardPeerId": 7,
        "allowedIps": [{"network": "10.0.0.0/24"}],
        "publicKey": "pk",
        "privateKey": "sk",
    }
    session = RecordedSession([response(payload)])

    peer = _v3(session).get_router_vrf_interface_wireguard_peer(9, 2, 4, 7)

    assert peer.wireguard_peer_id == 7
    assert peer.allowed_ips[0].network == "10.0.0.0/24"
    assert "/cloud-routing/routers/9/config/vrfs/2/interfaces/4/wireguard-peers/7" in session.calls[0]["url"]


def test_delete_router_vrf_interface_wireguard_peer_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_interface_wireguard_peer(9, 2, 4, 7)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/interfaces/4/wireguard-peers/7" in session.calls[0]["url"]


# --- Router VRF SNAT rules ----------------------------------------------------


def test_create_router_vrf_snat_rule_always_sends_match_and_translation() -> None:
    session = RecordedSession([response({"snatRuleId": 1})])

    rule_id = _v3(session).create_router_vrf_snat_rule(9, 2, ip_version=4)

    assert rule_id == 1
    assert session.calls[0]["kwargs"]["json"] == {
        "ipVersion": 4,
        "protocol": "",
        "match": None,
        "translation": None,
    }


def test_create_router_vrf_snat_rule_includes_given_blocks() -> None:
    session = RecordedSession([response({"snatRuleId": 1})])

    _v3(session).create_router_vrf_snat_rule(
        9,
        2,
        ip_version=4,
        protocol="tcp",
        description="d",
        match={"interfaceId": 3, "network": "10.0.0.0/24"},
        translation={"network": "203.0.113.1/32"},
        priority={"location": "first"},
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["protocol"] == "tcp"
    assert body["description"] == "d"
    assert body["match"] == {"interfaceId": 3, "network": "10.0.0.0/24"}
    assert body["translation"] == {"network": "203.0.113.1/32"}
    assert body["priority"] == {"location": "first"}


def test_list_router_vrf_snat_rules_decodes_rows() -> None:
    payload = [{"snatRuleId": 1, "ipVersion": 4, "protocol": "tcp"}]
    session = RecordedSession([response(payload)])

    rules = _v3(session).list_router_vrf_snat_rules(9, 2)

    assert [r.snat_rule_id for r in rules] == [1]


def test_get_router_vrf_snat_rule_returns_match() -> None:
    payload = [{"snatRuleId": 1}, {"snatRuleId": 2}]
    session = RecordedSession([response(payload)])

    rule = _v3(session).get_router_vrf_snat_rule(9, 2, 2)

    assert rule.snat_rule_id == 2


def test_get_router_vrf_snat_rule_raises_not_found_when_missing() -> None:
    session = RecordedSession([response([{"snatRuleId": 1}])])

    with pytest.raises(NotFoundError):
        _v3(session).get_router_vrf_snat_rule(9, 2, 99)


def test_update_router_vrf_snat_rule_always_sends_description() -> None:
    session = RecordedSession([response({"snatRuleId": 1})])

    rule_id = _v3(session).update_router_vrf_snat_rule(9, 2, 1, ip_version=4, protocol="tcp")

    assert rule_id == 1
    body = session.calls[0]["kwargs"]["json"]
    assert body == {"ipVersion": 4, "protocol": "tcp", "description": ""}
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_vrf_snat_rule_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_snat_rule(9, 2, 1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/snat-rules/1" in session.calls[0]["url"]


# --- Router VRF DNAT rules ----------------------------------------------------


def test_create_router_vrf_dnat_rule_always_sends_match_and_translation() -> None:
    session = RecordedSession([response({"dnatRuleId": 1})])

    rule_id = _v3(session).create_router_vrf_dnat_rule(9, 2, ip_version=4)

    assert rule_id == 1
    assert session.calls[0]["kwargs"]["json"] == {
        "ipVersion": 4,
        "protocol": "",
        "match": None,
        "translation": None,
    }


def test_list_router_vrf_dnat_rules_decodes_rows() -> None:
    payload = [{"dnatRuleId": 1, "ipVersion": 4, "protocol": "tcp"}]
    session = RecordedSession([response(payload)])

    rules = _v3(session).list_router_vrf_dnat_rules(9, 2)

    assert [r.dnat_rule_id for r in rules] == [1]


def test_get_router_vrf_dnat_rule_returns_match() -> None:
    payload = [{"dnatRuleId": 1}, {"dnatRuleId": 2}]
    session = RecordedSession([response(payload)])

    rule = _v3(session).get_router_vrf_dnat_rule(9, 2, 2)

    assert rule.dnat_rule_id == 2


def test_get_router_vrf_dnat_rule_raises_not_found_when_missing() -> None:
    session = RecordedSession([response([{"dnatRuleId": 1}])])

    with pytest.raises(NotFoundError):
        _v3(session).get_router_vrf_dnat_rule(9, 2, 99)


def test_update_router_vrf_dnat_rule_always_sends_description() -> None:
    session = RecordedSession([response({"dnatRuleId": 1})])

    rule_id = _v3(session).update_router_vrf_dnat_rule(9, 2, 1, ip_version=4, protocol="tcp")

    assert rule_id == 1
    body = session.calls[0]["kwargs"]["json"]
    assert body == {"ipVersion": 4, "protocol": "tcp", "description": ""}


def test_delete_router_vrf_dnat_rule_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_dnat_rule(9, 2, 1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/dnat-rules/1" in session.calls[0]["url"]


# --- Router VRF tunnels -------------------------------------------------------


def test_list_router_vrf_tunnels_decodes_rows() -> None:
    payload = [
        {
            "tunnelId": 1,
            "name": "t1",
            "ipKey": 5,
            "mtu": "1500",
            "ipVersion": 4,
            "endpointAddress": {"source": "203.0.113.1", "remote": "203.0.113.2"},
        }
    ]
    session = RecordedSession([response(payload)])

    tunnels = _v3(session).list_router_vrf_tunnels(9, 2)

    assert [t.tunnel_id for t in tunnels] == [1]
    assert tunnels[0].mtu == "1500"
    assert tunnels[0].endpoint_address.remote == "203.0.113.2"


def test_get_router_vrf_tunnel_builds_path() -> None:
    payload = {
        "tunnelId": 1,
        "name": "t1",
        "ipKey": 5,
        "mtu": "1500",
        "ipVersion": 4,
        "endpointAddress": {"source": "203.0.113.1", "remote": "203.0.113.2"},
    }
    session = RecordedSession([response(payload)])

    tunnel = _v3(session).get_router_vrf_tunnel(9, 2, 1)

    assert tunnel.tunnel_id == 1
    assert "/cloud-routing/routers/9/config/vrfs/2/tunnels/1" in session.calls[0]["url"]


def test_create_router_vrf_tunnel_sends_full_body_with_nulls() -> None:
    session = RecordedSession([response({"tunnelId": 3})])

    tunnel_id = _v3(session).create_router_vrf_tunnel(9, 2, ip_key=5, name="t1", mtu=1500, remote="203.0.113.2")

    assert tunnel_id == 3
    assert session.calls[0]["kwargs"]["json"] == {
        "ipKey": 5,
        "name": "t1",
        "description": None,
        "mtu": 1500,
        "ipv4Cidr": None,
        "ipv6Cidr": None,
        "endpointAddress": {"remote": "203.0.113.2"},
    }


def test_update_router_vrf_tunnel_uses_put() -> None:
    session = RecordedSession([response({"tunnelId": 3})])

    tunnel_id = _v3(session).update_router_vrf_tunnel(9, 2, 3, ip_key=5, name="t1", mtu=1500, remote="203.0.113.2")

    assert tunnel_id == 3
    assert session.calls[0]["method"] == "PUT"


def test_delete_router_vrf_tunnel_calls_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_router_vrf_tunnel(9, 2, 3)

    assert session.calls[0]["method"] == "DELETE"
    assert "/cloud-routing/routers/9/config/vrfs/2/tunnels/3" in session.calls[0]["url"]


# --- Router VRF DHCP -----------------------------------------------------------


def test_get_router_vrf_dhcp_decodes_config() -> None:
    payload = {
        "enabled": True,
        "interfaceId": 4,
        "subnet": "10.0.0.0/24",
        "defaultRouterAddress": "10.0.0.1",
        "clientDomainName": "example.com",
        "leaseTimeout": 3600,
        "doPingCheck": True,
        "range": {"firstAddress": "10.0.0.10", "lastAddress": "10.0.0.100"},
        "domainNameServers": [{"address": "8.8.8.8"}],
        "ntpServers": [{"address": "10.0.0.2"}],
        "staticRoutes": [{"network": "192.168.0.0/24", "nextHop": "10.0.0.254"}],
    }
    session = RecordedSession([response(payload)])

    config = _v3(session).get_router_vrf_dhcp(9, 2)

    assert config.enabled is True
    assert config.range is not None
    assert config.range.first_address == "10.0.0.10"
    assert config.domain_name_servers[0].address == "8.8.8.8"
    assert config.static_routes[0].next_hop == "10.0.0.254"
    assert "/cloud-routing/routers/9/config/vrfs/2/services/dhcp" in session.calls[0]["url"]


def test_update_router_vrf_dhcp_sends_null_collections_when_unset() -> None:
    session = RecordedSession([response({"routerId": 9})])

    router_id = _v3(session).update_router_vrf_dhcp(
        9, 2, enabled=True, interface_id=4, subnet="10.0.0.0/24", lease_timeout=3600, do_ping_check=True
    )

    assert router_id == 9
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {
        "enabled": True,
        "interfaceId": 4,
        "subnet": "10.0.0.0/24",
        "leaseTimeout": 3600,
        "doPingCheck": True,
        "range": None,
        "domainNameServers": None,
        "ntpServers": None,
        "staticRoutes": None,
    }


def test_update_router_vrf_dhcp_encodes_given_collections() -> None:
    session = RecordedSession([response({"routerId": 9})])

    _v3(session).update_router_vrf_dhcp(
        9,
        2,
        enabled=True,
        interface_id=4,
        subnet="10.0.0.0/24",
        lease_timeout=3600,
        do_ping_check=True,
        default_router_address="10.0.0.1",
        client_domain_name="example.com",
        dhcp_range={"first_address": "10.0.0.10", "last_address": "10.0.0.100"},
        domain_name_servers=["8.8.8.8"],
        ntp_servers=["10.0.0.2"],
        static_routes=[{"network": "192.168.0.0/24", "next_hop": "10.0.0.254"}],
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["defaultRouterAddress"] == "10.0.0.1"
    assert body["clientDomainName"] == "example.com"
    assert body["range"] == {"firstAddress": "10.0.0.10", "lastAddress": "10.0.0.100"}
    assert body["domainNameServers"] == [{"address": "8.8.8.8"}]
    assert body["ntpServers"] == [{"address": "10.0.0.2"}]
    assert body["staticRoutes"] == [{"network": "192.168.0.0/24", "nextHop": "10.0.0.254"}]
