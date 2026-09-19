from __future__ import annotations

from typing import Any, Callable

import pytest

from netactuate.models import (
    DNSRecord,
    DNSZone,
    NKEAddon,
    NKEClusterDNSZone,
    NKECluster,
    NKEWorkerNode,
    SSHKey,
    Server,
    StorageBlockNamespace,
    StorageBlockVolume,
    StorageBucket,
    StorageLocation,
    StorageObjectStore,
    StorageType,
    Tag,
    TagLog,
    TagResource,
    VPC,
    VPCBackend,
    VPCBackendTemplate,
    VPCDNATRule,
    VPCFirewallRule,
    VPCFloatingIP,
    VPCLocation,
    VPCSNATRule,
    VPCSSHKey,
    VPCSSHSettings,
)


@pytest.mark.parametrize(
    ("decoder", "flat", "nested", "id_attr", "expected_id"),
    [
        (
            Server.from_api,
            {"mbpkgid": 11, "fqdn": "vm.example"},
            {"metadata": {"mbpkgid": 11, "fqdn": "vm.example"}},
            "id",
            11,
        ),
        (
            DNSZone.from_api,
            {"id": 12, "name": "example.com", "type": "master"},
            {"metadata": {"id": 12, "name": "example.com", "type": "master"}},
            "id",
            12,
        ),
        (
            DNSRecord.from_api,
            {"id": 13, "domain_id": 12, "name": "www", "type": "A", "content": "192.0.2.1"},
            {"metadata": {"id": 13, "domain_id": 12, "name": "www", "type": "A", "content": "192.0.2.1"}},
            "id",
            13,
        ),
        (
            VPC.from_api,
            {"id": 14, "label": "flat"},
            {"vpcId": 14, "metadata": {"label": "nested"}},
            "vpc_id",
            14,
        ),
        (
            StorageBucket.from_api,
            {"bucketId": 15, "label": "flat", "ready": True},
            {"credentials": {"accessKey": "id"}, "metadata": {"bucketId": 15, "label": "nested", "ready": True}},
            "bucket_id",
            15,
        ),
        (
            NKECluster.from_api,
            {"clusterId": 16, "name": "flat", "status": {"cluster": "Healthy"}},
            {"metadata": {"clusterId": 16, "name": "nested", "status": {"cluster": "Healthy"}}},
            "cluster_id",
            16,
        ),
        (
            SSHKey.from_api,
            {"id": 17, "name": "laptop", "ssh_key": "ssh-ed25519 AAAA"},
            {"metadata": {"id": 17, "name": "laptop", "ssh_key": "ssh-ed25519 AAAA"}},
            "id",
            17,
        ),
        (
            TagResource.from_api,
            {"id": 18, "resource_tag_id": 1, "resource_name": "server", "identifier": 99},
            {"metadata": {"id": 18, "resource_tag_id": 1, "resource_name": "server", "identifier": 99}},
            "id",
            18,
        ),
        (
            Tag.from_api,
            {"id": 19, "name": "prod", "resources": []},
            {"metadata": {"id": 19, "name": "prod", "resources": []}},
            "id",
            19,
        ),
    ],
)
def test_decoders_accept_flat_and_nested_shapes(
    decoder: Callable[[Any], Any],
    flat: Any,
    nested: Any,
    id_attr: str,
    expected_id: int,
) -> None:
    assert getattr(decoder(flat), id_attr) == expected_id
    assert getattr(decoder(nested), id_attr) == expected_id


def test_vpc_exposes_label_under_metadata() -> None:
    vpc = VPC.from_api({"id": 14, "label": "edge", "status": "Running"})

    assert vpc.vpc_id == 14
    assert vpc.metadata["label"] == "edge"


def test_storage_bucket_exposes_label_under_metadata() -> None:
    bucket = StorageBucket.from_api({"bucketId": 15, "label": "assets", "ready": True})

    assert bucket.bucket_id == 15
    assert bucket.metadata["label"] == "assets"
    assert bucket.metadata["ready"] is True


def test_storage_type_decodes_fields() -> None:
    storage_type = StorageType.from_api({"type": "block", "name": "Block", "description": "Block storage"})

    assert storage_type.type == "block"
    assert storage_type.name == "Block"


def test_storage_object_store_exposes_label_under_metadata() -> None:
    store = StorageObjectStore.from_api({"objectStoreId": 21, "label": "media", "ready": False})

    assert store.object_store_id == 21
    assert store.metadata["label"] == "media"
    assert store.metadata["ready"] is False


def test_storage_block_namespace_exposes_label_under_metadata() -> None:
    namespace = StorageBlockNamespace.from_api(
        {"blockNamespaceId": 8, "label": "team", "ready": True}
    )

    assert namespace.block_namespace_id == 8
    assert namespace.metadata["label"] == "team"


def test_storage_block_volume_exposes_label_under_metadata() -> None:
    volume = StorageBlockVolume.from_api({"blockVolumeId": 3, "label": "data", "ready": True})

    assert volume.block_volume_id == 3
    assert volume.metadata["label"] == "data"


def test_storage_block_volume_accepts_missing_id() -> None:
    """The single-volume get endpoint can omit the id entirely; the caller
    fills it in rather than the decoder rejecting the payload."""
    volume = StorageBlockVolume.from_api({"label": "data", "ready": True})

    assert volume.block_volume_id == 0


def test_nke_worker_node_decodes_status_and_rejects_missing_id() -> None:
    node = NKEWorkerNode.from_api({"workerNodeId": 1, "clusterId": 7, "status": {"ready": True}})

    assert node.ready is True
    with pytest.raises(ValueError):
        NKEWorkerNode.from_api({"clusterId": 7, "name": "missing"})


def test_nke_addon_decodes_read_shaped_config() -> None:
    addon = NKEAddon.from_api(
        {
            "id": 1,
            "addonType": "netactuate-dns",
            "config": {"zones": [{"dnsZoneId": 4, "zone": "example.com", "mode": "primary"}]},
        }
    )

    assert addon.config["zones"][0]["zone"] == "example.com"


def test_nke_cluster_dns_zone_decodes_fields() -> None:
    zone = NKEClusterDNSZone.from_api(
        {"dnsZoneId": 4, "clusterId": 7, "zone": "example.com", "mode": "primary", "state": "Active"}
    )

    assert zone.dns_zone_id == 4
    assert zone.state == "Active"


def test_storage_location_decodes_nested_blocks() -> None:
    location = StorageLocation.from_api(
        {"location": {"id": 1, "name": "atl"}, "hardware": {"id": 2, "name": "nvme"}}
    )

    assert location.location["name"] == "atl"
    assert location.hardware["name"] == "nvme"


@pytest.mark.parametrize(
    ("decoder", "payload"),
    [
        (Server.from_api, {"fqdn": "missing"}),
        (DNSZone.from_api, {"name": "missing"}),
        (DNSRecord.from_api, {"name": "missing"}),
        (VPC.from_api, {"label": "missing"}),
        (StorageBucket.from_api, {"label": "missing"}),
        (StorageObjectStore.from_api, {"label": "missing"}),
        (StorageBlockNamespace.from_api, {"label": "missing"}),
        (NKECluster.from_api, {"name": "missing"}),
        (SSHKey.from_api, {"name": "missing"}),
        (TagResource.from_api, {"resource_name": "missing"}),
        (Tag.from_api, {"name": "missing"}),
    ],
)
def test_decoders_reject_shape_mismatch(decoder: Callable[[Any], Any], payload: Any) -> None:
    with pytest.raises(ValueError):
        decoder(payload)


def test_tag_log_does_not_require_an_id() -> None:
    log = TagLog.from_api({"action": "created", "message": "tag created"})

    assert log.id == 0
    assert log.action == "created"


def test_tag_decodes_embedded_resources() -> None:
    tag = Tag.from_api(
        {
            "id": 1,
            "name": "prod",
            "resources": [
                {"id": 5, "resource_tag_id": 1, "resource_name": "server", "identifier": 99, "created_at": ""}
            ],
        }
    )

    assert tag.resources[0].identifier == 99


def test_tag_rejects_non_list_resources() -> None:
    with pytest.raises(ValueError):
        Tag.from_api({"id": 1, "name": "prod", "resources": "not-a-list"})


def test_vpc_location_decodes_fields() -> None:
    location = VPCLocation.from_api({"id": 1, "name": "NYC", "flag": "us"})

    assert location.id == 1
    assert location.name == "NYC"
    assert location.flag == "us"


def test_vpc_location_rejects_missing_id() -> None:
    with pytest.raises(ValueError):
        VPCLocation.from_api({"name": "NYC"})


def test_vpc_backend_decodes_fields() -> None:
    backend = VPCBackend.from_api(
        {"backendHostId": 1, "name": "h1", "address": "192.0.2.10", "internalAddress": "10.0.0.10"}
    )

    assert backend.backend_host_id == 1
    assert backend.address == "192.0.2.10"
    assert backend.internal_address == "10.0.0.10"


def test_vpc_backend_template_decodes_nested_backends() -> None:
    template = VPCBackendTemplate.from_api(
        {
            "backendTemplateId": 1,
            "name": "web",
            "description": "web pool",
            "backendHosts": [{"backendHostId": 1, "address": "192.0.2.10"}],
        }
    )

    assert template.backend_template_id == 1
    assert template.backend_hosts[0].backend_host_id == 1


def test_vpc_backend_template_rejects_missing_id() -> None:
    with pytest.raises(ValueError):
        VPCBackendTemplate.from_api({"name": "web"})


def test_vpc_ssh_settings_decodes_plain_shape() -> None:
    settings = VPCSSHSettings.from_api(
        {"port": 22, "enabled": True, "keys": {"5": {"id": 5, "name": "laptop"}}}
    )

    assert settings.port == 22
    assert settings.enabled is True
    assert settings.keys["5"]["name"] == "laptop"


def test_vpc_ssh_settings_decodes_numeric_string_port() -> None:
    settings = VPCSSHSettings.from_api({"port": "2222", "enabled": False})

    assert settings.port == 2222


def test_vpc_ssh_settings_decodes_object_port() -> None:
    settings = VPCSSHSettings.from_api({"port": {"number": 2200}, "enabled": False})

    assert settings.port == 2200


def test_vpc_ssh_settings_decodes_null_port() -> None:
    settings = VPCSSHSettings.from_api({"port": None, "enabled": False})

    assert settings.port is None


def test_vpc_ssh_settings_decodes_wrapped_keys() -> None:
    settings = VPCSSHSettings.from_api(
        {"port": 22, "enabled": True, "keys": {"data": [{"id": 9, "name": "office"}]}}
    )

    assert settings.keys["9"]["name"] == "office"


def test_vpc_ssh_key_effective_id_prefers_id() -> None:
    key = VPCSSHKey.from_api({"id": 5, "sshKeyId": 9, "name": "laptop"})

    assert key.effective_id == 5


def test_vpc_ssh_key_effective_id_falls_back_to_ssh_key_id() -> None:
    key = VPCSSHKey.from_api({"id": 0, "sshKeyId": 9, "name": "laptop"})

    assert key.effective_id == 9


def test_vpc_ssh_key_enabled_reflects_dates() -> None:
    enabled_key = VPCSSHKey.from_api(
        {"id": 5, "dates": {"created": "2026-01-01", "enabled": "2026-01-02"}}
    )
    disabled_key = VPCSSHKey.from_api({"id": 6, "dates": {"created": "2026-01-01", "enabled": None}})
    no_dates_key = VPCSSHKey.from_api({"id": 7})

    assert enabled_key.enabled is True
    assert disabled_key.enabled is False
    assert no_dates_key.enabled is False


def test_vpc_floating_ip_decodes_fields() -> None:
    fip = VPCFloatingIP.from_api(
        {"floatingIpId": 9, "address": "203.0.113.5", "ipVersion": 4, "ptr": "host.example.com", "isPrimary": True}
    )

    assert fip.floating_ip_id == 9
    assert fip.address == "203.0.113.5"
    assert fip.is_primary is True


def test_vpc_firewall_rule_decodes_port() -> None:
    rule = VPCFirewallRule.from_api(
        {
            "firewallRuleId": 4,
            "ipVersion": 4,
            "direction": "inbound",
            "protocol": "tcp",
            "port": {"start": 80, "end": 80},
        }
    )

    assert rule.firewall_rule_id == 4
    assert rule.port == {"start": 80, "end": 80}


def test_vpc_firewall_rule_rejects_non_object_port() -> None:
    with pytest.raises(ValueError):
        VPCFirewallRule.from_api({"firewallRuleId": 4, "port": "not-an-object"})


def test_vpc_snat_rule_decodes_match_and_translation() -> None:
    rule = VPCSNATRule.from_api(
        {
            "snatRuleId": 5,
            "ipVersion": 4,
            "match": {"internalCidr": "10.0.0.0/24"},
            "translation": {"address": {"start": "203.0.113.1", "end": "203.0.113.1"}},
        }
    )

    assert rule.snat_rule_id == 5
    assert rule.match == {"internalCidr": "10.0.0.0/24"}
    assert rule.translation["address"]["start"] == "203.0.113.1"


def test_vpc_dnat_rule_decodes_match_and_translation() -> None:
    rule = VPCDNATRule.from_api(
        {
            "dnatRuleId": 6,
            "ipVersion": 4,
            "match": {"address": "192.0.2.1"},
            "translation": {"address": "192.0.2.20"},
        }
    )

    assert rule.dnat_rule_id == 6
    assert rule.match == {"address": "192.0.2.1"}
    assert rule.translation == {"address": "192.0.2.20"}
