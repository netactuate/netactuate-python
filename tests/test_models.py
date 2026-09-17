from __future__ import annotations

from typing import Any, Callable

import pytest

from netactuate.models import DNSRecord, DNSZone, NKECluster, Server, StorageBucket, VPC


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


@pytest.mark.parametrize(
    ("decoder", "payload"),
    [
        (Server.from_api, {"fqdn": "missing"}),
        (DNSZone.from_api, {"name": "missing"}),
        (DNSRecord.from_api, {"name": "missing"}),
        (VPC.from_api, {"label": "missing"}),
        (StorageBucket.from_api, {"label": "missing"}),
        (NKECluster.from_api, {"name": "missing"}),
    ],
)
def test_decoders_reject_shape_mismatch(decoder: Callable[[Any], Any], payload: Any) -> None:
    with pytest.raises(ValueError):
        decoder(payload)
