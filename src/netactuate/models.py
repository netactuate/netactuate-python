"""Data models and decoders for NetActuate API resources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional


Payload = Mapping[str, Any]


def _require_mapping(value: Any, model: str) -> Payload:
    if not isinstance(value, Mapping):
        raise ValueError(f"{model} payload must be an object")
    return value


def _metadata_payload(value: Payload, model: str) -> Dict[str, Any]:
    metadata = value.get("metadata")
    if metadata is None:
        return dict(value)
    if not isinstance(metadata, Mapping):
        raise ValueError(f"{model} metadata must be an object")
    merged = dict(value)
    merged.update(metadata)
    return merged


def _metadata_from(value: Payload, keys: tuple[str, ...]) -> Dict[str, Any]:
    metadata = value.get("metadata")
    if metadata is not None:
        return dict(metadata)
    return {key: value[key] for key in keys if key in value}


def _int_value(value: Any) -> int:
    if value is None or value == "":
        return 0
    return int(value)


@dataclass
class Server:
    """Cloud server returned by vAPI2."""

    id: int
    name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Server":
        """Decode a server from flat or metadata-nested API payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "server"), "server")
        server_id = _int_value(value.get("mbpkgid", value.get("id")))
        name = str(value.get("fqdn", value.get("name", "")))
        if server_id == 0:
            raise ValueError("server payload is missing mbpkgid")
        return cls(id=server_id, name=name, raw=dict(payload))


@dataclass
class DNSZone:
    """DNS zone returned by vAPI2."""

    id: int
    name: str
    type: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DNSZone":
        """Decode a DNS zone from flat or metadata-nested API payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "DNS zone"), "DNS zone")
        zone_id = _int_value(value.get("id", value.get("zoneId")))
        name = str(value.get("name", ""))
        if zone_id == 0:
            raise ValueError("DNS zone payload is missing id")
        return cls(id=zone_id, name=name, type=str(value.get("type", "")), raw=dict(payload))


@dataclass
class DNSRecord:
    """DNS record returned by vAPI2."""

    id: int
    zone_id: int
    name: str
    type: str
    content: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DNSRecord":
        """Decode a DNS record from flat or metadata-nested API payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "DNS record"), "DNS record")
        record_id = _int_value(value.get("id", value.get("recordId")))
        zone_id = _int_value(value.get("domain_id", value.get("zoneId")))
        if record_id == 0:
            raise ValueError("DNS record payload is missing id")
        return cls(
            id=record_id,
            zone_id=zone_id,
            name=str(value.get("name", "")),
            type=str(value.get("type", "")),
            content=str(value.get("content", value.get("record_content", ""))),
            raw=dict(payload),
        )


@dataclass
class VPC:
    """VPC returned by vAPI3."""

    vpc_id: int
    metadata: Dict[str, Any]
    location: Dict[str, Any]
    bastion: Dict[str, Any]
    floating_ips: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPC":
        """Decode a VPC from flat list row or metadata-nested get payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        original = _require_mapping(payload, "VPC")
        value = _metadata_payload(original, "VPC")
        vpc_id = _int_value(value.get("vpcId", value.get("id")))
        if vpc_id == 0:
            raise ValueError("VPC payload is missing vpcId")
        metadata = _metadata_from(
            original,
            ("createdOn", "label", "description", "readyOn", "status", "uptimeSeconds"),
        )
        location = value.get("location", {})
        bastion = value.get("bastion", {})
        floating_ips = value.get("floatingIps", value.get("floating_ips", {}))
        return cls(
            vpc_id=vpc_id,
            metadata=metadata,
            location=dict(location) if isinstance(location, Mapping) else {},
            bastion=dict(bastion) if isinstance(bastion, Mapping) else {},
            floating_ips=dict(floating_ips) if isinstance(floating_ips, Mapping) else {},
            raw=dict(original),
        )


@dataclass
class StorageBucket:
    """Object storage bucket returned by vAPI3."""

    bucket_id: int
    metadata: Dict[str, Any]
    credentials: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StorageBucket":
        """Decode a storage bucket from flat list row or metadata-nested get payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        original = _require_mapping(payload, "storage bucket")
        value = _metadata_payload(original, "storage bucket")
        bucket_id = _int_value(value.get("bucketId", value.get("id")))
        if bucket_id == 0:
            raise ValueError("storage bucket payload is missing bucketId")
        credentials = original.get("credentials")
        if credentials is not None and not isinstance(credentials, Mapping):
            raise ValueError("storage bucket credentials must be an object")
        metadata = _metadata_from(
            original,
            ("bucketId", "label", "ready", "private", "assignedOn", "location", "capacity", "hardwareClass"),
        )
        return cls(
            bucket_id=bucket_id,
            metadata=metadata,
            credentials=dict(credentials) if credentials is not None else None,
            raw=dict(original),
        )


@dataclass
class NKECluster:
    """NKE cluster returned by vAPI3."""

    cluster_id: int
    name: str
    contract_id: int
    vpc_id: int
    replicas: int
    do_autoscaling: int
    is_dual_stack: bool
    has_high_availability: bool
    status: Dict[str, Any]
    version: Dict[str, Any]
    location: Dict[str, Any]
    package: Dict[str, Any]
    nodes: Dict[str, Any]
    tags: list[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NKECluster":
        """Decode an NKE cluster from flat list row or metadata-nested get payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        original = _require_mapping(payload, "NKE cluster")
        value = _metadata_payload(original, "NKE cluster")
        cluster_id = _int_value(value.get("clusterId", value.get("id")))
        if cluster_id == 0:
            raise ValueError("NKE cluster payload is missing clusterId")
        status = value.get("status", {})
        if status is not None and not isinstance(status, Mapping):
            raise ValueError("NKE cluster status must be an object")
        version = value.get("version", {})
        location = value.get("location", {})
        package = value.get("package", {})
        nodes = value.get("nodes", {})
        tags = value.get("tags", [])
        if tags is not None and not isinstance(tags, list):
            raise ValueError("NKE cluster tags must be a list")
        return cls(
            cluster_id=cluster_id,
            name=str(value.get("name", "")),
            contract_id=_int_value(value.get("contractId")),
            vpc_id=_int_value(value.get("vpcId")),
            replicas=_int_value(value.get("replicas")),
            do_autoscaling=_int_value(value.get("doAutoscaling")),
            is_dual_stack=bool(value.get("isDualStack", False)),
            has_high_availability=bool(value.get("hasHighAvailabity", False)),
            status=dict(status or {}),
            version=dict(version) if isinstance(version, Mapping) else {},
            location=dict(location) if isinstance(location, Mapping) else {},
            package=dict(package) if isinstance(package, Mapping) else {},
            nodes=dict(nodes) if isinstance(nodes, Mapping) else {},
            tags=[dict(tag) for tag in tags if isinstance(tag, Mapping)],
            raw=dict(original),
        )
