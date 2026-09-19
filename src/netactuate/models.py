"""Data models and decoders for NetActuate API resources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


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


def _string_value(value: Any) -> str:
    """Coerce a value that may be absent, a string or a number to a string.

    Mirrors gona's unmarshalStringField, which accepts either JSON shape for
    fields such as a change log entry's id.

    Parameters:
        value: Raw field value from a decoded JSON payload.
    """
    if value is None:
        return ""
    return str(value)


def _bool_value(value: Any) -> bool:
    """Coerce a vAPI2 flag to a bool, accepting bool, numeric and string forms.

    The firewall endpoints answer boolean flags as a JSON bool, a 0/1 number
    or a "0"/"1"/"true"/"false" string depending on the field and account, so
    every form is normalized here rather than trusted to be one shape.

    Parameters:
        value: Raw flag value from a decoded JSON payload.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value in ("1", "true")
    return False


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
class VPCLocation:
    """VPC-capable location returned by vAPI3."""

    id: int
    name: str
    flag: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCLocation":
        """Decode a VPC location from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one location row.
        """
        value = _require_mapping(payload, "VPC location")
        location_id = _int_value(value.get("id"))
        if location_id == 0:
            raise ValueError("VPC location payload is missing id")
        return cls(
            id=location_id,
            name=str(value.get("name", "")),
            flag=str(value.get("flag", "")),
            raw=dict(payload),
        )


@dataclass
class VPCIPReservations:
    """Gateway, interface and VM IP reservations for a VPC, returned by vAPI3.

    The API describes each section's shape inconsistently across accounts, so
    each field is kept as whatever JSON value arrived rather than forced into
    a fixed structure.
    """

    gateways: Any
    interfaces: Any
    vms: Any
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCIPReservations":
        """Decode VPC IP reservations from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object returned by the IP reservations endpoint.
        """
        value = _require_mapping(payload, "VPC IP reservations")
        return cls(
            gateways=value.get("gateways"),
            interfaces=value.get("interfaces"),
            vms=value.get("vms"),
            raw=dict(value),
        )


def _decode_vpc_ssh_port(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("VPC SSH port must not be a boolean")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        return int(raw)
    if isinstance(raw, Mapping):
        for key in ("port", "value", "number"):
            if key in raw:
                return _decode_vpc_ssh_port(raw[key])
        raise ValueError("VPC SSH port object has no port value")
    raise ValueError("VPC SSH port has an unrecognized shape")


def _decode_vpc_ssh_keys(raw: Any) -> Dict[str, Dict[str, Any]]:
    if raw is None:
        return {}
    if isinstance(raw, Mapping) and isinstance(raw.get("data"), list):
        keys: Dict[str, Dict[str, Any]] = {}
        for row in raw["data"]:
            if not isinstance(row, Mapping):
                continue
            key_id = row.get("id", row.get("sshKeyId"))
            keys[str(key_id)] = dict(row)
        return keys
    if isinstance(raw, Mapping):
        return {str(key): dict(value) for key, value in raw.items() if isinstance(value, Mapping)}
    raise ValueError("VPC SSH keys have an unrecognized shape")


@dataclass
class VPCSSHSettings:
    """Bastion SSH settings for a VPC, returned by vAPI3.

    The port arrives as a number, a numeric string or an object carrying the
    number under a port, value or number key, and keys arrives either as a
    map of key id to key or wrapped in the list envelope used elsewhere in
    this API. Both shapes are normalized here.
    """

    port: Optional[int]
    enabled: bool
    keys: Dict[str, Dict[str, Any]]
    bastion: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCSSHSettings":
        """Decode VPC SSH settings from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object returned by the VPC SSH settings endpoint.
        """
        value = _require_mapping(payload, "VPC SSH settings")
        bastion = value.get("bastion")
        if bastion is not None and not isinstance(bastion, Mapping):
            raise ValueError("VPC SSH bastion must be an object")
        return cls(
            port=_decode_vpc_ssh_port(value.get("port")),
            enabled=bool(value.get("enabled", False)),
            keys=_decode_vpc_ssh_keys(value.get("keys")),
            bastion=dict(bastion) if bastion is not None else None,
            raw=dict(value),
        )


@dataclass
class VPCSSHKey:
    """An SSH key enabled on a VPC's bastion, returned by vAPI3.

    The identifier arrives as `id` on some accounts and `sshKeyId` on
    others; `effective_id` resolves both to the value a caller should match
    against, mirroring the fallback gona applies.
    """

    id: int
    ssh_key_id: int
    name: str
    fingerprint: str
    public_key: str
    dates: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @property
    def effective_id(self) -> int:
        """Return `id` when set, falling back to `ssh_key_id`."""
        return self.id or self.ssh_key_id

    @property
    def enabled(self) -> bool:
        """Return whether the key has an enabled timestamp recorded."""
        return self.dates is not None and self.dates.get("enabled") is not None

    @classmethod
    def from_api(cls, payload: Any) -> "VPCSSHKey":
        """Decode a VPC SSH key from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one SSH key row.
        """
        value = _require_mapping(payload, "VPC SSH key")
        dates = value.get("dates")
        if dates is not None and not isinstance(dates, Mapping):
            raise ValueError("VPC SSH key dates must be an object")
        return cls(
            id=_int_value(value.get("id")),
            ssh_key_id=_int_value(value.get("sshKeyId")),
            name=str(value.get("name", "")),
            fingerprint=str(value.get("fingerprint", "")),
            public_key=str(value.get("publicKey", "")),
            dates=dict(dates) if dates is not None else None,
            raw=dict(value),
        )


@dataclass
class VPCFloatingIP:
    """A floating IP attached to a VPC, returned by vAPI3."""

    floating_ip_id: int
    address: str
    ip_version: int
    ptr: str
    is_primary: bool
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCFloatingIP":
        """Decode a VPC floating IP from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one floating IP row.
        """
        value = _require_mapping(payload, "VPC floating IP")
        return cls(
            floating_ip_id=_int_value(value.get("floatingIpId")),
            address=str(value.get("address", "")),
            ip_version=_int_value(value.get("ipVersion")),
            ptr=str(value.get("ptr", "")),
            is_primary=bool(value.get("isPrimary", False)),
            raw=dict(value),
        )


@dataclass
class VPCFirewallRule:
    """A gateway firewall rule for a VPC, returned by vAPI3."""

    firewall_rule_id: int
    ip_version: int
    direction: str
    protocol: str
    description: str
    network: str
    address: str
    prefix_length: int
    port: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCFirewallRule":
        """Decode a VPC firewall rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single response.
        """
        value = _require_mapping(payload, "VPC firewall rule")
        port = value.get("port")
        if port is not None and not isinstance(port, Mapping):
            raise ValueError("VPC firewall rule port must be an object")
        return cls(
            firewall_rule_id=_int_value(value.get("firewallRuleId")),
            ip_version=_int_value(value.get("ipVersion")),
            direction=str(value.get("direction", "")),
            protocol=str(value.get("protocol", "")),
            description=str(value.get("description", "")),
            network=str(value.get("network", "")),
            address=str(value.get("address", "")),
            prefix_length=_int_value(value.get("prefixLength")),
            port=dict(port) if port is not None else None,
            raw=dict(value),
        )


@dataclass
class VPCSNATRule:
    """A gateway SNAT rule for a VPC, returned by vAPI3."""

    snat_rule_id: int
    ip_version: int
    protocol: str
    description: str
    match: Optional[Dict[str, Any]]
    translation: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCSNATRule":
        """Decode a VPC SNAT rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single response.
        """
        value = _require_mapping(payload, "VPC SNAT rule")
        match = value.get("match")
        if match is not None and not isinstance(match, Mapping):
            raise ValueError("VPC SNAT rule match must be an object")
        translation = value.get("translation")
        if translation is not None and not isinstance(translation, Mapping):
            raise ValueError("VPC SNAT rule translation must be an object")
        return cls(
            snat_rule_id=_int_value(value.get("snatRuleId")),
            ip_version=_int_value(value.get("ipVersion")),
            protocol=str(value.get("protocol", "")),
            description=str(value.get("description", "")),
            match=dict(match) if match is not None else None,
            translation=dict(translation) if translation is not None else None,
            raw=dict(value),
        )


@dataclass
class VPCDNATRule:
    """A gateway DNAT rule for a VPC, returned by vAPI3."""

    dnat_rule_id: int
    ip_version: int
    protocol: str
    description: str
    match: Optional[Dict[str, Any]]
    translation: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCDNATRule":
        """Decode a VPC DNAT rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single response.
        """
        value = _require_mapping(payload, "VPC DNAT rule")
        match = value.get("match")
        if match is not None and not isinstance(match, Mapping):
            raise ValueError("VPC DNAT rule match must be an object")
        translation = value.get("translation")
        if translation is not None and not isinstance(translation, Mapping):
            raise ValueError("VPC DNAT rule translation must be an object")
        return cls(
            dnat_rule_id=_int_value(value.get("dnatRuleId")),
            ip_version=_int_value(value.get("ipVersion")),
            protocol=str(value.get("protocol", "")),
            description=str(value.get("description", "")),
            match=dict(match) if match is not None else None,
            translation=dict(translation) if translation is not None else None,
            raw=dict(value),
        )


@dataclass
class VPCBackend:
    """A single backend host in a VPC backend template, returned by vAPI3."""

    backend_host_id: int
    name: str
    address: str
    internal_address: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCBackend":
        """Decode a VPC backend host from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one backend host row.
        """
        value = _require_mapping(payload, "VPC backend")
        return cls(
            backend_host_id=_int_value(value.get("backendHostId")),
            name=str(value.get("name", "")),
            address=str(value.get("address", "")),
            internal_address=str(value.get("internalAddress", "")),
            raw=dict(value),
        )


@dataclass
class VPCBackendTemplate:
    """A VPC backend template and its backend hosts, returned by vAPI3."""

    backend_template_id: int
    name: str
    description: str
    backend_hosts: list[VPCBackend]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCBackendTemplate":
        """Decode a VPC backend template from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "VPC backend template")
        template_id = _int_value(value.get("backendTemplateId"))
        if template_id == 0:
            raise ValueError("VPC backend template payload is missing backendTemplateId")
        hosts = value.get("backendHosts") or []
        if not isinstance(hosts, list):
            raise ValueError("VPC backend template backendHosts must be a list")
        return cls(
            backend_template_id=template_id,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            backend_hosts=[VPCBackend.from_api(row) for row in hosts if isinstance(row, Mapping)],
            raw=dict(value),
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
class StorageType:
    """Storage type entry returned by vAPI3."""

    type: str
    name: str
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StorageType":
        """Decode a storage type from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one storage type row.
        """
        value = _require_mapping(payload, "storage type")
        return cls(
            type=str(value.get("type", "")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            raw=dict(value),
        )


@dataclass
class StorageObjectStore:
    """Object storage store returned by vAPI3."""

    object_store_id: int
    metadata: Dict[str, Any]
    credentials: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StorageObjectStore":
        """Decode an object store from flat list row or metadata-nested get payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        original = _require_mapping(payload, "storage object store")
        value = _metadata_payload(original, "storage object store")
        object_store_id = _int_value(value.get("objectStoreId", value.get("id")))
        if object_store_id == 0:
            raise ValueError("storage object store payload is missing objectStoreId")
        credentials = original.get("credentials")
        if credentials is not None and not isinstance(credentials, Mapping):
            raise ValueError("storage object store credentials must be an object")
        metadata = _metadata_from(
            original,
            ("objectStoreId", "label", "ready", "assignedOn", "location", "capacity", "hardwareClass"),
        )
        return cls(
            object_store_id=object_store_id,
            metadata=metadata,
            credentials=dict(credentials) if credentials is not None else None,
            raw=dict(original),
        )


@dataclass
class StorageBlockNamespace:
    """Block storage namespace returned by vAPI3."""

    block_namespace_id: int
    metadata: Dict[str, Any]
    credentials: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StorageBlockNamespace":
        """Decode a block namespace from flat list row or metadata-nested get payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        original = _require_mapping(payload, "storage block namespace")
        value = _metadata_payload(original, "storage block namespace")
        block_namespace_id = _int_value(value.get("blockNamespaceId", value.get("id")))
        if block_namespace_id == 0:
            raise ValueError("storage block namespace payload is missing blockNamespaceId")
        credentials = original.get("credentials")
        if credentials is not None and not isinstance(credentials, Mapping):
            raise ValueError("storage block namespace credentials must be an object")
        metadata = _metadata_from(
            original,
            ("blockNamespaceId", "label", "ready", "assignedOn", "location", "capacity", "hardwareClass"),
        )
        return cls(
            block_namespace_id=block_namespace_id,
            metadata=metadata,
            credentials=dict(credentials) if credentials is not None else None,
            raw=dict(original),
        )


@dataclass
class StorageBlockVolume:
    """Block storage volume returned by vAPI3.

    The single-volume get endpoint on this API can answer with the id
    missing from its own payload; callers that hit that case fill in the id
    they requested rather than trust a decoded zero. See
    `V3Client.get_storage_block_volume`.
    """

    block_volume_id: int
    metadata: Dict[str, Any]
    credentials: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StorageBlockVolume":
        """Decode a block volume from flat list row or metadata-nested get payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        original = _require_mapping(payload, "storage block volume")
        value = _metadata_payload(original, "storage block volume")
        block_volume_id = _int_value(value.get("blockVolumeId", value.get("id")))
        credentials = original.get("credentials")
        if credentials is not None and not isinstance(credentials, Mapping):
            raise ValueError("storage block volume credentials must be an object")
        metadata = _metadata_from(
            original,
            ("blockVolumeId", "label", "ready", "assignedOn", "location", "capacity", "hardwareClass"),
        )
        return cls(
            block_volume_id=block_volume_id,
            metadata=metadata,
            credentials=dict(credentials) if credentials is not None else None,
            raw=dict(original),
        )


@dataclass
class StorageLocation:
    """A location where storage resources can be created, returned by vAPI3."""

    location: Dict[str, Any]
    hardware: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StorageLocation":
        """Decode a storage location from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one storage location row.
        """
        value = _require_mapping(payload, "storage location")
        location = value.get("location")
        if location is not None and not isinstance(location, Mapping):
            raise ValueError("storage location location must be an object")
        hardware = value.get("hardware")
        if hardware is not None and not isinstance(hardware, Mapping):
            raise ValueError("storage location hardware must be an object")
        return cls(
            location=dict(location) if location is not None else {},
            hardware=dict(hardware) if hardware is not None else {},
            raw=dict(value),
        )


@dataclass
class SSHKey:
    """SSH key returned by vAPI2."""

    id: int
    name: str
    key: str
    fingerprint: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "SSHKey":
        """Decode an SSH key from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "SSH key"), "SSH key")
        key_id = _int_value(value.get("id"))
        if key_id == 0:
            raise ValueError("SSH key payload is missing id")
        return cls(
            id=key_id,
            name=str(value.get("name", "")),
            key=str(value.get("ssh_key", "")),
            fingerprint=str(value.get("fingerprint", "")),
            raw=dict(payload),
        )


@dataclass
class TagResource:
    """A single tag-to-resource assignment, embedded in Tag.resources."""

    id: int
    resource_tag_id: int
    resource_name: str
    identifier: int
    created_at: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TagResource":
        """Decode a tag resource assignment from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one assignment row.
        """
        value = _metadata_payload(_require_mapping(payload, "tag resource"), "tag resource")
        row_id = _int_value(value.get("id"))
        if row_id == 0:
            raise ValueError("tag resource payload is missing id")
        return cls(
            id=row_id,
            resource_tag_id=_int_value(value.get("resource_tag_id")),
            resource_name=str(value.get("resource_name", "")),
            identifier=_int_value(value.get("identifier")),
            created_at=str(value.get("created_at", "")),
            raw=dict(payload),
        )


@dataclass
class TagLog:
    """A log entry for a tag.

    All fields are optional in the API schema, so this decoder does not
    require an id: the full payload is always kept on `raw`.
    """

    id: int
    tag_id: int
    action: str
    message: str
    created_at: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TagLog":
        """Decode a tag log entry from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one log row.
        """
        value = _metadata_payload(_require_mapping(payload, "tag log"), "tag log")
        return cls(
            id=_int_value(value.get("id")),
            tag_id=_int_value(value.get("tag_id")),
            action=str(value.get("action", "")),
            message=str(value.get("message", "")),
            created_at=str(value.get("created_at", "")),
            raw=dict(payload),
        )


@dataclass
class Tag:
    """Tag returned by vAPI2, with its resource assignments embedded."""

    id: int
    name: str
    description: str
    icon: str
    color: str
    is_default: bool
    is_favorite: bool
    is_locked: bool
    show_dashboard: bool
    created_at: str
    mb_id: int
    resources_count: int
    resources: list[TagResource]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Tag":
        """Decode a tag from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "tag"), "tag")
        tag_id = _int_value(value.get("id"))
        if tag_id == 0:
            raise ValueError("tag payload is missing id")
        resources = value.get("resources") or []
        if not isinstance(resources, list):
            raise ValueError("tag resources must be a list")
        return cls(
            id=tag_id,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            icon=str(value.get("icon", "")),
            color=str(value.get("color", "")),
            is_default=bool(_int_value(value.get("is_default"))),
            is_favorite=bool(_int_value(value.get("is_favorite"))),
            is_locked=bool(_int_value(value.get("is_locked"))),
            show_dashboard=bool(_int_value(value.get("show_dashboard"))),
            created_at=str(value.get("created_at", "")),
            mb_id=_int_value(value.get("mb_id")),
            resources_count=_int_value(value.get("resources_count")),
            resources=[TagResource.from_api(row) for row in resources if isinstance(row, Mapping)],
            raw=dict(payload),
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


@dataclass
class NKEAccessURLs:
    """Secure access URLs created for an NKE cluster, returned by vAPI3."""

    api: str
    prometheus: str
    kubernetes_dashboard: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NKEAccessURLs":
        """Decode an NKE cluster access URLs response.

        Parameters:
            payload: Decoded JSON object returned by the create-access-urls endpoint.
        """
        value = _require_mapping(payload, "NKE access URLs")
        return cls(
            api=str(value.get("api", "")),
            prometheus=str(value.get("prometheus", "")),
            kubernetes_dashboard=str(value.get("kubernetesDashboard", "")),
            raw=dict(value),
        )


@dataclass
class NKEWorkerNode:
    """A worker node belonging to an NKE cluster, returned by vAPI3."""

    worker_node_id: int
    cluster_id: int
    name: str
    mbpkg_id: int
    location_id: int
    ready: bool
    package: Dict[str, Any]
    location: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NKEWorkerNode":
        """Decode an NKE worker node.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "NKE worker node")
        worker_node_id = _int_value(value.get("workerNodeId"))
        if worker_node_id == 0:
            raise ValueError("NKE worker node payload is missing workerNodeId")
        status = value.get("status", {})
        if status is not None and not isinstance(status, Mapping):
            raise ValueError("NKE worker node status must be an object")
        package = value.get("package")
        location = value.get("location")
        return cls(
            worker_node_id=worker_node_id,
            cluster_id=_int_value(value.get("clusterId")),
            name=str(value.get("name", "")),
            mbpkg_id=_int_value(value.get("mbpkgid")),
            location_id=_int_value(value.get("locationId")),
            ready=bool((status or {}).get("ready", False)),
            package=dict(package) if isinstance(package, Mapping) else {},
            location=dict(location) if isinstance(location, Mapping) else {},
            raw=dict(value),
        )


@dataclass
class NKELogEntry:
    """One entry in an NKE cluster's log, returned by vAPI3."""

    recorded_on: str
    message: str

    @classmethod
    def from_api(cls, payload: Any) -> "NKELogEntry":
        """Decode an NKE cluster log entry.

        Parameters:
            payload: Decoded JSON object for one row of the cluster logs list.
        """
        value = _require_mapping(payload, "NKE cluster log entry")
        return cls(
            recorded_on=str(value.get("recordedOn", "")),
            message=str(value.get("message", "")),
        )


@dataclass
class NKEAddonCatalogEntry:
    """An addon type installable on NKE clusters, returned by vAPI3."""

    addon_id: int
    addon_type: str
    version: str
    channel: str
    display_name: str
    min_kubernetes_version: str
    max_kubernetes_version: str
    is_default: bool
    requires_vpc: bool
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NKEAddonCatalogEntry":
        """Decode an NKE addon catalog entry.

        Parameters:
            payload: Decoded JSON object for one row of the addon catalog list.
        """
        value = _require_mapping(payload, "NKE addon catalog entry")
        return cls(
            addon_id=_int_value(value.get("addonId")),
            addon_type=str(value.get("addonType", "")),
            version=str(value.get("version", "")),
            channel=str(value.get("channel", "")),
            display_name=str(value.get("displayName", "")),
            min_kubernetes_version=str(value.get("minKubernetesVersion", "")),
            max_kubernetes_version=str(value.get("maxKubernetesVersion", "")),
            is_default=bool(value.get("isDefault", False)),
            requires_vpc=bool(value.get("requiresVpc", False)),
            raw=dict(value),
        )


@dataclass
class NKEAddon:
    """An addon installed on an NKE cluster, returned by vAPI3.

    `config` carries whatever shape the addon type reports, for example a
    `zones` list for the DNS addon or an `integrations` list for the
    storage addon, which is not the shape either addon was configured with.
    """

    id: int
    addon_id: int
    cluster_id: int
    addon_type: str
    version: str
    channel: str
    display_name: str
    state: str
    update_available: bool
    catalog: Dict[str, Any]
    health: Dict[str, Any]
    workload_health: Dict[str, Any]
    config: Dict[str, Any]
    timestamps: Dict[str, Any]
    failure_reason: str
    install_retry_on: str
    install_failure_ct: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NKEAddon":
        """Decode an NKE cluster addon.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "NKE addon")
        catalog = value.get("catalog")
        health = value.get("health")
        workload_health = value.get("workloadHealth")
        config = value.get("config")
        timestamps = value.get("timestamps")
        return cls(
            id=_int_value(value.get("id")),
            addon_id=_int_value(value.get("addonId")),
            cluster_id=_int_value(value.get("clusterId")),
            addon_type=str(value.get("addonType", "")),
            version=str(value.get("version", "")),
            channel=str(value.get("channel", "")),
            display_name=str(value.get("displayName", "")),
            state=str(value.get("state", "")),
            update_available=bool(value.get("updateAvailable", False)),
            catalog=dict(catalog) if isinstance(catalog, Mapping) else {},
            health=dict(health) if isinstance(health, Mapping) else {},
            workload_health=dict(workload_health) if isinstance(workload_health, Mapping) else {},
            config=dict(config) if isinstance(config, Mapping) else {},
            timestamps=dict(timestamps) if isinstance(timestamps, Mapping) else {},
            failure_reason=str(value.get("failureReason", "")),
            install_retry_on=str(value.get("installRetryOn", "")),
            install_failure_ct=_int_value(value.get("installFailureCt")),
            raw=dict(value),
        )


@dataclass
class NKEClusterDNSZone:
    """A DNS zone managed by an NKE cluster's DNS addon, returned by vAPI3."""

    dns_zone_id: int
    cluster_id: int
    zone: str
    mode: str
    failure_reason: str
    state: str
    health: Dict[str, Any]
    timestamps: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NKEClusterDNSZone":
        """Decode an NKE cluster DNS zone.

        Parameters:
            payload: Decoded JSON object for one row of the cluster DNS zones list.
        """
        value = _require_mapping(payload, "NKE cluster DNS zone")
        health = value.get("health")
        timestamps = value.get("timestamps")
        return cls(
            dns_zone_id=_int_value(value.get("dnsZoneId")),
            cluster_id=_int_value(value.get("clusterId")),
            zone=str(value.get("zone", "")),
            mode=str(value.get("mode", "")),
            failure_reason=str(value.get("failureReason", "")),
            state=str(value.get("state", "")),
            health=dict(health) if isinstance(health, Mapping) else {},
            timestamps=dict(timestamps) if isinstance(timestamps, Mapping) else {},
            raw=dict(value),
        )


@dataclass
class FirewallSet:
    """Cloud firewall set returned by vAPI2."""

    id: int
    name: str
    description: str
    enabled: bool
    is_draft: bool
    draft_firewall_set_id: Optional[int]
    created: str
    last_updated: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "FirewallSet":
        """Decode a firewall set from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "firewall set"), "firewall set")
        set_id = _int_value(value.get("id"))
        if set_id == 0:
            raise ValueError("firewall set payload is missing id")
        draft_id = value.get("draft_firewall_set_id")
        return cls(
            id=set_id,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            enabled=_bool_value(value.get("enabled")),
            is_draft=_bool_value(value.get("is_draft")),
            draft_firewall_set_id=_int_value(draft_id) if draft_id not in (None, "") else None,
            created=str(value.get("created", "")),
            last_updated=str(value.get("last_updated", "")),
            raw=dict(payload),
        )


@dataclass
class FirewallRule:
    """Cloud firewall rule returned by vAPI2.

    `match_criteria` is kept as the decoded JSON object rather than a typed
    model, mirroring how nested request and response blocks are handled
    elsewhere in this SDK (see `VPCFirewallRule.port`).
    """

    id: int
    firewall_set_id: int
    ip_version: str
    direction: str
    action: str
    enabled: bool
    match_criteria: Optional[Dict[str, Any]]
    admin_comment: str
    rule_priority: int
    created: str
    last_updated: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "FirewallRule":
        """Decode a firewall rule from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "firewall rule"), "firewall rule")
        rule_id = _int_value(value.get("id"))
        if rule_id == 0:
            raise ValueError("firewall rule payload is missing id")
        match_criteria = value.get("match_criteria")
        if match_criteria is not None and not isinstance(match_criteria, Mapping):
            raise ValueError("firewall rule match_criteria must be an object")
        return cls(
            id=rule_id,
            firewall_set_id=_int_value(value.get("firewall_set_id")),
            ip_version=str(value.get("ip_version", "")),
            direction=str(value.get("direction", "")),
            action=str(value.get("action", "")),
            enabled=_bool_value(value.get("enabled")),
            match_criteria=dict(match_criteria) if match_criteria is not None else None,
            admin_comment=str(value.get("admin_comment", "")),
            rule_priority=_int_value(value.get("rule_priority")),
            created=str(value.get("created", "")),
            last_updated=str(value.get("last_updated", "")),
            raw=dict(payload),
        )


@dataclass
class FirewallExternalIPSet:
    """External IP set usable in firewall match criteria, returned by vAPI2."""

    id: int
    name: str
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "FirewallExternalIPSet":
        """Decode a firewall external IP set from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "firewall external IP set")
        set_id = _int_value(value.get("id"))
        if set_id == 0:
            raise ValueError("firewall external IP set payload is missing id")
        return cls(
            id=set_id,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            raw=dict(value),
        )


@dataclass
class FirewallManageEnabled:
    """Whether cloud firewall management is available for the account."""

    enabled: bool
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "FirewallManageEnabled":
        """Decode the firewall manage-enabled flag from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the manage-enabled endpoint.
        """
        value = _require_mapping(payload, "firewall manage enabled")
        return cls(enabled=_bool_value(value.get("enabled")), raw=dict(value))


@dataclass
class ProvisionedLocation:
    """A location where a VLAN is provisioned, or pending provisioning."""

    provisioned: bool
    name: str
    location_id: int
    flag: str
    iata_code: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ProvisionedLocation":
        """Decode a VLAN provisioned location from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one provisioned location row.
        """
        value = _require_mapping(payload, "VLAN provisioned location")
        return cls(
            provisioned=bool(value.get("provisioned", False)),
            name=str(value.get("name", "")),
            location_id=_int_value(value.get("location_id")),
            flag=str(value.get("flag", "")),
            iata_code=str(value.get("iata_code", "")),
            raw=dict(value),
        )


@dataclass
class VLAN:
    """Customer VLAN returned by vAPI2."""

    id: int
    mbid: int
    private: int
    allow_sriov: int
    display_name: str
    description: str
    last_updated: str
    created: str
    provisioned_locations: list[ProvisionedLocation]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VLAN":
        """Decode a customer VLAN from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "VLAN")
        vlan_id = _int_value(value.get("id"))
        if vlan_id == 0:
            raise ValueError("VLAN payload is missing id")
        locations = value.get("provisioned_locations") or []
        if not isinstance(locations, list):
            raise ValueError("VLAN provisioned_locations must be a list")
        return cls(
            id=vlan_id,
            mbid=_int_value(value.get("mbid")),
            private=_int_value(value.get("private")),
            allow_sriov=_int_value(value.get("allow_sriov")),
            display_name=str(value.get("display_name", "")),
            description=str(value.get("description", "")),
            last_updated=str(value.get("last_updated", "")),
            created=str(value.get("created", "")),
            provisioned_locations=[
                ProvisionedLocation.from_api(row) for row in locations if isinstance(row, Mapping)
            ],
            raw=dict(value),
        )


@dataclass
class ServerNIC:
    """A server's network interface attachment to a customer VLAN, returned by vAPI2.

    The interface identifier arrives as `nic_id` on some responses and `id`
    on others; the latter is used only when `nic_id` is absent or zero,
    mirroring gona's fallback.
    """

    nic_id: int
    mbpkgid: int
    customer_vlan_id: int
    attach_order: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ServerNIC":
        """Decode a server network interface from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row, attach response or update response.
        """
        value = _require_mapping(payload, "server NIC")
        nic_id = _int_value(value.get("nic_id"))
        if nic_id == 0:
            nic_id = _int_value(value.get("id"))
        return cls(
            nic_id=nic_id,
            mbpkgid=_int_value(value.get("mbpkgid")),
            customer_vlan_id=_int_value(value.get("customer_vlan_id")),
            attach_order=_int_value(value.get("attach_order")),
            raw=dict(value),
        )


@dataclass
class FloatingIPLocation:
    """Location metadata for a cloud floating IPv4 address, returned by vAPI3."""

    id: int
    name: str
    flag: str
    latitude: str
    longitude: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "FloatingIPLocation":
        """Decode a floating IP location from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for the location member of a floating IP row.
        """
        value = _require_mapping(payload, "floating IP location")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            flag=str(value.get("flag", "")),
            latitude=str(value.get("latitude", "")),
            longitude=str(value.get("longitude", "")),
            raw=dict(value),
        )


@dataclass
class CloudFloatingIPv4:
    """A cloud floating IPv4 address, returned by vAPI3."""

    floating_ipv4_id: int
    assigned_on: str
    address: str
    vlan_id: int
    ptr_domain: Optional[str]
    location: Optional[FloatingIPLocation]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudFloatingIPv4":
        """Decode a cloud floating IPv4 address from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or create response.
        """
        value = _require_mapping(payload, "cloud floating IPv4 address")
        location = value.get("location")
        if location is not None and not isinstance(location, Mapping):
            raise ValueError("cloud floating IPv4 address location must be an object")
        return cls(
            floating_ipv4_id=_int_value(value.get("floatingIpv4Id")),
            assigned_on=str(value.get("AssignedOn", "")),
            address=str(value.get("address", "")),
            vlan_id=_int_value(value.get("vlanId")),
            ptr_domain=value.get("ptrDomain"),
            location=FloatingIPLocation.from_api(location) if location is not None else None,
            raw=dict(value),
        )


@dataclass
class CloudFloatingIPv4VM:
    """A VM allowed to access a cloud floating IPv4 address, returned by vAPI3."""

    mbpkgid: int
    fqdn: str
    ip: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudFloatingIPv4VM":
        """Decode a floating IPv4 VM grant from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one VM row.
        """
        value = _require_mapping(payload, "cloud floating IPv4 VM")
        return cls(
            mbpkgid=_int_value(value.get("mbpkgid")),
            fqdn=str(value.get("fqdn", "")),
            ip=str(value.get("ip", "")),
            raw=dict(value),
        )


@dataclass
class CloudNetworkingLocation:
    """A mapping from a cloud location to a datacenter, returned by vAPI3."""

    location_id: int
    datacenter_id: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudNetworkingLocation":
        """Decode a cloud networking location mapping from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one location row.
        """
        value = _require_mapping(payload, "cloud networking location")
        return cls(
            location_id=_int_value(value.get("locationId")),
            datacenter_id=_int_value(value.get("datacenterId")),
            raw=dict(value),
        )


def _decode_mbpkg_ref(raw: Any) -> int:
    """Return the mbpkgid from a bare int or an object carrying mbpkgid.

    OIDC client VM and bare metal server allow-list rows arrive as either
    shape depending on account.

    Parameters:
        raw: Decoded JSON value for one allow-list row.
    """
    if isinstance(raw, Mapping):
        return _int_value(raw.get("mbpkgid"))
    if isinstance(raw, bool):
        return 0
    if isinstance(raw, (int, float)):
        return int(raw)
    return 0


@dataclass
class OIDCClientVM:
    """A VM allowed to access an OIDC client, returned by vAPI3.

    `raw` keeps the row exactly as received, since its shape (a bare
    mbpkgid or an object) varies by account.
    """

    mbpkgid: int
    raw: Any

    @classmethod
    def from_api(cls, payload: Any) -> "OIDCClientVM":
        """Decode an OIDC client VM allow-list row.

        Parameters:
            payload: Decoded JSON value for one row.
        """
        return cls(mbpkgid=_decode_mbpkg_ref(payload), raw=payload)


@dataclass
class OIDCClientBareMetalServer:
    """A bare metal server allowed to access an OIDC client, returned by vAPI3.

    `raw` keeps the row exactly as received, since its shape (a bare
    mbpkgid or an object) varies by account.
    """

    mbpkgid: int
    raw: Any

    @classmethod
    def from_api(cls, payload: Any) -> "OIDCClientBareMetalServer":
        """Decode an OIDC client bare metal server allow-list row.

        Parameters:
            payload: Decoded JSON value for one row.
        """
        return cls(mbpkgid=_decode_mbpkg_ref(payload), raw=payload)


@dataclass
class OIDCClientKey:
    """A public key registered to an OIDC client, returned by vAPI3."""

    key_id: int
    label: str
    description: str
    provided_on: str
    revoked_on: str
    type: str
    value: str
    public_key: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "OIDCClientKey":
        """Decode an OIDC client key from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one key row.
        """
        value = _require_mapping(payload, "OIDC client key")
        return cls(
            key_id=_int_value(value.get("keyId")),
            label=str(value.get("label", "")),
            description=str(value.get("description", "")),
            provided_on=str(value.get("providedOn", "")),
            revoked_on=str(value.get("revokedOn", "")),
            type=str(value.get("type", "")),
            value=str(value.get("value", "")),
            public_key=str(value.get("publicKey", "")),
            raw=dict(value),
        )


@dataclass
class OIDCClientAuthLog:
    """An OIDC client authentication log entry, returned by vAPI3."""

    log_id: int
    issued_on: str
    expires_on: str
    jti: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "OIDCClientAuthLog":
        """Decode an OIDC client auth log entry from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one log row.
        """
        value = _require_mapping(payload, "OIDC client auth log")
        return cls(
            log_id=_int_value(value.get("id")),
            issued_on=str(value.get("issuedOn", "")),
            expires_on=str(value.get("expiresOn", "")),
            jti=str(value.get("jti", "")),
            raw=dict(value),
        )


@dataclass
class OIDCClientChangeLog:
    """An OIDC client change log entry, returned by vAPI3."""

    key_id: int
    recorded_on: str
    type: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "OIDCClientChangeLog":
        """Decode an OIDC client change log entry from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one log row.
        """
        value = _require_mapping(payload, "OIDC client change log")
        return cls(
            key_id=_int_value(value.get("keyId")),
            recorded_on=str(value.get("recordedOn", "")),
            type=str(value.get("type", "")),
            raw=dict(value),
        )


@dataclass
class OIDCClient:
    """An OIDC client and its keys, auth logs and change logs, returned by vAPI3.

    `V3Client.list_oidc_clients` decodes a client with `keys`, `auth_logs`
    and `change_logs` left empty; `V3Client.get_oidc_client` fills them in
    along with the label, description, jwksUri and timestamps carried on
    the detail endpoint.
    """

    client_id: int
    created_on: str
    last_used_on: Optional[str]
    label: str
    description: str
    jwks_uri: Optional[str]
    account_default: bool
    default_audience: str
    ttl: int
    enforce_allow_list: bool
    tenant: Optional[str]
    keys: list[OIDCClientKey]
    auth_logs: list[OIDCClientAuthLog]
    change_logs: list[OIDCClientChangeLog]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any, tenant: Optional[str] = None) -> "OIDCClient":
        """Decode an OIDC client list row.

        Parameters:
            payload: Decoded JSON object for one row of `list_oidc_clients`.
            tenant: Tenant identifier carried alongside the client list, if any.
        """
        value = _require_mapping(payload, "OIDC client")
        client_id = _int_value(value.get("clientId"))
        if client_id == 0:
            raise ValueError("OIDC client payload is missing clientId")
        jwks_uri = value.get("jwksUri")
        if jwks_uri is None:
            jwks_uri = value.get("jwksHttpsUrl")
        return cls(
            client_id=client_id,
            created_on=str(value.get("createdOn", "")),
            last_used_on=value.get("lastUsedOn"),
            label=str(value.get("label", "")),
            description=str(value.get("description", "")),
            jwks_uri=jwks_uri,
            account_default=bool(value.get("accountDefault", False)),
            default_audience=str(value.get("defaultAudience", "")),
            ttl=_int_value(value.get("ttl")),
            enforce_allow_list=_bool_value(value.get("enforceAllowList")),
            tenant=str(tenant) if tenant is not None else None,
            keys=[],
            auth_logs=[],
            change_logs=[],
            raw=dict(value),
        )


@dataclass
class FirewallSetVM:
    """A VM's attachment to a cloud firewall set, returned by vAPI2."""

    id: int
    mbpkgid: int
    interface_id: int
    firewall_set_id: int
    set_priority: int
    created: str
    last_updated: str
    iata_code: str
    location: str
    hostname: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "FirewallSetVM":
        """Decode a firewall set VM attachment from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one attachment row.
        """
        value = _require_mapping(payload, "firewall set VM")
        return cls(
            id=_int_value(value.get("id")),
            mbpkgid=_int_value(value.get("mbpkgid")),
            interface_id=_int_value(value.get("interface_id")),
            firewall_set_id=_int_value(value.get("firewall_set_id")),
            set_priority=_int_value(value.get("set_priority")),
            created=str(value.get("created", "")),
            last_updated=str(value.get("last_updated", "")),
            iata_code=str(value.get("iata_code", "")),
            location=str(value.get("location", "")),
            hostname=str(value.get("hostname", "")),
            raw=dict(value),
        )


@dataclass
class ServerBuild:
    """Server creation or rebuild response returned by vAPI2."""

    server_id: int
    status: str
    build: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ServerBuild":
        """Decode a server build response from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by a server buy or rebuild call.
        """
        value = _require_mapping(payload, "server build")
        return cls(
            server_id=_int_value(value.get("mbpkgid")),
            status=str(value.get("status", "")),
            build=_int_value(value.get("build")),
            raw=dict(value),
        )


@dataclass
class JobStatus:
    """NQueue job status returned by vAPI2."""

    id: int
    ts_insert: str
    command: str
    status: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "JobStatus":
        """Decode a job status from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the job status endpoint.
        """
        value = _require_mapping(payload, "job status")
        return cls(
            id=_int_value(value.get("id")),
            ts_insert=str(value.get("ts_insert", "")),
            command=str(value.get("command", "")),
            status=_int_value(value.get("status")),
            raw=dict(value),
        )


@dataclass
class CloudLocation:
    """Cloud deployment location returned by vAPI2."""

    id: int
    name: str
    location: str
    city: str
    country: str
    iata_code: str
    flag: str
    latitude: Optional[str]
    longitude: Optional[str]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudLocation":
        """Decode a cloud location from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the cloud location endpoint.
        """
        value = _require_mapping(payload, "cloud location")
        latitude = value.get("latitude")
        longitude = value.get("longitude")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            location=str(value.get("location", "")),
            city=str(value.get("city", "")),
            country=str(value.get("country", "")),
            iata_code=str(value.get("iata_code", "")),
            flag=str(value.get("flag", "")),
            latitude=str(latitude) if latitude is not None else None,
            longitude=str(longitude) if longitude is not None else None,
            raw=dict(value),
        )


@dataclass
class CloudPool:
    """Cloud pool returned by vAPI2.

    required_vcpu carries a CPU model string such as "EPYC-Milan", not a
    vcpu count, despite the name.
    """

    id: int
    name: str
    description: str
    required_vcpu: Optional[str]
    hard_capabilities: List[str]
    soft_capabilities: List[str]
    private: int
    backup_cloud_pool_id: Optional[int]
    default_ram_price: str
    default_cpu_price: str
    default_disk_price: str
    last_updated: str
    created: str
    contract_id: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudPool":
        """Decode a cloud pool from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the cloud pool endpoint.
        """
        value = _require_mapping(payload, "cloud pool")
        required_vcpu = value.get("required_vcpu")
        backup_cloud_pool_id = value.get("backup_cloud_pool_id")
        contract_id = value.get("contract_id")
        hard_capabilities = value.get("hard_capabilities")
        soft_capabilities = value.get("soft_capabilities")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            required_vcpu=str(required_vcpu) if required_vcpu is not None else None,
            hard_capabilities=[str(item) for item in hard_capabilities] if isinstance(hard_capabilities, list) else [],
            soft_capabilities=[str(item) for item in soft_capabilities] if isinstance(soft_capabilities, list) else [],
            private=_int_value(value.get("private")),
            backup_cloud_pool_id=_int_value(backup_cloud_pool_id) if backup_cloud_pool_id is not None else None,
            default_ram_price=str(value.get("default_ram_price", "")),
            default_cpu_price=str(value.get("default_cpu_price", "")),
            default_disk_price=str(value.get("default_disk_price", "")),
            last_updated=str(value.get("last_updated", "")),
            created=str(value.get("created", "")),
            contract_id=_int_value(contract_id) if contract_id is not None else None,
            raw=dict(value),
        )


@dataclass
class ContractUsage:
    """Usage contract returned by vAPI2. Every field but raw is nullable on the wire."""

    id: Optional[int]
    contract_mbpkgid: Optional[int]
    parent_contract_id: Optional[int]
    brand: Optional[str]
    mb_id: Optional[int]
    contract_type: Optional[str]
    is_free: Optional[int]
    include_bandwidth: Optional[int]
    customer_po: Optional[str]
    customer_description: Optional[str]
    po_monthly_limit: Optional[int]
    monthly_discount: Optional[int]
    hourly_discount: Optional[int]
    max_cpus: Optional[int]
    max_ram: Optional[int]
    max_disk: Optional[int]
    allow_overage: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ContractUsage":
        """Decode a usage contract from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by a usage contract endpoint.
        """
        value = _require_mapping(payload, "contract usage")

        def _opt_int(key: str) -> Optional[int]:
            raw_value = value.get(key)
            return _int_value(raw_value) if raw_value is not None else None

        def _opt_str(key: str) -> Optional[str]:
            raw_value = value.get(key)
            return str(raw_value) if raw_value is not None else None

        return cls(
            id=_opt_int("id"),
            contract_mbpkgid=_opt_int("contract_mbpkgid"),
            parent_contract_id=_opt_int("parent_contract_id"),
            brand=_opt_str("brand"),
            mb_id=_opt_int("mb_id"),
            contract_type=_opt_str("contract_type"),
            is_free=_opt_int("is_free"),
            include_bandwidth=_opt_int("include_bandwidth"),
            customer_po=_opt_str("customer_po"),
            customer_description=_opt_str("customer_description"),
            po_monthly_limit=_opt_int("po_monthly_limit"),
            monthly_discount=_opt_int("monthly_discount"),
            hourly_discount=_opt_int("hourly_discount"),
            max_cpus=_opt_int("max_cpus"),
            max_ram=_opt_int("max_ram"),
            max_disk=_opt_int("max_disk"),
            allow_overage=_opt_int("allow_overage"),
            raw=dict(value),
        )


@dataclass
class Kernel:
    """Boot kernel option returned by vAPI2."""

    id: int
    name: str
    description: Optional[str]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Kernel":
        """Decode a boot kernel from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one kernel row.
        """
        value = _require_mapping(payload, "kernel")
        description = value.get("description")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            description=str(description) if description is not None else None,
            raw=dict(value),
        )


@dataclass
class ServerBuildStatus:
    """Asynchronous server build status returned by vAPI2."""

    id: int
    status: str
    percent: int
    response: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ServerBuildStatus":
        """Decode a server build status from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the build status endpoint.
        """
        value = _require_mapping(payload, "server build status")
        return cls(
            id=_int_value(value.get("id")),
            status=str(value.get("status", "")),
            percent=_int_value(value.get("percent")),
            response=str(value.get("response", "")),
            raw=dict(value),
        )


@dataclass
class ServerIPAddress:
    """IPv4 or IPv6 address attached to a server, returned by vAPI2."""

    id: int
    ip: str
    reverse: Optional[str]
    netmask: Optional[str]
    gateway: Optional[str]
    type: Optional[str]
    primary: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ServerIPAddress":
        """Decode a server IP address from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one address row.
        """
        value = _require_mapping(payload, "server IP address")
        reverse = value.get("reverse")
        netmask = value.get("netmask")
        gateway = value.get("gateway")
        address_type = value.get("type")
        primary = value.get("primary")
        return cls(
            id=_int_value(value.get("id")),
            ip=str(value.get("ip", "")),
            reverse=str(reverse) if reverse is not None else None,
            netmask=str(netmask) if netmask is not None else None,
            gateway=str(gateway) if gateway is not None else None,
            type=str(address_type) if address_type is not None else None,
            primary=_int_value(primary) if primary is not None else None,
            raw=dict(value),
        )


@dataclass
class ServerStatus:
    """Server status payload returned by vAPI2."""

    status: str
    state: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ServerStatus":
        """Decode a server status from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the server status endpoint.
        """
        value = _require_mapping(payload, "server status")
        return cls(
            status=str(value.get("status", "")),
            state=str(value.get("state", "")),
            raw=dict(value),
        )


@dataclass
class Size:
    """Deploy size (plan) offered at a location, returned by vAPI2."""

    plan_id: int
    plan: str
    ram: str
    disk: str
    transfer: str
    price: str
    cpu: int
    port: str
    available: float
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Size":
        """Decode a deploy size from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one size row.
        """
        value = _require_mapping(payload, "size")
        available = value.get("available")
        return cls(
            plan_id=_int_value(value.get("plan_id")),
            plan=str(value.get("plan", "")),
            ram=str(value.get("ram", "")),
            disk=str(value.get("disk", "")),
            transfer=str(value.get("transfer", "")),
            price=str(value.get("price", "")),
            cpu=_int_value(value.get("cpu")),
            port=str(value.get("port", "")),
            available=float(available) if available is not None else 0.0,
            raw=dict(value),
        )


@dataclass
class Service:
    """Account service record returned by vAPI2."""

    id: int
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Service":
        """Decode an account service from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one service row.
        """
        value = _require_mapping(payload, "service")
        return cls(
            id=_int_value(value.get("id")),
            description=str(value.get("description", "")),
            raw=dict(value),
        )


@dataclass
class ColocationService:
    """Colocation service record returned by vAPI2."""

    id: int
    service_id: int
    datacenter_id: int
    rack_identifier: str
    power_details: str
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ColocationService":
        """Decode a colocation service from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one colocation service row.
        """
        value = _require_mapping(payload, "colocation service")
        return cls(
            id=_int_value(value.get("id")),
            service_id=_int_value(value.get("service_id")),
            datacenter_id=_int_value(value.get("datacenter_id")),
            rack_identifier=str(value.get("rack_identifier", "")),
            power_details=str(value.get("power_details", "")),
            description=str(value.get("description", "")),
            raw=dict(value),
        )


@dataclass
class IPTransitService:
    """IP transit service record returned by vAPI2."""

    id: int
    service_id: int
    datacenter_id: int
    bgp_group_id: int
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "IPTransitService":
        """Decode an IP transit service from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one IP transit service row.
        """
        value = _require_mapping(payload, "IP transit service")
        return cls(
            id=_int_value(value.get("id")),
            service_id=_int_value(value.get("service_id")),
            datacenter_id=_int_value(value.get("datacenter_id")),
            bgp_group_id=_int_value(value.get("bgp_group_id")),
            description=str(value.get("description", "")),
            raw=dict(value),
        )


@dataclass
class IPTransitIPAddress:
    """IP address assigned to an IP transit service, returned by vAPI2."""

    id: int
    service_iptransit_id: int
    ip: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "IPTransitIPAddress":
        """Decode an IP transit IP address from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one IP transit IP address row.
        """
        value = _require_mapping(payload, "IP transit IP address")
        return cls(
            id=_int_value(value.get("id")),
            service_iptransit_id=_int_value(value.get("service_iptransit_id")),
            ip=str(value.get("ip", "")),
            raw=dict(value),
        )


@dataclass
class IPTransitPort:
    """Port assigned to an IP transit service, returned by vAPI2."""

    id: int
    service_iptransit_id: int
    name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "IPTransitPort":
        """Decode an IP transit port from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one IP transit port row.
        """
        value = _require_mapping(payload, "IP transit port")
        return cls(
            id=_int_value(value.get("id")),
            service_iptransit_id=_int_value(value.get("service_iptransit_id")),
            name=str(value.get("name", "")),
            raw=dict(value),
        )


@dataclass
class TransportService:
    """Transport service record returned by vAPI2."""

    id: int
    service_id: int
    datacenter_id: int
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TransportService":
        """Decode a transport service from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one transport service row.
        """
        value = _require_mapping(payload, "transport service")
        return cls(
            id=_int_value(value.get("id")),
            service_id=_int_value(value.get("service_id")),
            datacenter_id=_int_value(value.get("datacenter_id")),
            description=str(value.get("description", "")),
            raw=dict(value),
        )


@dataclass
class TransportPort:
    """Port assigned to a transport service, returned by vAPI2."""

    id: int
    service_transport_id: int
    name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TransportPort":
        """Decode a transport port from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one transport port row.
        """
        value = _require_mapping(payload, "transport port")
        return cls(
            id=_int_value(value.get("id")),
            service_transport_id=_int_value(value.get("service_transport_id")),
            name=str(value.get("name", "")),
            raw=dict(value),
        )


@dataclass
class Datacenter:
    """Datacenter record returned by vAPI2."""

    id: int
    name: str
    iata: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Datacenter":
        """Decode a datacenter from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one datacenter row.
        """
        value = _require_mapping(payload, "datacenter")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            iata=str(value.get("iata", "")),
            raw=dict(value),
        )


@dataclass
class PlatformStatusLocation:
    """Component status at one location, returned by vAPI2."""

    location: str
    container_id: str
    status: str
    last_updated: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any, location: str = "") -> "PlatformStatusLocation":
        """Decode a platform status location from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one location entry.
            location: Location key this entry was found under, used when the
                payload itself carries no location field.
        """
        value = _require_mapping(payload, "platform status location")
        return cls(
            location=str(value.get("location", location)),
            container_id=str(value.get("container_id", "")),
            status=str(value.get("status", "")),
            last_updated=str(value.get("last_updated", "")),
            raw=dict(value),
        )


@dataclass
class PlatformStatusService:
    """Platform status for one service, aggregated by location, returned by vAPI2."""

    service: str
    component_id: str
    locations: List[PlatformStatusLocation]
    raw: Dict[str, Any]


@dataclass
class PlatformChangeLogEntry:
    """Platform change log entry returned by vAPI2."""

    change_log_id: str
    title: str
    short_description: str
    status: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "PlatformChangeLogEntry":
        """Decode a platform change log entry from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one change log entry.
        """
        value = _require_mapping(payload, "platform change log entry")
        return cls(
            change_log_id=_string_value(value.get("id")),
            title=_string_value(value.get("title")),
            short_description=_string_value(value.get("short_description")),
            status=_string_value(value.get("status")),
            raw=dict(value),
        )


@dataclass
class PlatformLookingGlassInit:
    """Looking glass initialization payload returned by vAPI2, kept opaque."""

    raw: Any

    @classmethod
    def from_api(cls, payload: Any) -> "PlatformLookingGlassInit":
        """Wrap a looking glass initialization payload without interpreting its shape.

        Parameters:
            payload: Decoded JSON value returned by the looking glass init endpoint.
        """
        return cls(raw=payload)


@dataclass
class PlatformLookingGlassResult:
    """Looking glass execution result returned by vAPI2, kept opaque."""

    raw: Any

    @classmethod
    def from_api(cls, payload: Any) -> "PlatformLookingGlassResult":
        """Wrap a looking glass execution payload without interpreting its shape.

        Parameters:
            payload: Decoded JSON value returned by the looking glass execute endpoint.
        """
        return cls(raw=payload)


@dataclass
class PlatformMaintenanceInfo:
    """Platform maintenance detail payload returned by vAPI2, kept opaque."""

    raw: Any

    @classmethod
    def from_api(cls, payload: Any) -> "PlatformMaintenanceInfo":
        """Wrap a maintenance detail payload without interpreting its shape.

        Parameters:
            payload: Decoded JSON value returned by the maintenance info endpoint.
        """
        return cls(raw=payload)


@dataclass
class PlatformEvent:
    """Platform incident or maintenance event returned by vAPI2."""

    event_id: str
    type: str
    name: str
    status: str
    start_time: str
    end_time: str
    components: List[str]
    containers: List[str]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "PlatformEvent":
        """Decode a platform event from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one event row.
        """
        value = _require_mapping(payload, "platform event")
        components = value.get("components") or []
        containers = value.get("containers") or []
        return cls(
            event_id=_string_value(value.get("event_id")),
            type=str(value.get("type", "")),
            name=str(value.get("name", "")),
            status=str(value.get("status", "")),
            start_time=str(value.get("start_time", "")),
            end_time=str(value.get("end_time", "")),
            components=[str(item) for item in components],
            containers=[str(item) for item in containers],
            raw=dict(value),
        )


@dataclass
class PlatformEvents:
    """Active, upcoming and historic platform events returned by vAPI2."""

    active: List[PlatformEvent]
    upcoming: List[PlatformEvent]
    historic: List[PlatformEvent]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "PlatformEvents":
        """Decode a platform events envelope from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object with active, upcoming and historic
                event lists, as returned by an incidents or maintenance endpoint.
        """
        value = _require_mapping(payload, "platform events")
        return cls(
            active=[PlatformEvent.from_api(row) for row in value.get("active") or []],
            upcoming=[PlatformEvent.from_api(row) for row in value.get("upcoming") or []],
            historic=[PlatformEvent.from_api(row) for row in value.get("historic") or []],
            raw=dict(value),
        )


@dataclass
class Ticket:
    """Support ticket returned by vAPI2."""

    id: str
    subject: str
    status: str
    department: str
    urgency: str
    created_at: str
    updated_at: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Ticket":
        """Decode a support ticket from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "support ticket"), "support ticket")
        return cls(
            id=_string_value(value.get("id")),
            subject=str(value.get("subject", "")),
            status=str(value.get("status", "")),
            department=str(value.get("department", "")),
            urgency=str(value.get("urgency", "")),
            created_at=str(value.get("created_at", "")),
            updated_at=str(value.get("updated_at", "")),
            raw=dict(payload),
        )


@dataclass
class TicketReply:
    """Support ticket reply returned by vAPI2."""

    id: str
    message: str
    created_at: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TicketReply":
        """Decode a support ticket reply from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one reply row.
        """
        value = _metadata_payload(
            _require_mapping(payload, "support ticket reply"), "support ticket reply"
        )
        return cls(
            id=_string_value(value.get("id")),
            message=str(value.get("message", "")),
            created_at=str(value.get("created_at", "")),
            raw=dict(payload),
        )


@dataclass
class TicketDepartment:
    """Support ticket department returned by vAPI2."""

    id: int
    name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TicketDepartment":
        """Decode a support ticket department from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one department row.
        """
        value = _metadata_payload(
            _require_mapping(payload, "support ticket department"), "support ticket department"
        )
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            raw=dict(payload),
        )


@dataclass
class TicketAttachment:
    """Support ticket or reply attachment metadata returned by vAPI2."""

    name: str
    content_type: str
    size: int
    data: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TicketAttachment":
        """Decode support ticket attachment metadata from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object describing the attachment.
        """
        value = _metadata_payload(
            _require_mapping(payload, "support ticket attachment"), "support ticket attachment"
        )
        return cls(
            name=str(value.get("name", "")),
            content_type=str(value.get("content_type", "")),
            size=_int_value(value.get("size")),
            data=str(value.get("data", "")),
            raw=dict(payload),
        )


@dataclass
class SecretList:
    """Secret list returned by vAPI2."""

    id: int
    name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "SecretList":
        """Decode a secret list from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(_require_mapping(payload, "secret list"), "secret list")
        list_id = _int_value(value.get("id"))
        if list_id == 0:
            raise ValueError("secret list payload is missing id")
        return cls(id=list_id, name=str(value.get("name", "")), raw=dict(payload))


@dataclass
class SecretListValue:
    """Secret list value returned by vAPI2."""

    id: int
    secret_list_id: int
    secret_key: str
    secret_value: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "SecretListValue":
        """Decode a secret list value from a vAPI2 payload.

        The secret_list_id field arrives as either a JSON number or a
        numeric string depending on endpoint, so it is coerced rather
        than trusted to be one shape.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _metadata_payload(
            _require_mapping(payload, "secret list value"), "secret list value"
        )
        value_id = _int_value(value.get("id"))
        if value_id == 0:
            raise ValueError("secret list value payload is missing id")
        return cls(
            id=value_id,
            secret_list_id=_int_value(value.get("secret_list_id")),
            secret_key=str(value.get("secret_key", "")),
            secret_value=str(value.get("secret_value", "")),
            raw=dict(payload),
        )


@dataclass
class DedicatedLocation:
    """Location where dedicated servers can be deployed."""

    location_id: int
    short_name: str
    pub_description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedLocation":
        """Decode a dedicated server location from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one location row.
        """
        value = _require_mapping(payload, "dedicated location")
        location_id = _int_value(value.get("location_id"))
        if location_id == 0:
            raise ValueError("dedicated location payload is missing location_id")
        return cls(
            location_id=location_id,
            short_name=str(value.get("short_name", "")),
            pub_description=str(value.get("pub_description", "")),
            raw=dict(payload),
        )


@dataclass
class DedicatedIDName:
    """Identifier and display name pair nested within a dedicated OS profile."""

    id: int
    name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedIDName":
        """Decode an id/name pair from a dedicated OS profile payload.

        This endpoint encodes the pair using PascalCase keys ("ID", "Name")
        rather than the snake_case used elsewhere in vAPI2, so the keys are
        matched exactly as gona expects them on the wire.

        Parameters:
            payload: Decoded JSON object with ID and Name keys.
        """
        value = _require_mapping(payload, "dedicated id/name")
        return cls(id=_int_value(value.get("ID")), name=str(value.get("Name", "")), raw=dict(payload))


@dataclass
class DedicatedOSProfile:
    """Operating system profile compatible with a dedicated device.

    This endpoint encodes its fields using PascalCase keys rather than the
    snake_case used elsewhere in vAPI2, so the keys are matched exactly as
    gona expects them on the wire.
    """

    os_id: int
    name: str
    group_name: str
    tags: List[str]
    disk_layouts: List[DedicatedIDName]
    scripts: List[DedicatedIDName]
    default_disk_layout: int
    default_scripts: List[int]
    allow_ssh_keys: int
    set_root_password: int
    rescue_image: int
    public: int
    enabled: int
    created: str
    last_updated: str
    profile_id: int
    arch: str
    flavor: str
    location_id: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedOSProfile":
        """Decode a dedicated OS profile from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one OS profile row.
        """
        value = _require_mapping(payload, "dedicated OS profile")
        tags = value.get("Tags")
        default_scripts = value.get("DefaultScripts")
        location_id = value.get("LocationID")
        return cls(
            os_id=_int_value(value.get("OSID")),
            name=str(value.get("Name", "")),
            group_name=str(value.get("GroupName", "")),
            tags=[str(tag) for tag in tags] if isinstance(tags, list) else [],
            disk_layouts=[
                DedicatedIDName.from_api(row) for row in value.get("DiskLayouts") or []
            ],
            scripts=[DedicatedIDName.from_api(row) for row in value.get("Scripts") or []],
            default_disk_layout=_int_value(value.get("DefaultDiskLayout")),
            default_scripts=[_int_value(item) for item in default_scripts] if isinstance(default_scripts, list) else [],
            allow_ssh_keys=_int_value(value.get("AllowSSHKeys")),
            set_root_password=_int_value(value.get("SetRootPassword")),
            rescue_image=_int_value(value.get("RescueImage")),
            public=_int_value(value.get("Public")),
            enabled=_int_value(value.get("Enabled")),
            created=str(value.get("Created", "")),
            last_updated=str(value.get("LastUpdated", "")),
            profile_id=_int_value(value.get("ProfileID")),
            arch=str(value.get("Arch", "")),
            flavor=str(value.get("Flavor", "")),
            location_id=_int_value(location_id) if location_id is not None else None,
            raw=dict(payload),
        )


@dataclass
class DedicatedServer:
    """Dedicated server package returned by vAPI2.

    Only the fields most relevant to identifying and operating the server
    are decoded here; every field the API returns remains available in raw.
    """

    id: int
    mbpkgid: int
    hostname: str
    primary_ip: str
    primary_ipv6: Optional[str]
    location: str
    package_status: str
    locked: bool
    total_ram: int
    ipmi_pubip: str
    ob_id: str
    building: Any
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedServer":
        """Decode a dedicated server from a vAPI2 payload.

        `ob_id` arrives as either a JSON number or a numeric string
        depending on the account, so it is coerced to a string rather than
        trusted to be one shape. `building` is an object while a build is
        in progress and null otherwise, so it is kept as-is rather than
        decoded into a fixed shape.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "dedicated server")
        mbpkgid = _int_value(value.get("mbpkgid"))
        if mbpkgid == 0:
            raise ValueError("dedicated server payload is missing mbpkgid")
        primary_ipv6 = value.get("primary_ipv6")
        return cls(
            id=_int_value(value.get("id")),
            mbpkgid=mbpkgid,
            hostname=str(value.get("hostname", "")),
            primary_ip=str(value.get("primary_ip", "")),
            primary_ipv6=str(primary_ipv6) if primary_ipv6 is not None else None,
            location=str(value.get("location", "")),
            package_status=str(value.get("package_status", "")),
            locked=_bool_value(value.get("locked")),
            total_ram=_int_value(value.get("total_ram")),
            ipmi_pubip=str(value.get("ipmi_pubip", "")),
            ob_id=_string_value(value.get("ob_id")),
            building=value.get("building"),
            raw=dict(payload),
        )


@dataclass
class ImageBuild:
    """Custom image build job tracked for an image."""

    id: int
    status: int
    command: str
    ts_insert: str
    mb_id: int
    mb_pkgid: int
    params: str
    build_packet: str
    response: str
    created: str
    last_updated: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ImageBuild":
        """Decode a custom image build job from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one image build row.
        """
        value = _require_mapping(payload, "image build")
        return cls(
            id=_int_value(value.get("id")),
            status=_int_value(value.get("status")),
            command=str(value.get("command", "")),
            ts_insert=str(value.get("ts_insert", "")),
            mb_id=_int_value(value.get("mb_id")),
            mb_pkgid=_int_value(value.get("mb_pkgid")),
            params=str(value.get("params", "")),
            build_packet=str(value.get("build_packet", "")),
            response=str(value.get("response", "")),
            created=str(value.get("created", "")),
            last_updated=str(value.get("last_updated", "")),
            raw=dict(payload),
        )


@dataclass
class Image:
    """Custom server image returned by vAPI2."""

    id: int
    name: str
    description: Optional[str]
    type: str
    subtype: str
    bits: str
    tech: str
    size: str
    category: str
    enabled: Optional[int]
    script_bash: int
    script_cloudinit: int
    created: str
    updated: str
    active_build: Optional[ImageBuild]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Image":
        """Decode a custom server image from a vAPI2 payload.

        The image display name arrives under the "os" key on the wire.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "image")
        image_id = _int_value(value.get("id"))
        if image_id == 0:
            raise ValueError("image payload is missing id")
        description = value.get("description")
        enabled = value.get("os_enabled")
        active_build = value.get("active_build")
        return cls(
            id=image_id,
            name=str(value.get("os", "")),
            description=str(description) if description is not None else None,
            type=str(value.get("type", "")),
            subtype=str(value.get("subtype", "")),
            bits=str(value.get("bits", "")),
            tech=str(value.get("tech", "")),
            size=str(value.get("size", "")),
            category=str(value.get("category", "")),
            enabled=_int_value(enabled) if enabled is not None else None,
            script_bash=_int_value(value.get("script_bash")),
            script_cloudinit=_int_value(value.get("script_cloudinit")),
            created=str(value.get("created", "")),
            updated=str(value.get("updated", "")),
            active_build=ImageBuild.from_api(active_build) if isinstance(active_build, Mapping) else None,
            raw=dict(payload),
        )


@dataclass
class ImageQueueStatus:
    """Status of a queued custom image job."""

    status: str
    percent: int
    response: str
    image_id: int
    image_name: str
    image_help: str
    location: str
    mbpkgid: int
    fqdn: str
    os: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ImageQueueStatus":
        """Decode an image queue job status from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the image queue status endpoint.
        """
        value = _require_mapping(payload, "image queue status")
        return cls(
            status=str(value.get("status", "")),
            percent=_int_value(value.get("percent")),
            response=str(value.get("response", "")),
            image_id=_int_value(value.get("image_id")),
            image_name=str(value.get("image_name", "")),
            image_help=str(value.get("image_help", "")),
            location=str(value.get("location", "")),
            mbpkgid=_int_value(value.get("mbpkgid")),
            fqdn=str(value.get("fqdn", "")),
            os=str(value.get("os", "")),
            raw=dict(payload),
        )


@dataclass
class BGPGroup:
    """Account BGP group returned by vAPI2."""

    id: int
    name: str
    description: str
    group_type: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BGPGroup":
        """Decode a BGP group from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "BGP group")
        group_id = _int_value(value.get("id"))
        if group_id == 0:
            raise ValueError("BGP group payload is missing id")
        return cls(
            id=group_id,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            group_type=str(value.get("group_type", "")),
            raw=dict(payload),
        )


@dataclass
class BGPPrefix:
    """Account BGP prefix returned by vAPI2."""

    id: int
    name: str
    prefix: str
    group_id: int
    asn_id: int
    anycast_profile: int
    agreement_id: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BGPPrefix":
        """Decode a BGP prefix from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "BGP prefix")
        prefix_id = _int_value(value.get("id"))
        if prefix_id == 0:
            raise ValueError("BGP prefix payload is missing id")
        return cls(
            id=prefix_id,
            name=str(value.get("name", "")),
            prefix=str(value.get("prefix", "")),
            group_id=_int_value(value.get("group_id")),
            asn_id=_int_value(value.get("asn_id")),
            anycast_profile=_int_value(value.get("anycast_profile")),
            agreement_id=_int_value(value.get("agreement_id")),
            raw=dict(payload),
        )


@dataclass
class BGPASN:
    """Account ASN returned by vAPI2."""

    id: int
    asn: int
    name: str
    group_type: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BGPASN":
        """Decode a BGP ASN from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "BGP ASN")
        asn_id = _int_value(value.get("id"))
        if asn_id == 0:
            raise ValueError("BGP ASN payload is missing id")
        return cls(
            id=asn_id,
            asn=_int_value(value.get("asn")),
            name=str(value.get("name", "")),
            group_type=str(value.get("group_type", "")),
            raw=dict(payload),
        )


@dataclass
class BGPGroupFirewallSetBinding:
    """Firewall set binding on a BGP group, returned by vAPI2."""

    id: int
    bgp_group_id: int
    firewall_set_id: int
    interface_number: int
    set_priority: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BGPGroupFirewallSetBinding":
        """Decode a BGP group firewall set binding from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the bind endpoint.
        """
        value = _require_mapping(payload, "BGP group firewall set binding")
        return cls(
            id=_int_value(value.get("id")),
            bgp_group_id=_int_value(value.get("bgp2_group_id")),
            firewall_set_id=_int_value(value.get("firewall_set_id")),
            interface_number=_int_value(value.get("interface_number")),
            set_priority=_int_value(value.get("set_priority")),
            raw=dict(payload),
        )


@dataclass
class AccountAgreement:
    """Legal agreement available to the account, returned by vAPI2."""

    id: int
    name: str
    title: str
    description: str
    version: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "AccountAgreement":
        """Decode an account agreement from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from the agreements list.
        """
        value = _require_mapping(payload, "account agreement")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            title=str(value.get("title", "")),
            description=str(value.get("description", "")),
            version=str(value.get("version", "")),
            raw=dict(payload),
        )


@dataclass
class MagicMesh:
    """Magic mesh returned by vAPI3."""

    mesh_id: int
    name: str
    description: Optional[str]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "MagicMesh":
        """Decode a magic mesh from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "magic mesh")
        mesh_id = _int_value(value.get("meshId"))
        if mesh_id == 0:
            raise ValueError("magic mesh payload is missing meshId")
        description = value.get("description")
        return cls(
            mesh_id=mesh_id,
            name=str(value.get("name", "")),
            description=str(description) if description is not None else None,
            raw=dict(payload),
        )


@dataclass
class MeshRouter:
    """Router attached to a magic mesh, returned by vAPI3."""

    router_id: int
    name: str
    description: str
    ipv4_address: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "MeshRouter":
        """Decode a mesh router from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from the mesh routers list.
        """
        value = _require_mapping(payload, "mesh router")
        router_id = _int_value(value.get("routerId"))
        if router_id == 0:
            raise ValueError("mesh router payload is missing routerId")
        return cls(
            router_id=router_id,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            ipv4_address=str(value.get("ipv4Address", "")),
            raw=dict(payload),
        )


def _decode_flexible_ipv4(value: Any) -> str:
    """Decode a router config metadata IPv4 address given as a string or packed int.

    Mirrors gona's FlexibleIPv4.UnmarshalJSON, which accepts either shape.

    Parameters:
        value: Raw ipv4Address field value from a decoded JSON payload.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        raise ValueError("ipv4Address must be either string or int")
    if isinstance(value, int):
        packed = value & 0xFFFFFFFF
        return ".".join(str((packed >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    raise ValueError("ipv4Address must be either string or int")


@dataclass
class RouterBuildStep:
    """One timestamped step of a cloud router build, returned by vAPI3."""

    text: str
    date: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterBuildStep":
        """Decode a router build step from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one build step entry.
        """
        value = _require_mapping(payload, "router build step")
        return cls(text=str(value.get("text", "")), date=str(value.get("date", "")))


@dataclass
class Router:
    """Cloud router returned by vAPI3."""

    name: str
    description: Optional[str]
    ready_on: Optional[str]
    has_default_vrf: bool
    can_join_magic_mesh: bool
    mesh_id: Optional[int]
    build: List[RouterBuildStep]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Router":
        """Decode a cloud router from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router")
        description = value.get("description")
        mesh_id = value.get("meshId")
        build = value.get("build") or []
        if not isinstance(build, list):
            raise ValueError("router payload build must be a list")
        ready_on = value.get("readyOn")
        return cls(
            name=str(value.get("name", "")),
            description=str(description) if description is not None else None,
            ready_on=str(ready_on) if ready_on is not None else None,
            has_default_vrf=bool(value.get("hasDefaultVrf", False)),
            can_join_magic_mesh=bool(value.get("canJoinMagicMesh", False)),
            mesh_id=_int_value(mesh_id) if mesh_id is not None else None,
            build=[RouterBuildStep.from_api(step) for step in build],
            raw=dict(payload),
        )


@dataclass
class RouterLocation:
    """Location metadata nested in a router config, returned by vAPI3."""

    id: int
    name: str
    flag: Optional[str]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterLocation":
        """Decode router config location metadata from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for the location block.
        """
        value = _require_mapping(payload, "router location")
        flag = value.get("flag")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            flag=str(flag) if flag is not None else None,
        )


@dataclass
class RouterConfigMetadata:
    """Metadata block of a router config, returned by vAPI3."""

    status: str
    name: str
    updated_on: Optional[str]
    version: int
    ipv4_address: str
    location: Optional[RouterLocation]
    has_default_vrf: bool
    mesh_id: Optional[int]
    can_join_magic_mesh: bool

    @classmethod
    def from_api(cls, payload: Any) -> "RouterConfigMetadata":
        """Decode router config metadata from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for the config metadata block.
        """
        value = _require_mapping(payload, "router config metadata")
        updated_on = value.get("updatedOn")
        location = value.get("location")
        mesh_id = value.get("meshId")
        return cls(
            status=str(value.get("status", "")),
            name=str(value.get("name", "")),
            updated_on=str(updated_on) if updated_on is not None else None,
            version=_int_value(value.get("version")),
            ipv4_address=_decode_flexible_ipv4(value.get("ipv4Address")),
            location=RouterLocation.from_api(location) if isinstance(location, Mapping) else None,
            has_default_vrf=bool(value.get("hasDefaultVrf", False)),
            mesh_id=_int_value(mesh_id) if mesh_id is not None else None,
            can_join_magic_mesh=bool(value.get("canJoinMagicMesh", False)),
        )


@dataclass
class RouterBGPNeighborSource:
    """Source address override for a router VRF BGP neighbor."""

    address: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterBGPNeighborSource":
        value = _require_mapping(payload, "router BGP neighbor source")
        return cls(address=str(value.get("address", "")))


@dataclass
class RouterBGPNeighborEnabledIPVersion:
    """IP versions enabled for a router VRF BGP neighbor."""

    ipv4: bool
    ipv6: bool

    @classmethod
    def from_api(cls, payload: Any) -> "RouterBGPNeighborEnabledIPVersion":
        value = _require_mapping(payload, "router BGP neighbor enabled IP version")
        return cls(ipv4=bool(value.get("ipv4", False)), ipv6=bool(value.get("ipv6", False)))


@dataclass
class RouterBGPNeighborASN:
    """Remote ASN of a router VRF BGP neighbor."""

    remote: int

    @classmethod
    def from_api(cls, payload: Any) -> "RouterBGPNeighborASN":
        value = _require_mapping(payload, "router BGP neighbor ASN")
        return cls(remote=_int_value(value.get("remote")))


@dataclass
class RouterBGPNeighborRouteMapRule:
    """One rule of a router VRF BGP neighbor import or export route map."""

    prefix_list_id: int
    action: str
    set_local_preference: Optional[int]
    prepend_last_asn: Optional[int]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterBGPNeighborRouteMapRule":
        value = _require_mapping(payload, "router BGP neighbor route map rule")
        set_local_preference = value.get("setLocalPreference")
        prepend_last_asn = value.get("prependLastAsn")
        return cls(
            prefix_list_id=_int_value(value.get("prefixListId")),
            action=str(value.get("action", "")),
            set_local_preference=_int_value(set_local_preference) if set_local_preference is not None else None,
            prepend_last_asn=_int_value(prepend_last_asn) if prepend_last_asn is not None else None,
        )


@dataclass
class RouterBGPNeighborRouteMap:
    """Import or export route map of a router VRF BGP neighbor."""

    do_default_drop: bool
    rules: List[RouterBGPNeighborRouteMapRule]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterBGPNeighborRouteMap":
        value = _require_mapping(payload, "router BGP neighbor route map")
        rules = value.get("rules") or []
        if not isinstance(rules, list):
            raise ValueError("router BGP neighbor route map rules must be a list")
        return cls(
            do_default_drop=bool(value.get("doDefaultDrop", False)),
            rules=[RouterBGPNeighborRouteMapRule.from_api(rule) for rule in rules],
        )


@dataclass
class RouterVRFBGPNeighbor:
    """BGP neighbor configured on a router VRF, returned by vAPI3."""

    neighbor_id: Optional[int]
    address: str
    is_shutdown: bool
    do_as_override: bool
    do_next_help_self: bool
    source: Optional[RouterBGPNeighborSource]
    enabled_ip_version: RouterBGPNeighborEnabledIPVersion
    ebgp_multihop: Optional[int]
    asn: RouterBGPNeighborASN
    md5_secret: str
    import_route_map: Optional[RouterBGPNeighborRouteMap]
    export_route_map: Optional[RouterBGPNeighborRouteMap]
    name: str
    description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFBGPNeighbor":
        """Decode a router VRF BGP neighbor from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router VRF BGP neighbor")
        neighbor_id = value.get("neighborId")
        source = value.get("source")
        ebgp_multihop = value.get("ebgpMultihop")
        import_map = value.get("import")
        export_map = value.get("export")
        return cls(
            neighbor_id=_int_value(neighbor_id) if neighbor_id is not None else None,
            address=str(value.get("address", "")),
            is_shutdown=bool(value.get("isShutdown", False)),
            do_as_override=bool(value.get("doAsOverride", False)),
            do_next_help_self=bool(value.get("doNextHelpSelf", False)),
            source=RouterBGPNeighborSource.from_api(source) if isinstance(source, Mapping) else None,
            enabled_ip_version=RouterBGPNeighborEnabledIPVersion.from_api(value.get("enabledIpVersion") or {}),
            ebgp_multihop=_int_value(ebgp_multihop) if ebgp_multihop is not None else None,
            asn=RouterBGPNeighborASN.from_api(value.get("asn") or {}),
            md5_secret=str(value.get("md5Secret", "")),
            import_route_map=RouterBGPNeighborRouteMap.from_api(import_map) if isinstance(import_map, Mapping) else None,
            export_route_map=RouterBGPNeighborRouteMap.from_api(export_map) if isinstance(export_map, Mapping) else None,
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            raw=dict(payload),
        )


@dataclass
class RouterVRFBGPNetwork:
    """Network advertised by a router VRF's BGP configuration."""

    subnet: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFBGPNetwork":
        value = _require_mapping(payload, "router VRF BGP network")
        return cls(subnet=str(value.get("subnet", "")))


@dataclass
class RouterVRFBGPConfig:
    """BGP configuration of a router VRF, returned by vAPI3."""

    local_asn: Optional[str]
    router_id: str
    networks: List[RouterVRFBGPNetwork]
    neighbors: List[RouterVRFBGPNeighbor]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFBGPConfig":
        """Decode a router VRF BGP configuration from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for the VRF bgp block.
        """
        value = _require_mapping(payload, "router VRF BGP config")
        local_asn = value.get("localAsn")
        networks = value.get("networks") or []
        neighbors = value.get("neighbors") or []
        if not isinstance(networks, list):
            raise ValueError("router VRF BGP config networks must be a list")
        if not isinstance(neighbors, list):
            raise ValueError("router VRF BGP config neighbors must be a list")
        return cls(
            local_asn=str(local_asn) if local_asn is not None else None,
            router_id=str(value.get("routerId", "")),
            networks=[RouterVRFBGPNetwork.from_api(row) for row in networks],
            neighbors=[RouterVRFBGPNeighbor.from_api(row) for row in neighbors],
            raw=dict(payload),
        )


@dataclass
class RouterVRFBGPUpdateResult:
    """Response returned after updating a router VRF's BGP configuration.

    Distinct from RouterVRFBGPConfig because gona's update response encodes
    routerId as an integer rather than the string used everywhere else.
    """

    local_asn: Optional[str]
    router_id: int
    networks: List[RouterVRFBGPNetwork]
    neighbors: List[RouterVRFBGPNeighbor]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFBGPUpdateResult":
        value = _require_mapping(payload, "router VRF BGP update result")
        local_asn = value.get("localAsn")
        networks = value.get("networks") or []
        neighbors = value.get("neighbors") or []
        if not isinstance(networks, list):
            raise ValueError("router VRF BGP update result networks must be a list")
        if not isinstance(neighbors, list):
            raise ValueError("router VRF BGP update result neighbors must be a list")
        return cls(
            local_asn=str(local_asn) if local_asn is not None else None,
            router_id=_int_value(value.get("routerId")),
            networks=[RouterVRFBGPNetwork.from_api(row) for row in networks],
            neighbors=[RouterVRFBGPNeighbor.from_api(row) for row in neighbors],
            raw=dict(payload),
        )


@dataclass
class RouterVRFConfig:
    """VRF configuration of a cloud router, returned by vAPI3.

    Fields that gona itself leaves untyped (dnatRules, snatRules, tunnels,
    interfaces, ipSec, routes and services) are kept as raw JSON here too.
    """

    vrf_id: int
    name: str
    description: str
    bgp: RouterVRFBGPConfig
    dnat_rules: List[Any]
    snat_rules: List[Any]
    services: Dict[str, Any]
    tunnels: List[Any]
    routes: Dict[str, Any]
    interfaces: List[Any]
    ip_sec: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFConfig":
        """Decode a router VRF configuration from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one VRF, from the VRF map or a
                single VRF get response.
        """
        value = _require_mapping(payload, "router VRF config")
        services = value.get("services")
        routes = value.get("routes")
        ip_sec = value.get("ipSec")
        return cls(
            vrf_id=_int_value(value.get("vrfId")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            bgp=RouterVRFBGPConfig.from_api(value.get("bgp") or {}),
            dnat_rules=list(value.get("dnatRules") or []),
            snat_rules=list(value.get("snatRules") or []),
            services=dict(services) if isinstance(services, Mapping) else {},
            tunnels=list(value.get("tunnels") or []),
            routes=dict(routes) if isinstance(routes, Mapping) else {},
            interfaces=list(value.get("interfaces") or []),
            ip_sec=dict(ip_sec) if isinstance(ip_sec, Mapping) else {},
            raw=dict(payload),
        )


@dataclass
class RouterConfig:
    """Full configuration of a cloud router, returned by vAPI3.

    PrefixLists and ipSec are kept as raw JSON, mirroring gona's own
    untyped `[]interface{}` and `interface{}` fields for them.
    """

    default_vrf_id: int
    service: Dict[str, Any]
    prefix_lists: List[Any]
    vrf: Dict[str, RouterVRFConfig]
    ip_sec: Any
    metadata: RouterConfigMetadata
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterConfig":
        """Decode a full router configuration from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from the router config get response.
        """
        value = _require_mapping(payload, "router config")
        service = value.get("service")
        vrf = value.get("vrf") or {}
        if not isinstance(vrf, Mapping):
            raise ValueError("router config vrf must be an object")
        return cls(
            default_vrf_id=_int_value(value.get("defaultVrfId")),
            service=dict(service) if isinstance(service, Mapping) else {},
            prefix_lists=list(value.get("prefixLists") or []),
            vrf={key: RouterVRFConfig.from_api(row) for key, row in vrf.items()},
            ip_sec=value.get("ipSec"),
            metadata=RouterConfigMetadata.from_api(value.get("metadata") or {}),
            raw=dict(payload),
        )


@dataclass
class RouterStaticRouteVia:
    """Next-hop target of a router VRF static route."""

    next_hop: str
    interface_id: Optional[int]
    tunnel_id: Optional[int]
    ip_sec_peer_id: Optional[int]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterStaticRouteVia":
        value = _require_mapping(payload, "router static route via")
        interface_id = value.get("interfaceId")
        tunnel_id = value.get("tunnelId")
        ip_sec_peer_id = value.get("ipSecPeerId")
        return cls(
            next_hop=str(value.get("nextHop", "")),
            interface_id=_int_value(interface_id) if interface_id is not None else None,
            tunnel_id=_int_value(tunnel_id) if tunnel_id is not None else None,
            ip_sec_peer_id=_int_value(ip_sec_peer_id) if ip_sec_peer_id is not None else None,
        )


@dataclass
class RouterStaticRoute:
    """Static route configured on a router VRF, returned by vAPI3."""

    route_id: int
    network: str
    via: RouterStaticRouteVia
    description: str
    distance: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterStaticRoute":
        """Decode a router VRF static route from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router static route")
        route_id = _int_value(value.get("staticRouteId"))
        if route_id == 0:
            raise ValueError("router static route payload is missing staticRouteId")
        distance = value.get("distance")
        return cls(
            route_id=route_id,
            network=str(value.get("network", "")),
            via=RouterStaticRouteVia.from_api(value.get("via") or {}),
            description=str(value.get("description", "")),
            distance=_int_value(distance) if distance is not None else None,
            raw=dict(payload),
        )


@dataclass
class RouterPrefixListRule:
    """One rule of a router prefix list."""

    action: str
    prefix: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterPrefixListRule":
        value = _require_mapping(payload, "router prefix list rule")
        return cls(action=str(value.get("action", "")), prefix=str(value.get("prefix", "")))


@dataclass
class RouterPrefixList:
    """Prefix list configured on a cloud router, returned by vAPI3."""

    prefix_list_id: int
    name: str
    ip_version: int
    description: str
    rules: List[RouterPrefixListRule]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterPrefixList":
        """Decode a router prefix list from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router prefix list")
        prefix_list_id = _int_value(value.get("prefixListId"))
        if prefix_list_id == 0:
            raise ValueError("router prefix list payload is missing prefixListId")
        rules = value.get("rules") or []
        if not isinstance(rules, list):
            raise ValueError("router prefix list rules must be a list")
        return cls(
            prefix_list_id=prefix_list_id,
            name=str(value.get("name", "")),
            ip_version=_int_value(value.get("ipVersion")),
            description=str(value.get("description", "")),
            rules=[RouterPrefixListRule.from_api(rule) for rule in rules],
            raw=dict(payload),
        )


@dataclass
class RouterNTPUpstream:
    """NTP upstream domain configured on a cloud router."""

    domain: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterNTPUpstream":
        value = _require_mapping(payload, "router NTP upstream")
        return cls(domain=str(value.get("domain", "")))


@dataclass
class RouterNTPConfig:
    """NTP service configuration of a cloud router, returned by vAPI3."""

    enabled: bool
    interface_id: Optional[int]
    upstreams: List[RouterNTPUpstream]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterNTPConfig":
        """Decode a router NTP configuration from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from the NTP config get response.
        """
        value = _require_mapping(payload, "router NTP config")
        interface_id = value.get("interfaceId")
        upstreams = value.get("upstreams") or []
        if not isinstance(upstreams, list):
            raise ValueError("router NTP config upstreams must be a list")
        return cls(
            enabled=bool(value.get("enabled", False)),
            interface_id=_int_value(interface_id) if interface_id is not None else None,
            upstreams=[RouterNTPUpstream.from_api(row) for row in upstreams],
            raw=dict(payload),
        )


@dataclass
class RouterIPSecIKEGroup:
    """IKE (phase 1) negotiation parameters of a router's IPsec service."""

    do_auto_renegotiation: bool
    key_exchange_version: int
    lifetime_seconds: int
    dh_group_number: int
    encryption: str
    hash: str
    prf: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterIPSecIKEGroup":
        """Decode an IKE group from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for the ikeGroup member.
        """
        value = _require_mapping(payload, "router IPsec IKE group")
        return cls(
            do_auto_renegotiation=bool(value.get("doAutoRenegotiation", False)),
            key_exchange_version=_int_value(value.get("keyExchangeVersion")),
            lifetime_seconds=_int_value(value.get("lifetimeSeconds")),
            dh_group_number=_int_value(value.get("dhGroupNumber")),
            encryption=str(value.get("encryption", "")),
            hash=str(value.get("hash", "")),
            prf=str(value.get("prf", "")),
        )


@dataclass
class RouterIPSecESPGroup:
    """ESP (phase 2) negotiation parameters of a router's IPsec service."""

    lifetime_seconds: int
    encryption: str
    hash: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterIPSecESPGroup":
        """Decode an ESP group from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for the espGroup member.
        """
        value = _require_mapping(payload, "router IPsec ESP group")
        return cls(
            lifetime_seconds=_int_value(value.get("lifetimeSeconds")),
            encryption=str(value.get("encryption", "")),
            hash=str(value.get("hash", "")),
        )


@dataclass
class RouterIPSecConfig:
    """IPsec service configuration of a cloud router, returned by vAPI3."""

    ike_group: RouterIPSecIKEGroup
    esp_group: RouterIPSecESPGroup
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterIPSecConfig":
        """Decode a router IPsec configuration from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from the IPsec config get response.
        """
        value = _require_mapping(payload, "router IPsec config")
        return cls(
            ike_group=RouterIPSecIKEGroup.from_api(value.get("ikeGroup") or {}),
            esp_group=RouterIPSecESPGroup.from_api(value.get("espGroup") or {}),
            raw=dict(payload),
        )


@dataclass
class RouterVRFIPSecOverlayNetwork:
    """Overlay network addresses of an IPsec peer on a router VRF."""

    ipv4: Optional[str]
    ipv6: Optional[str]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFIPSecOverlayNetwork":
        value = _require_mapping(payload, "router VRF IPsec overlay network")
        ipv4 = value.get("ipv4")
        ipv6 = value.get("ipv6")
        return cls(
            ipv4=str(ipv4) if ipv4 is not None else None,
            ipv6=str(ipv6) if ipv6 is not None else None,
        )


@dataclass
class RouterVRFIPSecPeer:
    """IPsec peer configured on a router VRF, returned by vAPI3."""

    ip_sec_peer_id: int
    name: str
    description: Optional[str]
    remote_id: str
    psk_secret: str
    do_initiate_connection: bool
    peer_address: str
    local_id: str
    overlay_network: RouterVRFIPSecOverlayNetwork
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFIPSecPeer":
        """Decode a router VRF IPsec peer from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router VRF IPsec peer")
        ip_sec_peer_id = _int_value(value.get("ipSecPeerId"))
        if ip_sec_peer_id == 0:
            raise ValueError("router VRF IPsec peer payload is missing ipSecPeerId")
        description = value.get("description")
        return cls(
            ip_sec_peer_id=ip_sec_peer_id,
            name=str(value.get("name", "")),
            description=str(description) if description is not None else None,
            remote_id=str(value.get("remoteId", "")),
            psk_secret=str(value.get("pskSecret", "")),
            do_initiate_connection=bool(value.get("doInitiateConnection", False)),
            peer_address=str(value.get("peerAddress", "")),
            local_id=str(value.get("localId", "")),
            overlay_network=RouterVRFIPSecOverlayNetwork.from_api(value.get("overlayNetwork") or {}),
            raw=dict(payload),
        )


@dataclass
class WireguardPeerAllowedIP:
    """Network allowed through a router VRF interface's wireguard peer."""

    network: str

    @classmethod
    def from_api(cls, payload: Any) -> "WireguardPeerAllowedIP":
        value = _require_mapping(payload, "wireguard peer allowed IP")
        return cls(network=str(value.get("network", "")))


@dataclass
class RouterVRFInterfaceWireguardPeer:
    """Wireguard peer of a router VRF interface, returned by vAPI3."""

    wireguard_peer_id: int
    allowed_ips: List[WireguardPeerAllowedIP]
    public_key: str
    private_key: str
    pre_shared_key: Optional[str]
    remote: Optional[str]
    name: Optional[str]
    description: Optional[str]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFInterfaceWireguardPeer":
        """Decode a router VRF interface wireguard peer from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from an interface's peers member or
                a single get response.
        """
        value = _require_mapping(payload, "router VRF interface wireguard peer")
        wireguard_peer_id = _int_value(value.get("wireguardPeerId"))
        if wireguard_peer_id == 0:
            raise ValueError("router VRF interface wireguard peer payload is missing wireguardPeerId")
        allowed_ips = value.get("allowedIps") or []
        if not isinstance(allowed_ips, list):
            raise ValueError("router VRF interface wireguard peer allowedIps must be a list")
        pre_shared_key = value.get("preSharedKey")
        remote = value.get("remote")
        name = value.get("name")
        description = value.get("description")
        return cls(
            wireguard_peer_id=wireguard_peer_id,
            allowed_ips=[WireguardPeerAllowedIP.from_api(ip) for ip in allowed_ips],
            public_key=str(value.get("publicKey", "")),
            private_key=str(value.get("privateKey", "")),
            pre_shared_key=str(pre_shared_key) if pre_shared_key is not None else None,
            remote=str(remote) if remote is not None else None,
            name=str(name) if name is not None else None,
            description=str(description) if description is not None else None,
            raw=dict(payload),
        )


@dataclass
class RouterVRFInterface:
    """Interface configured on a router VRF, returned by vAPI3."""

    interface_id: int
    vrf_id: int
    type: str
    name: str
    description: Optional[str]
    ipv4_cidr: Optional[str]
    ipv6_cidr: Optional[str]
    ethernet_hardware_id: Optional[str]
    wireguard_port: Optional[int]
    public_key: Optional[str]
    static_routes: List[Any]
    peers: List[RouterVRFInterfaceWireguardPeer]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFInterface":
        """Decode a router VRF interface from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from the interface map or a single
                get response.
        """
        value = _require_mapping(payload, "router VRF interface")
        description = value.get("description")
        ipv4_cidr = value.get("ipv4Cidr")
        ipv6_cidr = value.get("ipv6Cidr")
        ethernet_hardware_id = value.get("ethernetHardwareId")
        wireguard_port = value.get("wireguardPort")
        public_key = value.get("publicKey")
        static_routes = value.get("staticRoutes") or []
        if not isinstance(static_routes, list):
            raise ValueError("router VRF interface staticRoutes must be a list")
        peers = value.get("peers") or []
        if not isinstance(peers, list):
            raise ValueError("router VRF interface peers must be a list")
        return cls(
            interface_id=_int_value(value.get("interfaceId")),
            vrf_id=_int_value(value.get("vrfId")),
            type=str(value.get("type", "")),
            name=str(value.get("name", "")),
            description=str(description) if description is not None else None,
            ipv4_cidr=str(ipv4_cidr) if ipv4_cidr is not None else None,
            ipv6_cidr=str(ipv6_cidr) if ipv6_cidr is not None else None,
            ethernet_hardware_id=str(ethernet_hardware_id) if ethernet_hardware_id is not None else None,
            wireguard_port=_int_value(wireguard_port) if wireguard_port is not None else None,
            public_key=str(public_key) if public_key is not None else None,
            static_routes=list(static_routes),
            peers=[RouterVRFInterfaceWireguardPeer.from_api(row) for row in peers],
            raw=dict(payload),
        )


@dataclass
class RouterVRFSNATRule:
    """Router VRF SNAT rule, returned by vAPI3.

    Match, translation and priority are kept as raw JSON, mirroring gona's
    own anonymous struct fields for them: the shapes vary with protocol and
    port usage more than a fixed schema is worth modeling here.
    """

    snat_rule_id: int
    ip_version: int
    protocol: str
    name: str
    description: str
    match: Optional[Dict[str, Any]]
    translation: Optional[Dict[str, Any]]
    priority: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFSNATRule":
        """Decode a router VRF SNAT rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router VRF SNAT rule")
        snat_rule_id = _int_value(value.get("snatRuleId"))
        if snat_rule_id == 0:
            raise ValueError("router VRF SNAT rule payload is missing snatRuleId")
        match = value.get("match")
        if match is not None and not isinstance(match, Mapping):
            raise ValueError("router VRF SNAT rule match must be an object")
        translation = value.get("translation")
        if translation is not None and not isinstance(translation, Mapping):
            raise ValueError("router VRF SNAT rule translation must be an object")
        priority = value.get("priority")
        if priority is not None and not isinstance(priority, Mapping):
            raise ValueError("router VRF SNAT rule priority must be an object")
        return cls(
            snat_rule_id=snat_rule_id,
            ip_version=_int_value(value.get("ipVersion")),
            protocol=str(value.get("protocol", "")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            match=dict(match) if match is not None else None,
            translation=dict(translation) if translation is not None else None,
            priority=dict(priority) if priority is not None else None,
            raw=dict(payload),
        )


@dataclass
class RouterVRFDNATRule:
    """Router VRF DNAT rule, returned by vAPI3.

    Match, translation and priority are kept as raw JSON, mirroring gona's
    own anonymous struct fields for them: the shapes vary with protocol and
    port usage more than a fixed schema is worth modeling here.
    """

    dnat_rule_id: int
    ip_version: int
    protocol: str
    name: str
    description: str
    match: Optional[Dict[str, Any]]
    translation: Optional[Dict[str, Any]]
    priority: Optional[Dict[str, Any]]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFDNATRule":
        """Decode a router VRF DNAT rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router VRF DNAT rule")
        dnat_rule_id = _int_value(value.get("dnatRuleId"))
        if dnat_rule_id == 0:
            raise ValueError("router VRF DNAT rule payload is missing dnatRuleId")
        match = value.get("match")
        if match is not None and not isinstance(match, Mapping):
            raise ValueError("router VRF DNAT rule match must be an object")
        translation = value.get("translation")
        if translation is not None and not isinstance(translation, Mapping):
            raise ValueError("router VRF DNAT rule translation must be an object")
        priority = value.get("priority")
        if priority is not None and not isinstance(priority, Mapping):
            raise ValueError("router VRF DNAT rule priority must be an object")
        return cls(
            dnat_rule_id=dnat_rule_id,
            ip_version=_int_value(value.get("ipVersion")),
            protocol=str(value.get("protocol", "")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            match=dict(match) if match is not None else None,
            translation=dict(translation) if translation is not None else None,
            priority=dict(priority) if priority is not None else None,
            raw=dict(payload),
        )


@dataclass
class RouterVRFTunnelEndpoint:
    """Source and remote addresses of a router VRF tunnel."""

    source: str
    remote: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFTunnelEndpoint":
        value = _require_mapping(payload, "router VRF tunnel endpoint")
        return cls(source=str(value.get("source", "")), remote=str(value.get("remote", "")))


@dataclass
class RouterVRFTunnel:
    """GRE tunnel configured on a router VRF, returned by vAPI3.

    MTU is decoded as a string: gona's own get-response type carries it as
    `string` while the create and update requests send it as an int, an
    asymmetry inherited from the platform's own responses.
    """

    tunnel_id: int
    name: str
    description: Optional[str]
    ip_key: int
    mtu: str
    ipv4_cidr: Optional[str]
    ipv6_cidr: Optional[str]
    ip_version: int
    endpoint_address: RouterVRFTunnelEndpoint
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFTunnel":
        """Decode a router VRF tunnel from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "router VRF tunnel")
        tunnel_id = _int_value(value.get("tunnelId"))
        if tunnel_id == 0:
            raise ValueError("router VRF tunnel payload is missing tunnelId")
        description = value.get("description")
        ipv4_cidr = value.get("ipv4Cidr")
        ipv6_cidr = value.get("ipv6Cidr")
        return cls(
            tunnel_id=tunnel_id,
            name=str(value.get("name", "")),
            description=str(description) if description is not None else None,
            ip_key=_int_value(value.get("ipKey")),
            mtu=str(value.get("mtu", "")),
            ipv4_cidr=str(ipv4_cidr) if ipv4_cidr is not None else None,
            ipv6_cidr=str(ipv6_cidr) if ipv6_cidr is not None else None,
            ip_version=_int_value(value.get("ipVersion")),
            endpoint_address=RouterVRFTunnelEndpoint.from_api(value.get("endpointAddress") or {}),
            raw=dict(payload),
        )


@dataclass
class RouterDHCPRange:
    """Address range a router VRF's DHCP server leases from."""

    first_address: str
    last_address: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterDHCPRange":
        value = _require_mapping(payload, "router DHCP range")
        return cls(
            first_address=str(value.get("firstAddress", "")),
            last_address=str(value.get("lastAddress", "")),
        )


@dataclass
class RouterDHCPServer:
    """Server address advertised by a router VRF's DHCP service."""

    address: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterDHCPServer":
        value = _require_mapping(payload, "router DHCP server")
        return cls(address=str(value.get("address", "")))


@dataclass
class RouterDHCPStaticRoute:
    """Static route advertised by a router VRF's DHCP service."""

    network: str
    next_hop: str

    @classmethod
    def from_api(cls, payload: Any) -> "RouterDHCPStaticRoute":
        value = _require_mapping(payload, "router DHCP static route")
        return cls(network=str(value.get("network", "")), next_hop=str(value.get("nextHop", "")))


@dataclass
class RouterVRFDHCPConfig:
    """DHCP service configuration of a router VRF, returned by vAPI3."""

    enabled: bool
    interface_id: int
    subnet: str
    default_router_address: str
    client_domain_name: str
    lease_timeout: int
    do_ping_check: bool
    range: Optional[RouterDHCPRange]
    domain_name_servers: List[RouterDHCPServer]
    ntp_servers: List[RouterDHCPServer]
    static_routes: List[RouterDHCPStaticRoute]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "RouterVRFDHCPConfig":
        """Decode a router VRF DHCP configuration from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from the DHCP config get response.
        """
        value = _require_mapping(payload, "router VRF DHCP config")
        range_value = value.get("range")
        domain_name_servers = value.get("domainNameServers") or []
        if not isinstance(domain_name_servers, list):
            raise ValueError("router VRF DHCP config domainNameServers must be a list")
        ntp_servers = value.get("ntpServers") or []
        if not isinstance(ntp_servers, list):
            raise ValueError("router VRF DHCP config ntpServers must be a list")
        static_routes = value.get("staticRoutes") or []
        if not isinstance(static_routes, list):
            raise ValueError("router VRF DHCP config staticRoutes must be a list")
        return cls(
            enabled=bool(value.get("enabled", False)),
            interface_id=_int_value(value.get("interfaceId")),
            subnet=str(value.get("subnet", "")),
            default_router_address=str(value.get("defaultRouterAddress", "")),
            client_domain_name=str(value.get("clientDomainName", "")),
            lease_timeout=_int_value(value.get("leaseTimeout")),
            do_ping_check=bool(value.get("doPingCheck", False)),
            range=RouterDHCPRange.from_api(range_value) if range_value is not None else None,
            domain_name_servers=[RouterDHCPServer.from_api(row) for row in domain_name_servers],
            ntp_servers=[RouterDHCPServer.from_api(row) for row in ntp_servers],
            static_routes=[RouterDHCPStaticRoute.from_api(row) for row in static_routes],
            raw=dict(payload),
        )


@dataclass
class Plan:
    """Purchasable plan offered at a location, returned by vAPI2."""

    id: int
    name: str
    ram: str
    disk: str
    transfer: str
    price: str
    available: float
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Plan":
        """Decode a plan from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one plan row.
        """
        value = _require_mapping(payload, "plan")
        available = value.get("available")
        return cls(
            id=_int_value(value.get("plan_id")),
            name=str(value.get("plan", "")),
            ram=str(value.get("ram", "")),
            disk=str(value.get("disk", "")),
            transfer=str(value.get("transfer", "")),
            price=str(value.get("price", "")),
            available=float(available) if available is not None else 0.0,
            raw=dict(value),
        )


@dataclass
class BootProfile:
    """Cloud boot profile returned by vAPI2."""

    id: int
    name: str
    type: str
    description: str
    builder: str
    kernel: str
    boot: str
    serial: str
    disk_represent: str
    image_template: int
    last_updated: str
    extra: Optional[str]
    vncdisplay: Optional[str]
    disk_root: Optional[str]
    bootloader: Optional[str]
    ramdisk: Optional[str]
    initrd: Optional[str]
    created: Optional[str]
    pae: int
    acpi: int
    apic: int
    xlocaltime: int
    sdl: int
    vnc: int
    vncconsole: int
    vncunused: int
    hide: int
    kvm: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BootProfile":
        """Decode a cloud boot profile from a vAPI2 payload.

        The API answers image_template as a number rather than a string,
        confirmed live, so it is decoded as an int here.

        Parameters:
            payload: Decoded JSON object for one boot profile row.
        """
        value = _require_mapping(payload, "boot profile")

        def _opt_str(key: str) -> Optional[str]:
            raw_value = value.get(key)
            return str(raw_value) if raw_value is not None else None

        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            type=str(value.get("type", "")),
            description=str(value.get("description", "")),
            builder=str(value.get("builder", "")),
            kernel=str(value.get("kernel", "")),
            boot=str(value.get("boot", "")),
            serial=str(value.get("serial", "")),
            disk_represent=str(value.get("disk_represent", "")),
            image_template=_int_value(value.get("image_template")),
            last_updated=str(value.get("last_updated", "")),
            extra=_opt_str("extra"),
            vncdisplay=_opt_str("vncdisplay"),
            disk_root=_opt_str("disk_root"),
            bootloader=_opt_str("bootloader"),
            ramdisk=_opt_str("ramdisk"),
            initrd=_opt_str("initrd"),
            created=_opt_str("created"),
            pae=_int_value(value.get("pae")),
            acpi=_int_value(value.get("acpi")),
            apic=_int_value(value.get("apic")),
            xlocaltime=_int_value(value.get("xlocaltime")),
            sdl=_int_value(value.get("sdl")),
            vnc=_int_value(value.get("vnc")),
            vncconsole=_int_value(value.get("vncconsole")),
            vncunused=_int_value(value.get("vncunused")),
            hide=_int_value(value.get("hide")),
            kvm=_int_value(value.get("kvm")),
            raw=dict(value),
        )


def _dedicated_id_name(payload: Any) -> "DedicatedIDName":
    """Decode one id/name entry nested in a dedicated OS or rescue OS profile.

    Mirrors gona's parseDedicatedIDName: the entry can arrive as an object
    with an id, layout_id or script_id key plus a name, as a bare string
    (the name alone) or as a bare integer (the id alone).

    Parameters:
        payload: Decoded JSON value for one nested id/name entry.
    """
    if isinstance(payload, Mapping):
        id_value = payload.get("id", payload.get("layout_id", payload.get("script_id")))
        name_value = payload.get("name")
        if id_value is not None or name_value is not None:
            return DedicatedIDName(
                id=_int_value(id_value) if id_value is not None else 0,
                name=str(name_value) if name_value is not None else "",
                raw=dict(payload),
            )
        raise ValueError(f"unsupported id/name shape {payload!r}")
    if isinstance(payload, str):
        return DedicatedIDName(id=0, name=payload.strip(), raw={"name": payload.strip()})
    if isinstance(payload, bool):
        raise ValueError(f"unsupported id/name shape {payload!r}")
    if isinstance(payload, int):
        return DedicatedIDName(id=payload, name="", raw={"id": payload})
    raise ValueError(f"unsupported id/name shape {payload!r}")


def _dedicated_id_names(raw: Any) -> List["DedicatedIDName"]:
    """Decode the disklayouts or scripts field of a dedicated OS profile.

    Mirrors gona's parseDedicatedIDNames: the field can arrive as an object
    keyed by id with string names, or as a list of entries each decoded by
    `_dedicated_id_name`. A missing or null field decodes to an empty list.

    Parameters:
        raw: Decoded JSON value for the disklayouts or scripts field.
    """
    if raw is None:
        return []
    if isinstance(raw, Mapping):
        if not all(isinstance(name, str) for name in raw.values()):
            raise ValueError("dedicated id/name map values must be strings")

        def _sort_key(key: str) -> Tuple[int, Any]:
            try:
                return (0, int(key))
            except ValueError:
                return (1, key)

        items = []
        for key in sorted(raw.keys(), key=_sort_key):
            try:
                item_id = int(key)
            except ValueError as exc:
                raise ValueError(f"invalid id key {key!r}") from exc
            items.append(DedicatedIDName(id=item_id, name=raw[key], raw={"id": item_id, "name": raw[key]}))
        return items
    if isinstance(raw, list):
        return [_dedicated_id_name(item) for item in raw]
    raise ValueError("dedicated id/name payload must be an object or a list")


@dataclass
class DedicatedOS:
    """Operating system profile offered by the platform, returned by vAPI2.

    Distinct from `DedicatedOSProfile`, which decodes the device-scoped
    endpoint's PascalCase wire shape. This endpoint answers snake_case keys.
    """

    os_id: int
    name: str
    group_name: str
    tags: List[str]
    disk_layouts: List["DedicatedIDName"]
    scripts: List["DedicatedIDName"]
    default_disk_layout: int
    default_scripts: List[int]
    allow_ssh_keys: int
    set_root_password: int
    rescue_image: int
    public: int
    enabled: int
    created: str
    last_updated: str
    profile_id: int
    arch: str
    flavor: str
    location_id: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedOS":
        """Decode a platform-wide dedicated OS profile from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one OS profile row.
        """
        return _decode_dedicated_os(cls, payload, "dedicated OS profile")


@dataclass
class DedicatedRescueOS:
    """Rescue operating system profile offered by the platform, returned by vAPI2."""

    os_id: int
    name: str
    group_name: str
    tags: List[str]
    disk_layouts: List["DedicatedIDName"]
    scripts: List["DedicatedIDName"]
    default_disk_layout: int
    default_scripts: List[int]
    allow_ssh_keys: int
    set_root_password: int
    rescue_image: int
    public: int
    enabled: int
    created: str
    last_updated: str
    profile_id: int
    arch: str
    flavor: str
    location_id: Optional[int]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedRescueOS":
        """Decode a platform-wide dedicated rescue OS profile from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one rescue OS profile row.
        """
        return _decode_dedicated_os(cls, payload, "dedicated rescue OS profile")


def _decode_dedicated_os(cls: Any, payload: Any, model: str) -> Any:
    """Decode the snake_case dedicated OS profile shape shared by both endpoints.

    Mirrors gona's wireProfile, used by both GetDedicatedOSProfiles and
    GetDedicatedRescueOS.

    Parameters:
        cls: DedicatedOS or DedicatedRescueOS, the dataclass to build.
        payload: Decoded JSON object for one profile row.
        model: Model name used in error messages.
    """
    value = _require_mapping(payload, model)
    tags = value.get("tags")
    default_scripts = value.get("default_scripts")
    default_disk_layout = value.get("default_disklayout")
    location_id = value.get("location_id")
    return cls(
        os_id=_int_value(value.get("id")),
        name=str(value.get("name", "")),
        group_name=str(value.get("group_name", "")),
        tags=[str(tag) for tag in tags] if isinstance(tags, list) else [],
        disk_layouts=_dedicated_id_names(value.get("disklayouts")),
        scripts=_dedicated_id_names(value.get("scripts")),
        default_disk_layout=_int_value(default_disk_layout) if default_disk_layout is not None else 0,
        default_scripts=[_int_value(item) for item in default_scripts] if isinstance(default_scripts, list) else [],
        allow_ssh_keys=_int_value(value.get("allow_ssh_keys")),
        set_root_password=_int_value(value.get("set_root_password")),
        rescue_image=_int_value(value.get("rescue_image")),
        public=_int_value(value.get("public")),
        enabled=_int_value(value.get("enabled")),
        created=str(value.get("created", "")),
        last_updated=str(value.get("last_updated", "")),
        profile_id=_int_value(value.get("profile_id")),
        arch=str(value.get("arch", "")),
        flavor=str(value.get("flavor", "")),
        location_id=_int_value(location_id) if location_id is not None else None,
        raw=dict(value),
    )


@dataclass
class DedicatedDiskLayout:
    """Dedicated server disk layout returned by vAPI2."""

    layout_id: int
    name: str
    profile: str
    min_disks: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedDiskLayout":
        """Decode a dedicated disk layout from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one disk layout row.
        """
        value = _require_mapping(payload, "dedicated disk layout")
        return cls(
            layout_id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            profile=str(value.get("profile", "")),
            min_disks=_int_value(value.get("min_disks")),
            raw=dict(value),
        )


@dataclass
class SSLCertificateDates:
    """Lifecycle timestamps for an SSL certificate, returned by vAPI3."""

    created: str
    updated: str
    not_before: str
    expiration: str

    @classmethod
    def from_api(cls, payload: Any) -> "SSLCertificateDates":
        """Decode SSL certificate dates from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object nested under an SSL certificate's dates field.
        """
        value = _require_mapping(payload, "SSL certificate dates")
        return cls(
            created=str(value.get("created", "")),
            updated=str(value.get("updated", "")),
            not_before=str(value.get("notBefore", "")),
            expiration=str(value.get("expiration", "")),
        )


@dataclass
class SSLCertificate:
    """SSL certificate returned by vAPI3."""

    ssl_certificate_id: int
    name: str
    description: str
    fingerprint: str
    domains: List[str]
    is_active: bool
    status: str
    dates: Optional[SSLCertificateDates]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "SSLCertificate":
        """Decode an SSL certificate from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "SSL certificate")
        domains = value.get("domains")
        dates = value.get("dates")
        if dates is not None and not isinstance(dates, Mapping):
            raise ValueError("SSL certificate dates must be an object")
        return cls(
            ssl_certificate_id=_int_value(value.get("sslCertificateId")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            fingerprint=str(value.get("fingerprint", "")),
            domains=[str(domain) for domain in domains] if isinstance(domains, list) else [],
            is_active=bool(value.get("isActive", False)),
            status=str(value.get("status", "")),
            dates=SSLCertificateDates.from_api(dates) if dates is not None else None,
            raw=dict(value),
        )


@dataclass
class NLBGroupRule:
    """A protocol and port mapping rule within a network load balancer group."""

    protocol: str
    network_rule_id: int
    ports: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NLBGroupRule":
        """Decode a network load balancer group rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one rule entry.
        """
        value = _require_mapping(payload, "NLB group rule")
        ports = value.get("ports")
        if ports is not None and not isinstance(ports, Mapping):
            raise ValueError("NLB group rule ports must be an object")
        return cls(
            protocol=str(value.get("protocol", "")),
            network_rule_id=_int_value(value.get("networkRuleId")),
            ports=dict(ports) if ports is not None else {},
        )


@dataclass
class NLBGroupBackend:
    """A backend host bound to a network load balancer group."""

    name: str
    internal_address: str
    is_online: bool
    network_backend_id: int

    @classmethod
    def from_api(cls, payload: Any) -> "NLBGroupBackend":
        """Decode a network load balancer group backend from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one backend entry.
        """
        value = _require_mapping(payload, "NLB group backend")
        return cls(
            name=str(value.get("name", "")),
            internal_address=str(value.get("internalAddress", "")),
            is_online=bool(value.get("isOnline", False)),
            network_backend_id=_int_value(value.get("networkBackendId")),
        )


@dataclass
class NLBGroup:
    """A network load balancer group returned by vAPI3."""

    network_group_id: int
    name: str
    description: str
    ip_version: int
    algorithm: str
    is_online: bool
    match: Optional[Dict[str, Any]]
    health_check: Optional[Dict[str, Any]]
    rules: List[NLBGroupRule]
    backends: List[NLBGroupBackend]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "NLBGroup":
        """Decode a network load balancer group from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "NLB group")
        match = value.get("match")
        if match is not None and not isinstance(match, Mapping):
            raise ValueError("NLB group match must be an object")
        health_check = value.get("healthCheck")
        if health_check is not None and not isinstance(health_check, Mapping):
            raise ValueError("NLB group healthCheck must be an object")
        rules = value.get("rules") or []
        if not isinstance(rules, list):
            raise ValueError("NLB group rules must be a list")
        backends = value.get("backends") or []
        if not isinstance(backends, list):
            raise ValueError("NLB group backends must be a list")
        return cls(
            network_group_id=_int_value(value.get("networkGroupId")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            ip_version=_int_value(value.get("ipVersion")),
            algorithm=str(value.get("algorithm", "")),
            is_online=bool(value.get("isOnline", False)),
            match=dict(match) if match is not None else None,
            health_check=dict(health_check) if health_check is not None else None,
            rules=[NLBGroupRule.from_api(row) for row in rules],
            backends=[NLBGroupBackend.from_api(row) for row in backends],
            raw=dict(value),
        )


@dataclass
class StatisticSample:
    """One sampled data point of a statistics query result, returned by vAPI3."""

    count: float
    resources: float
    avg: float
    sum: float

    @classmethod
    def from_api(cls, payload: Any) -> "StatisticSample":
        """Decode a statistics sample from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one sample entry.
        """
        value = _require_mapping(payload, "statistic sample")
        return cls(
            count=float(value.get("count", 0) or 0),
            resources=float(value.get("resources", 0) or 0),
            avg=float(value.get("avg", 0) or 0),
            sum=float(value.get("sum", 0) or 0),
        )


@dataclass
class StatisticResult:
    """Result of a statistics query, returned by vAPI3."""

    metric: str
    service: str
    data: List[StatisticSample]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "StatisticResult":
        """Decode a statistics query result from a vAPI3 payload.

        The metric name arrives as the sole key of a nested "metric" object.
        When more than one key is present, the first in sorted order is
        used, mirroring gona's StatisticResult.UnmarshalJSON.

        Parameters:
            payload: Decoded JSON object for one statistics result entry.
        """
        value = _require_mapping(payload, "statistic result")
        metric_obj = value.get("metric")
        metric = ""
        if isinstance(metric_obj, Mapping) and metric_obj:
            metric = sorted(str(key) for key in metric_obj.keys())[0]
        data = value.get("data") or []
        if not isinstance(data, list):
            raise ValueError("statistic result data must be a list")
        return cls(
            metric=metric,
            service=str(value.get("service", "")),
            data=[StatisticSample.from_api(row) for row in data],
            raw=dict(value),
        )


@dataclass
class MetricSummary:
    """Aggregated summary of one metric window, returned by vAPI3."""

    sum: float
    avg: float
    min: float
    max: float

    @classmethod
    def from_api(cls, payload: Any) -> "MetricSummary":
        """Decode a metric summary from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for a sum, avg or last summary.
        """
        value = _require_mapping(payload, "metric summary")
        return cls(
            sum=float(value.get("sum", 0) or 0),
            avg=float(value.get("avg", 0) or 0),
            min=float(value.get("min", 0) or 0),
            max=float(value.get("max", 0) or 0),
        )


@dataclass
class MetricName:
    """One named metric returned by the all-metrics view, per vAPI3."""

    metric: str
    service: str
    resources: int
    avg: MetricSummary
    last: MetricSummary
    sum: MetricSummary

    @classmethod
    def from_api(cls, name: str, payload: Any) -> "MetricName":
        """Decode one named metric entry from a vAPI3 payload.

        Parameters:
            name: Metric name, taken from the entry's key in the response object.
            payload: Decoded JSON object for the metric's service, resources, avg, last and sum.
        """
        value = _require_mapping(payload, "metric name")
        return cls(
            metric=name,
            service=str(value.get("service", "")),
            resources=_int_value(value.get("resources")),
            avg=MetricSummary.from_api(value.get("avg") or {}),
            last=MetricSummary.from_api(value.get("last") or {}),
            sum=MetricSummary.from_api(value.get("sum") or {}),
        )


@dataclass
class MetricTimeWindow:
    """Time window covered by an all-metrics view response, returned by vAPI3."""

    start: str
    end: str
    seconds: int

    @classmethod
    def from_api(cls, payload: Any) -> "MetricTimeWindow":
        """Decode a metric time window from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object nested under the "__timeWindow" key.
        """
        value = _require_mapping(payload, "metric time window")
        return cls(
            start=str(value.get("start", "")),
            end=str(value.get("end", "")),
            seconds=_int_value(value.get("seconds")),
        )


@dataclass
class MetricNames:
    """Response of the all-metrics view, returned by vAPI3."""

    time_window: Optional[MetricTimeWindow]
    metrics: List[MetricName]

    @classmethod
    def from_api(cls, payload: Any) -> "MetricNames":
        """Decode an all-metrics view response from a vAPI3 payload.

        Every top level key other than "__timeWindow" names one metric, and
        metrics are returned sorted by name, mirroring gona's GetMetricNames.

        Parameters:
            payload: Decoded JSON object keyed by metric name, plus "__timeWindow".
        """
        value = _require_mapping(payload, "metric names")
        time_window_raw = value.get("__timeWindow")
        time_window = MetricTimeWindow.from_api(time_window_raw) if time_window_raw is not None else None
        names = sorted(key for key in value.keys() if not key.startswith("__"))
        return cls(
            time_window=time_window,
            metrics=[MetricName.from_api(name, value[name]) for name in names],
        )


@dataclass
class DDoSAttack:
    """A DDoS attack event returned by vAPI2, active or historical."""

    attack_id: int
    date_start: str
    date_end: str
    status: int
    ip: str
    prefix: str
    direction: str
    pps: int
    rule_id: int
    rule_type: str
    ban_duration: int
    rule_name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DDoSAttack":
        """Decode a DDoS attack event from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one attack row.
        """
        value = _require_mapping(payload, "DDoS attack")
        return cls(
            attack_id=_int_value(value.get("id")),
            date_start=str(value.get("date_start", "")),
            date_end=str(value.get("date_end", "")),
            status=_int_value(value.get("status")),
            ip=str(value.get("ip", "")),
            prefix=str(value.get("prefix", "")),
            direction=str(value.get("direction", "")),
            pps=_int_value(value.get("pps")),
            rule_id=_int_value(value.get("rule_id")),
            rule_type=str(value.get("rule_type", "")),
            ban_duration=_int_value(value.get("ban_duration")),
            rule_name=str(value.get("rule_name", "")),
            raw=dict(value),
        )


@dataclass
class DDoSDashboardAttack:
    """One entry in a DDoS dashboard's top attacks list.

    The live account has not produced a populated row, so no fields beyond
    the raw payload are decoded.
    """

    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DDoSDashboardAttack":
        """Decode a DDoS dashboard top attack entry from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one top attack row.
        """
        value = _require_mapping(payload, "DDoS dashboard attack")
        return cls(raw=dict(value))


@dataclass
class DDoSDashboard:
    """DDoS dashboard summary returned by vAPI2."""

    total_attacks: int
    active_rules: int
    longest_attack_seconds: int
    top_attacks: List[DDoSDashboardAttack]
    period: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DDoSDashboard":
        """Decode a DDoS dashboard summary from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the DDoS dashboard endpoint.
        """
        value = _require_mapping(payload, "DDoS dashboard")
        top_attacks = value.get("top_attacks") or []
        if not isinstance(top_attacks, list):
            raise ValueError("DDoS dashboard top_attacks must be a list")
        return cls(
            total_attacks=_int_value(value.get("total_attacks")),
            active_rules=_int_value(value.get("active_rules")),
            longest_attack_seconds=_int_value(value.get("longest_attack_seconds")),
            top_attacks=[DDoSDashboardAttack.from_api(row) for row in top_attacks],
            period=_int_value(value.get("period")),
            raw=dict(value),
        )


@dataclass
class DDoSRulePrefix:
    """A prefix bound to a DDoS rule."""

    prefix_id: int
    prefix: str
    prefix_type: str
    description: str
    allowed_pps: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DDoSRulePrefix":
        """Decode a DDoS rule prefix from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one rule prefix row.
        """
        value = _require_mapping(payload, "DDoS rule prefix")
        return cls(
            prefix_id=_int_value(value.get("id")),
            prefix=str(value.get("prefix", "")),
            prefix_type=str(value.get("prefix_type", "")),
            description=str(value.get("description", "")),
            allowed_pps=_int_value(value.get("allowed_pps")),
            raw=dict(value),
        )


@dataclass
class DDoSRuleAction:
    """An action step within a DDoS rule."""

    name: str
    action_type: str
    run_order: int
    action_name: str
    action_description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DDoSRuleAction":
        """Decode a DDoS rule action from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one rule action row.
        """
        value = _require_mapping(payload, "DDoS rule action")
        return cls(
            name=str(value.get("name", "")),
            action_type=str(value.get("action_type", "")),
            run_order=_int_value(value.get("run_order")),
            action_name=str(value.get("action_name", "")),
            action_description=str(value.get("action_description", "")),
            raw=dict(value),
        )


@dataclass
class DDoSRule:
    """A DDoS mitigation rule returned by vAPI2."""

    rule_id: int
    rule_name: str
    description: str
    prefixes: List[DDoSRulePrefix]
    rules: List[DDoSRuleAction]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DDoSRule":
        """Decode a DDoS rule from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "DDoS rule")
        rule_id = _int_value(value.get("id"))
        if rule_id == 0:
            raise ValueError("DDoS rule payload is missing id")
        prefixes = value.get("prefixes") or []
        if not isinstance(prefixes, list):
            raise ValueError("DDoS rule prefixes must be a list")
        rule_actions = value.get("rules") or []
        if not isinstance(rule_actions, list):
            raise ValueError("DDoS rule rules must be a list")
        return cls(
            rule_id=rule_id,
            rule_name=str(value.get("rule_name", "")),
            description=str(value.get("description", "")),
            prefixes=[DDoSRulePrefix.from_api(row) for row in prefixes],
            rules=[DDoSRuleAction.from_api(row) for row in rule_actions],
            raw=dict(value),
        )


@dataclass
class AccessControlSubnet:
    """A subnet permitted to access the account, returned by vAPI2."""

    id: int
    label: str
    subnet: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "AccessControlSubnet":
        """Decode an access control subnet from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "access control subnet")
        return cls(
            id=_int_value(value.get("id")),
            label=str(value.get("label", "")),
            subnet=str(value.get("subnet", "")),
            raw=dict(value),
        )


@dataclass
class MetalBuild:
    """Result of purchasing or rebuilding a metal device, returned by vAPI2."""

    mbpkgid: int
    status: str
    build: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "MetalBuild":
        """Decode a metal build result from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the metal buy or rebuild endpoint.
        """
        value = _require_mapping(payload, "metal build")
        return cls(
            mbpkgid=_int_value(value.get("mbpkgid")),
            status=str(value.get("status", "")),
            build=_int_value(value.get("build")),
            raw=dict(value),
        )


@dataclass
class MetalBuildStatus:
    """Progress of a metal device build, returned by vAPI2."""

    mbpkgid: int
    response: str
    status: str
    percent: int
    image_name: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "MetalBuildStatus":
        """Decode a metal build status from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the metal build status endpoint.
        """
        value = _require_mapping(payload, "metal build status")
        return cls(
            mbpkgid=_int_value(value.get("mbpkgid")),
            response=str(value.get("response", "")),
            status=str(value.get("status", "")),
            percent=_int_value(value.get("percent")),
            image_name=str(value.get("image_name", "")),
            raw=dict(value),
        )


def _bgp_string_int(value: Any) -> int:
    """Coerce a BGP session ASN to an int, accepting a quoted or bare number.

    Mirrors gona's `json:",string"` tag on ProviderAsn and CustomerAsn, which
    requires the wire value to be a quoted number. Wire payloads have been
    observed sending either shape, so both are accepted here.

    Parameters:
        value: Raw ASN value from a decoded JSON payload.
    """
    if value is None or value == "":
        return 0
    return int(value)


@dataclass
class BGPSessionPrefix:
    """A prefix announced on a BGP session, returned by vAPI2."""

    id: int
    mb_id: int
    prefix: str
    append: Any
    rule_type: str
    prefix_type: str
    description: str
    date: str
    allowed_pps: int
    bgp_group_id: int
    prefix_id: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BGPSessionPrefix":
        """Decode a BGP session prefix from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one prefix row.
        """
        value = _require_mapping(payload, "BGP session prefix")
        return cls(
            id=_int_value(value.get("id")),
            mb_id=_int_value(value.get("mb_id")),
            prefix=str(value.get("prefix", "")),
            append=value.get("append"),
            rule_type=str(value.get("rule_type", "")),
            prefix_type=str(value.get("prefix_type", "")),
            description=str(value.get("description", "")),
            date=str(value.get("date", "")),
            allowed_pps=_int_value(value.get("allowed_pps")),
            bgp_group_id=_int_value(value.get("bgp_group_id")),
            prefix_id=_int_value(value.get("prefix_id")),
            raw=dict(value),
        )


@dataclass
class BGPSession:
    """A customer BGP session returned by vAPI2."""

    id: int
    customer_ip: str
    group_id: int
    locked: int
    description: str
    state: Any
    routes_received: Any
    last_update: Any
    config_status: int
    password: Any
    prefixes: List[BGPSessionPrefix]
    export_list: str
    community: Any
    provider_peer_ip: str
    location: str
    latitude: str
    longitude: str
    group_name: str
    provider_ip_type: str
    provider_asn: int
    customer_asn: int
    raw: Dict[str, Any]

    @property
    def is_locked(self) -> bool:
        """Return whether the session is administratively locked."""
        return self.locked == 1

    @property
    def is_provider_ip_type_v4(self) -> bool:
        """Return whether the provider side of the session is IPv4."""
        return self.provider_ip_type == "ipv4"

    @classmethod
    def from_api(cls, payload: Any) -> "BGPSession":
        """Decode a BGP session from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "BGP session")
        session_id = _int_value(value.get("id"))
        if session_id == 0:
            raise ValueError("BGP session payload is missing id")
        prefixes = value.get("prefixes") or []
        if not isinstance(prefixes, list):
            raise ValueError("BGP session prefixes must be a list")
        return cls(
            id=session_id,
            customer_ip=str(value.get("customer_peer_ip", "")),
            group_id=_int_value(value.get("group_id")),
            locked=_int_value(value.get("locked")),
            description=str(value.get("description", "")),
            state=value.get("state"),
            routes_received=value.get("routes_received"),
            last_update=value.get("last_update"),
            config_status=_int_value(value.get("config_status")),
            password=value.get("password"),
            prefixes=[BGPSessionPrefix.from_api(row) for row in prefixes],
            export_list=str(value.get("export_list", "")),
            community=value.get("community"),
            provider_peer_ip=str(value.get("provider_peer_ip", "")),
            location=str(value.get("location", "")),
            latitude=str(value.get("latitude", "")),
            longitude=str(value.get("longitude", "")),
            group_name=str(value.get("group_name", "")),
            provider_ip_type=str(value.get("provider_ip_type", "")),
            provider_asn=_bgp_string_int(value.get("provider_asn")),
            customer_asn=_bgp_string_int(value.get("customer_asn")),
            raw=dict(value),
        )


@dataclass
class BillingPackage:
    """An account billing package returned by vAPI2."""

    id: int
    name: str
    domu_label: Optional[str]
    package_id: int
    domain: str
    amount: str
    billing_cycle: str
    domain_status: str
    next_due_date: str
    dedicated_ip: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "BillingPackage":
        """Decode a billing package from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one billing package row.
        """
        value = _require_mapping(payload, "billing package")
        domu_label = value.get("domu_label")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            domu_label=str(domu_label) if domu_label is not None else None,
            package_id=_int_value(value.get("packageid")),
            domain=str(value.get("domain", "")),
            amount=str(value.get("amount", "")),
            billing_cycle=str(value.get("billingcycle", "")),
            domain_status=str(value.get("domainstatus", "")),
            next_due_date=str(value.get("nextduedate", "")),
            dedicated_ip=str(value.get("dedicatedip", "")),
            raw=dict(value),
        )


@dataclass
class CloudCapacity:
    """Available capacity for a cloud package size, returned by vAPI2."""

    package_id: int
    package_name: str
    package_cpu: int
    package_ram: int
    package_disk: int
    package_net: int
    package_port: int
    monthly_price: float
    available: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudCapacity":
        """Decode a cloud capacity row from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one capacity row.
        """
        value = _require_mapping(payload, "cloud capacity")
        return cls(
            package_id=_int_value(value.get("pkg_id")),
            package_name=str(value.get("pkg_name", "")),
            package_cpu=_int_value(value.get("pkg_cpu")),
            package_ram=_int_value(value.get("pkg_ram")),
            package_disk=_int_value(value.get("pkg_disk")),
            package_net=_int_value(value.get("pkg_net")),
            package_port=_int_value(value.get("pkg_port")),
            monthly_price=float(value.get("monthly_price") or 0),
            available=_int_value(value.get("available")),
            raw=dict(value),
        )


@dataclass
class DedicatedCapacity:
    """Available capacity for a dedicated device, returned by vAPI2."""

    device_id: int
    location_id: int
    looking_glass: str
    mbpkgid: int
    name: str
    nps_enabled: int
    pub_description: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "DedicatedCapacity":
        """Decode a dedicated capacity row from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one capacity row.
        """
        value = _require_mapping(payload, "dedicated capacity")
        return cls(
            device_id=_int_value(value.get("device_id")),
            location_id=_int_value(value.get("location_id")),
            looking_glass=str(value.get("looking_glass", "")),
            mbpkgid=_int_value(value.get("mbpkgid")),
            name=str(value.get("name", "")),
            nps_enabled=_int_value(value.get("nps_enabled")),
            pub_description=str(value.get("pub_description", "")),
            raw=dict(value),
        )


@dataclass
class NonCloudPackageDetails:
    """Datacenter and bandwidth billing details shared by colocation and transit packages."""

    dc_name: str
    iata_code: str
    bw_commit: str
    overage_type: str
    overage_rate: str
    agg_bw_mbpkgid: str

    @classmethod
    def from_api(cls, payload: Any) -> "NonCloudPackageDetails":
        """Decode non-cloud package details from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object nested under a colocation or transit package's "details" key.
        """
        value = _require_mapping(payload, "non-cloud package details")
        return cls(
            dc_name=str(value.get("dc_name", "")),
            iata_code=str(value.get("iata_code", "")),
            bw_commit=str(value.get("bw_commit", "")),
            overage_type=str(value.get("overage_type", "")),
            overage_rate=str(value.get("overage_rate", "")),
            agg_bw_mbpkgid=str(value.get("agg_bw_mbpkgid", "")),
        )


@dataclass
class ColocationPackage:
    """A purchased colocation package returned by vAPI2."""

    mbpkgid: int
    package_status: str
    fqdn: str
    billing_cycle: str
    next_due_date: str
    amount: str
    details: NonCloudPackageDetails
    status: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "ColocationPackage":
        """Decode a colocation package from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "colocation package")
        return cls(
            mbpkgid=_int_value(value.get("mbpkgid")),
            package_status=str(value.get("package_status", "")),
            fqdn=str(value.get("fqdn", "")),
            billing_cycle=str(value.get("billingcycle", "")),
            next_due_date=str(value.get("nextduedate", "")),
            amount=str(value.get("amount", "")),
            details=NonCloudPackageDetails.from_api(value.get("details") or {}),
            status=str(value.get("status", "")),
            raw=dict(value),
        )


@dataclass
class TransitPackage:
    """A purchased IP transit package returned by vAPI2."""

    mbpkgid: int
    package_status: str
    fqdn: str
    billing_cycle: str
    next_due_date: str
    amount: str
    details: NonCloudPackageDetails
    status: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "TransitPackage":
        """Decode a transit package from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "transit package")
        return cls(
            mbpkgid=_int_value(value.get("mbpkgid")),
            package_status=str(value.get("package_status", "")),
            fqdn=str(value.get("fqdn", "")),
            billing_cycle=str(value.get("billingcycle", "")),
            next_due_date=str(value.get("nextduedate", "")),
            amount=str(value.get("amount", "")),
            details=NonCloudPackageDetails.from_api(value.get("details") or {}),
            status=str(value.get("status", "")),
            raw=dict(value),
        )


@dataclass
class Package:
    """A purchased cloud package returned by vAPI2.

    id, locked and installed arrive as either a quoted or a bare JSON
    number depending on the endpoint, so each is coerced through int()
    rather than trusted to be one shape.
    """

    id: int
    status: str
    locked: int
    plan_name: str
    installed: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "Package":
        """Decode a purchased package from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "package")
        return cls(
            id=_int_value(value.get("mbpkgid")),
            status=str(value.get("package_status", "")),
            locked=_int_value(value.get("locked")),
            plan_name=str(value.get("name", "")),
            installed=_int_value(value.get("installed")),
            raw=dict(value),
        )


@dataclass
class LocationByCurrentIP:
    """The platform location detected from the caller's current IP, returned by vAPI2."""

    ip: str
    location: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "LocationByCurrentIP":
        """Decode a location-by-IP response from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the location endpoint.
        """
        value = _require_mapping(payload, "location by current IP")
        return cls(
            ip=str(value.get("ip", "")),
            location=str(value.get("location", "")),
            raw=dict(value),
        )


@dataclass
class CloudLocationListing:
    """A cloud deployment location as returned by the locations list endpoint.

    Distinct from `CloudLocation`, which decodes the richer single-location
    endpoint's payload.
    """

    id: int
    name: str
    iata_code: str
    continent: str
    flag: str
    disabled: int
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudLocationListing":
        """Decode a cloud deployment location from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one location row.
        """
        value = _require_mapping(payload, "cloud location listing")
        return cls(
            id=_int_value(value.get("id")),
            name=str(value.get("name", "")),
            iata_code=str(value.get("iata_code", "")),
            continent=str(value.get("continent", "")),
            flag=str(value.get("flag", "")),
            disabled=_int_value(value.get("disabled")),
            raw=dict(value),
        )


@dataclass
class CloudOS:
    """An operating system template offered for cloud server builds, returned by vAPI2."""

    id: int
    os: str
    type: str
    subtype: str
    size: str
    bits: str
    tech: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudOS":
        """Decode a cloud OS template from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one OS row.
        """
        value = _require_mapping(payload, "cloud OS")
        return cls(
            id=_int_value(value.get("id")),
            os=str(value.get("os", "")),
            type=str(value.get("type", "")),
            subtype=str(value.get("subtype", "")),
            size=str(value.get("size", "")),
            bits=str(value.get("bits", "")),
            tech=str(value.get("tech", "")),
            raw=dict(value),
        )


@dataclass
class CloudNetworkIP:
    """One IP address returned by the cloud network IPs endpoint, vAPI2."""

    id: int
    primary: int
    reverse: str
    ip: str
    gateway: str
    netmask: str
    broadcast: str

    @classmethod
    def from_api(cls, payload: Any) -> "CloudNetworkIP":
        """Decode a cloud network IP from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object for one address row.
        """
        value = _require_mapping(payload, "cloud network IP")
        return cls(
            id=_int_value(value.get("id")),
            primary=_int_value(value.get("primary")),
            reverse=str(value.get("reverse", "")),
            ip=str(value.get("ip", "")),
            gateway=str(value.get("gateway", "")),
            netmask=str(value.get("netmask", "")),
            broadcast=str(value.get("broadcast", "")),
        )


@dataclass
class CloudNetworkIPs:
    """IPv4 and IPv6 addresses for a package, returned by the vAPI2 network IPs endpoint."""

    ipv4: List[CloudNetworkIP]
    ipv6: List[CloudNetworkIP]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "CloudNetworkIPs":
        """Decode a package's network IPs from a vAPI2 payload.

        Parameters:
            payload: Decoded JSON object returned by the network IPs endpoint.
        """
        value = _require_mapping(payload, "cloud network IPs")
        ipv4 = value.get("IPv4") or []
        ipv6 = value.get("IPv6") or []
        if not isinstance(ipv4, list) or not isinstance(ipv6, list):
            raise ValueError("cloud network IPs IPv4 and IPv6 must be lists")
        return cls(
            ipv4=[CloudNetworkIP.from_api(row) for row in ipv4],
            ipv6=[CloudNetworkIP.from_api(row) for row in ipv6],
            raw=dict(value),
        )


@dataclass
class HTTPLBGroupRule:
    """A domain and path routing rule within an HTTP load balancer group, vAPI3."""

    http_rule_id: int
    https_redirect_enabled: bool
    match: Dict[str, Any]
    ssl: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "HTTPLBGroupRule":
        """Decode an HTTP load balancer group rule from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one rule entry.
        """
        value = _require_mapping(payload, "HTTP LB group rule")
        match = value.get("match")
        ssl = value.get("ssl")
        return cls(
            http_rule_id=_int_value(value.get("httpRuleId")),
            https_redirect_enabled=bool(value.get("httpsRedirectEnabled", False)),
            match=dict(match) if isinstance(match, Mapping) else {},
            ssl=dict(ssl) if isinstance(ssl, Mapping) else {},
        )


@dataclass
class HTTPLBGroupBackend:
    """A backend host bound to an HTTP load balancer group, vAPI3."""

    name: str
    internal_address: str
    is_online: bool
    http_backend_id: int

    @classmethod
    def from_api(cls, payload: Any) -> "HTTPLBGroupBackend":
        """Decode an HTTP load balancer group backend from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one backend entry.
        """
        value = _require_mapping(payload, "HTTP LB group backend")
        return cls(
            name=str(value.get("name", "")),
            internal_address=str(value.get("internalAddress", "")),
            is_online=bool(value.get("isOnline", False)),
            http_backend_id=_int_value(value.get("httpBackendId")),
        )


@dataclass
class HTTPLBGroup:
    """An HTTP load balancer group returned by vAPI3."""

    http_group_id: int
    name: str
    description: str
    algorithm: str
    sticky_sessions_enabled: bool
    ssl_to_backend_enabled: bool
    internal_port: int
    is_online: bool
    match: Dict[str, Any]
    health_check: Dict[str, Any]
    rules: List[HTTPLBGroupRule]
    backends: List[HTTPLBGroupBackend]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "HTTPLBGroup":
        """Decode an HTTP load balancer group from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object from a list row or single get response.
        """
        value = _require_mapping(payload, "HTTP LB group")
        match = value.get("match")
        health_check = value.get("healthCheck")
        rules = value.get("rules") or []
        backends = value.get("backends") or []
        if not isinstance(rules, list):
            raise ValueError("HTTP LB group rules must be a list")
        if not isinstance(backends, list):
            raise ValueError("HTTP LB group backends must be a list")
        return cls(
            http_group_id=_int_value(value.get("httpGroupId")),
            name=str(value.get("name", "")),
            description=str(value.get("description", "")),
            algorithm=str(value.get("algorithm", "")),
            sticky_sessions_enabled=bool(value.get("stickySessionsEnabled", False)),
            ssl_to_backend_enabled=bool(value.get("sslToBackendEnabled", False)),
            internal_port=_int_value(value.get("internalPort")),
            is_online=bool(value.get("isOnline", False)),
            match=dict(match) if isinstance(match, Mapping) else {},
            health_check=dict(health_check) if isinstance(health_check, Mapping) else {},
            rules=[HTTPLBGroupRule.from_api(row) for row in rules],
            backends=[HTTPLBGroupBackend.from_api(row) for row in backends],
            raw=dict(value),
        )


@dataclass
class VPCNameserver:
    """One DHCP nameserver announced by a VPC, returned by vAPI3."""

    server: str
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCNameserver":
        """Decode a VPC nameserver entry from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one nameserver entry.
        """
        value = _require_mapping(payload, "VPC nameserver")
        return cls(server=str(value.get("server", "")), raw=dict(value))


@dataclass
class VPCNameservers:
    """DHCP nameservers announced by a VPC, split by IP version, returned by vAPI3."""

    ipv4: List[VPCNameserver]
    ipv6: List[VPCNameserver]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "VPCNameservers":
        """Decode a VPC's DHCP nameservers from a vAPI3 payload shaped as
        `{"ipv4": [{"server": ...}], "ipv6": [{"server": ...}]}`.

        Parameters:
            payload: Decoded JSON object returned by the nameservers update endpoint.
        """
        value = _require_mapping(payload, "VPC nameservers")
        ipv4 = value.get("ipv4") or []
        ipv6 = value.get("ipv6") or []
        if not isinstance(ipv4, list) or not isinstance(ipv6, list):
            raise ValueError("VPC nameservers ipv4 and ipv6 must be lists")
        return cls(
            ipv4=[VPCNameserver.from_api(row) for row in ipv4],
            ipv6=[VPCNameserver.from_api(row) for row in ipv6],
            raw=dict(value),
        )


@dataclass
class AccountLimit:
    """An account-wide resource limit returned by vAPI3."""

    used: int
    max: int
    allowed_plans: List[str]
    raw: Dict[str, Any]

    @classmethod
    def from_api(cls, payload: Any) -> "AccountLimit":
        """Decode an account limit from a vAPI3 payload.

        Parameters:
            payload: Decoded JSON object for one limit, keyed by resource name.
        """
        value = _require_mapping(payload, "account limit")
        allowed_plans = value.get("allowedPlans") or []
        if not isinstance(allowed_plans, list):
            raise ValueError("account limit allowedPlans must be a list")
        return cls(
            used=_int_value(value.get("used")),
            max=_int_value(value.get("max")),
            allowed_plans=[str(plan) for plan in allowed_plans],
            raw=dict(value),
        )
