"""HTTP clients for NetActuate vAPI2 and vAPI3."""

from __future__ import annotations

import ipaddress
import os
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import requests

from netactuate.errors import ContractError, NetActuateError, NotFoundError
from netactuate.models import (
    AccessControlSubnet,
    AccountAgreement,
    AccountLimit,
    BGPASN,
    BGPGroup,
    BGPGroupFirewallSetBinding,
    BGPPrefix,
    BGPSession,
    BillingPackage,
    CloudCapacity,
    CloudFloatingIPv4,
    CloudFloatingIPv4VM,
    CloudLocation,
    CloudLocationListing,
    CloudNetworkIPs,
    CloudNetworkingLocation,
    CloudOS,
    CloudPool,
    ColocationPackage,
    ColocationService,
    BootProfile,
    ContractUsage,
    Datacenter,
    DDoSAttack,
    DDoSDashboard,
    DDoSRule,
    DedicatedCapacity,
    DedicatedDiskLayout,
    DedicatedLocation,
    DedicatedOS,
    DedicatedOSProfile,
    DedicatedRescueOS,
    DedicatedServer,
    DNSRecord,
    DNSZone,
    FirewallExternalIPSet,
    FirewallManageEnabled,
    FirewallRule,
    FirewallSet,
    FirewallSetVM,
    HTTPLBGroup,
    Image,
    ImageQueueStatus,
    IPTransitIPAddress,
    IPTransitPort,
    IPTransitService,
    JobStatus,
    Kernel,
    LocationByCurrentIP,
    MagicMesh,
    MeshRouter,
    MetalBuild,
    MetalBuildStatus,
    MetricNames,
    NKEAccessURLs,
    NKEAddon,
    NKEAddonCatalogEntry,
    NKECluster,
    NKEClusterDNSZone,
    NKELogEntry,
    NKEWorkerNode,
    NLBGroup,
    OIDCClient,
    OIDCClientAuthLog,
    OIDCClientBareMetalServer,
    OIDCClientChangeLog,
    OIDCClientKey,
    OIDCClientVM,
    Package,
    Plan,
    PlatformChangeLogEntry,
    PlatformEvents,
    PlatformLookingGlassInit,
    PlatformLookingGlassResult,
    PlatformMaintenanceInfo,
    PlatformStatusLocation,
    PlatformStatusService,
    Router,
    RouterConfig,
    RouterDHCPRange,
    RouterDHCPServer,
    RouterDHCPStaticRoute,
    RouterIPSecConfig,
    RouterNTPConfig,
    RouterPrefixList,
    RouterStaticRoute,
    RouterVRFBGPConfig,
    RouterVRFBGPNeighbor,
    RouterVRFBGPUpdateResult,
    RouterVRFConfig,
    RouterVRFDHCPConfig,
    RouterVRFDNATRule,
    RouterVRFIPSecPeer,
    RouterVRFInterface,
    RouterVRFInterfaceWireguardPeer,
    RouterVRFSNATRule,
    RouterVRFTunnel,
    SSHKey,
    SSLCertificate,
    SecretList,
    SecretListValue,
    Server,
    ServerBuild,
    ServerBuildStatus,
    ServerIPAddress,
    ServerNIC,
    ServerStatus,
    Service,
    Size,
    StatisticResult,
    StorageBlockNamespace,
    StorageBlockVolume,
    StorageBucket,
    StorageLocation,
    StorageObjectStore,
    StorageType,
    Tag,
    TagLog,
    TagResource,
    Ticket,
    TicketAttachment,
    TicketDepartment,
    TicketReply,
    TransitPackage,
    TransportPort,
    TransportService,
    VLAN,
    VPC,
    VPCBackend,
    VPCBackendTemplate,
    VPCDNATRule,
    VPCFirewallRule,
    VPCFloatingIP,
    VPCIPReservations,
    VPCLocation,
    VPCNameserver,
    VPCNameservers,
    VPCSNATRule,
    VPCSSHKey,
    VPCSSHSettings,
)

V2_BASE_URL = "https://vapi2.netactuate.com/api/"
V3_BASE_URL = "https://vapi3.netactuate.com"


def _api_key(api_key: Optional[str]) -> str:
    key = api_key if api_key is not None else os.environ.get("NETACTUATE_API_KEY", "")
    if not key:
        raise ValueError("NETACTUATE_API_KEY is required")
    return key


def _with_key(url: str, api_key: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs.append(("key", api_key))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def _page_path(path: str, **updates: Any) -> str:
    parts = urlsplit(path)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = {name: value for name, value in pairs}
    for name, value in updates.items():
        query[name] = str(value)
    return urlunsplit(("", "", parts.path, urlencode(query), ""))


def _firewall_rule_body(
    ip_version: str,
    action: str,
    enabled: bool,
    direction: str,
    rule_priority: Optional[int],
    admin_comment: str,
    match_criteria: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build the JSON body shared by firewall rule create and update calls.

    Mirrors gona's `CreateFirewallRuleRequest`: `ip_version`, `action` and
    `enabled` are always sent, `match_criteria` is always sent even when
    absent (as null), and `direction`, `rule_priority` and `admin_comment`
    are omitted when unset.

    Parameters:
        ip_version: IP version the rule matches.
        action: Action the rule takes.
        enabled: Whether the rule is enabled.
        direction: Traffic direction, or empty to omit it.
        rule_priority: Explicit rule priority, or None to omit it.
        admin_comment: Operator-facing comment, or empty to omit it.
        match_criteria: Match criteria block, or None to send it as null.
    """
    body: Dict[str, Any] = {
        "ip_version": ip_version,
        "action": action,
        "enabled": enabled,
        "match_criteria": dict(match_criteria) if match_criteria is not None else None,
    }
    if direction:
        body["direction"] = direction
    if rule_priority is not None:
        body["rule_priority"] = rule_priority
    if admin_comment:
        body["admin_comment"] = admin_comment
    return body


def _firewall_vm_query_params(**flags: Optional[Any]) -> Dict[str, str]:
    """Build query parameters for the firewall VM listing endpoints.

    Bools are encoded as "1"/"0", other values as their string form, and
    entries left as None are omitted, mirroring gona's optional pointer
    fields on `FirewallAvailableVMOptions` and `FirewallRelatedSetOptions`.

    Parameters:
        flags: Query parameter name to value mapping.
    """
    params: Dict[str, str] = {}
    for name, value in flags.items():
        if value is None:
            continue
        if isinstance(value, bool):
            params[name] = "1" if value else "0"
        else:
            params[name] = str(value)
    return params


def _json(response: requests.Response) -> Mapping[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:
        raise NetActuateError(
            "could not decode API response",
            method=response.request.method,
            url=response.url,
            status_code=response.status_code,
            body=response.text,
        ) from exc
    if not isinstance(payload, Mapping):
        raise NetActuateError(
            "API response must be an object",
            method=response.request.method,
            url=response.url,
            status_code=response.status_code,
            body=response.text,
        )
    return payload


def _fields_match(fields: Any, wanted: Iterable[Tuple[str, str]]) -> Optional[str]:
    if not isinstance(fields, Mapping):
        return None
    for field, needle in wanted:
        messages = fields.get(field, [])
        if isinstance(messages, str):
            messages = [messages]
        if not isinstance(messages, Iterable):
            continue
        for message in messages:
            text = str(message)
            if needle in text:
                return text
    return None


def _response_int(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if value is None or value == "":
        return 0
    return int(value)


def _decode_storage_types(data: Any) -> List[StorageType]:
    """Decode the storage types response, which arrives as a bare array or as
    an object keyed by type code rather than a normal list envelope.

    Parameters:
        data: Decoded JSON value returned by GET /storage.
    """
    if isinstance(data, list):
        return [StorageType.from_api(row) for row in data]
    if isinstance(data, Mapping):
        inner = data.get("data")
        if isinstance(inner, list):
            return [StorageType.from_api(row) for row in inner]
        types: List[StorageType] = []
        for type_code in sorted(key for key in data.keys() if key != "meta"):
            row = data[type_code]
            entry = StorageType.from_api(row)
            if not entry.type:
                entry.type = type_code
            types.append(entry)
        return types
    raise NetActuateError("storage types response has an unrecognized shape")


def _decode_server_nic(data: Any) -> ServerNIC:
    """Decode a server NIC attach or update response.

    These endpoints answer with either a single NIC object or, on some
    accounts, a one-element array of it.

    Parameters:
        data: Decoded JSON value returned by the NIC attach or update endpoint.
    """
    if isinstance(data, Mapping):
        return ServerNIC.from_api(data)
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], Mapping):
        return ServerNIC.from_api(data[0])
    raise NetActuateError("server NIC response has an unrecognized shape")


def _server_build_values(
    *,
    plan: str,
    location: int,
    image: int,
    fqdn: str,
    ssh_key: str,
    ssh_key_id: int,
    password: str,
    package_billing: str,
    package_billing_contract_id: str,
    cloud_config: str,
    script_content: str,
    params: str,
    cloud_pool_id: Optional[int],
    vpc_id: Optional[int],
) -> Dict[str, Any]:
    """Build the form values shared by server buy and rebuild calls.

    Mirrors gona's CreateServerRequest and BuildServerRequest: every field is
    omitted when left at its zero value, and script_content implies
    script_type=user-data.

    Parameters:
        plan: Plan code to build.
        location: Location identifier to build in.
        image: Operating system image identifier.
        fqdn: Fully qualified hostname to assign.
        ssh_key: Public key content to install.
        ssh_key_id: Existing SSH key identifier to install.
        password: Root password to set.
        package_billing: Billing package code.
        package_billing_contract_id: Contract identifier to bill the package to.
        cloud_config: Cloud-init user data content.
        script_content: Startup script content.
        params: Additional provider specific parameters.
        cloud_pool_id: Optional cloud pool identifier.
        vpc_id: Optional VPC identifier.
    """
    values: Dict[str, Any] = {}
    if plan:
        values["plan"] = plan
    if location:
        values["location"] = location
    if image:
        values["image"] = image
    if fqdn:
        values["fqdn"] = fqdn
    if ssh_key:
        values["ssh_key"] = ssh_key
    if ssh_key_id:
        values["ssh_key_id"] = ssh_key_id
    if password:
        values["password"] = password
    if package_billing:
        values["package_billing"] = package_billing
    if package_billing_contract_id:
        values["package_billing_contract_id"] = package_billing_contract_id
    if cloud_config:
        values["cloud_config"] = cloud_config
    if script_content:
        values["script_content"] = script_content
        values["script_type"] = "user-data"
    if params:
        values["params"] = params
    if cloud_pool_id is not None:
        values["cloud_pool_id"] = cloud_pool_id
    if vpc_id is not None:
        values["vpc_id"] = vpc_id
    return values


def _add_tag_list(values: Dict[str, Any], tag_list: Optional[Sequence[str]]) -> None:
    """Add a repeated tag_list[] form field to values, mirroring gona's encoding.

    An empty sequence sends one empty tag_list[] entry to clear tags, while
    None omits the field entirely.

    Parameters:
        values: Form values mapping to update in place.
        tag_list: Complete set of tag names, or None to leave tags unspecified.
    """
    if tag_list is None:
        return
    values["tag_list[]"] = list(tag_list) if tag_list else [""]


def _dedicated_build_body(
    fqdn: str,
    profile: int,
    disk_layout: Optional[int],
    root_password: Optional[str],
    ssh_key: Optional[str],
    ssh_key_id: Optional[int],
    build_script: Optional[str],
) -> Dict[str, Any]:
    """Build the JSON body shared by dedicated server deploy calls.

    Mirrors gona's DedicatedServerBuildRequest: fqdn and profile are always
    sent, even when empty or zero, and the remaining fields are omitted
    when left unset.

    Parameters:
        fqdn: Fully qualified hostname to assign.
        profile: OS profile identifier to build.
        disk_layout: Optional disk layout identifier.
        root_password: Optional root password to set.
        ssh_key: Optional public key content to install.
        ssh_key_id: Optional existing SSH key identifier to install.
        build_script: Optional startup build script content.
    """
    body: Dict[str, Any] = {"fqdn": fqdn, "profile": profile}
    if disk_layout is not None:
        body["disklayout"] = disk_layout
    if root_password is not None:
        body["root_password"] = root_password
    if ssh_key is not None:
        body["ssh_key"] = ssh_key
    if ssh_key_id is not None:
        body["ssh_key_id"] = ssh_key_id
    if build_script is not None:
        body["build_script"] = build_script
    return body


def _server_action_body(force: Optional[bool]) -> Dict[str, Any]:
    """Build the JSON body for a cloud server power action.

    Mirrors gona's ServerActionRequest: force is omitted unless given. An
    empty object, rather than no body at all, is sent when force is left
    unset, matching the shape already relied on by callers that expect a
    JSON request.

    Parameters:
        force: Optional flag forcing the action.
    """
    body: Dict[str, Any] = {}
    if force is not None:
        body["force"] = force
    return body


def _dedicated_action_body(force: Optional[bool], password: Optional[str]) -> Optional[Dict[str, Any]]:
    """Build the JSON body for a dedicated server power or delete action.

    Mirrors gona's DedicatedServerActionRequest: both fields are optional,
    and None is returned, rather than an empty object, when neither is
    given, so the request carries no body at all.

    Parameters:
        force: Optional flag forcing the action.
        password: Optional password required by the platform for this action.
    """
    body: Dict[str, Any] = {}
    if force is not None:
        body["force"] = force
    if password is not None:
        body["password"] = password
    return body or None


def _metal_optional_values(
    ssh_key: str,
    ssh_key_id: Optional[int],
    password: str,
    build_script: str,
    disk_layout: Optional[int],
    profile: Optional[int],
    hostname: str,
) -> Dict[str, Any]:
    """Build the form values shared by metal device buy and rebuild calls.

    Mirrors the optional fields shared by gona's CreateMetalRequest and
    BuildMetalRequest: each is omitted when left at its zero value.

    Parameters:
        ssh_key: Public key content to install.
        ssh_key_id: Existing SSH key identifier to install.
        password: Root password to set.
        build_script: Startup build script content.
        disk_layout: Disk layout identifier.
        profile: OS profile identifier to build.
        hostname: Fully qualified hostname to assign.
    """
    values: Dict[str, Any] = {}
    if ssh_key:
        values["ssh_key"] = ssh_key
    if ssh_key_id is not None:
        values["ssh_key_id"] = ssh_key_id
    if password:
        values["root_password"] = password
    if build_script:
        values["build_script"] = build_script
    if disk_layout is not None:
        values["disklayout"] = disk_layout
    if profile is not None:
        values["profile"] = profile
    if hostname:
        values["fqdn"] = hostname
    return values


def _sorted_by_mbpkgid(data: Any, label: str) -> List[Dict[str, Any]]:
    """Decode a mapping of package id to row into a list sorted by mbpkgid.

    Mirrors gona's GetColocationPackages and GetTransitPackages, which
    receive a map keyed by package id and sort the values explicitly since
    Go map iteration order is not guaranteed.

    Parameters:
        data: Decoded JSON value keyed by package id.
        label: Description of the response used in the error message.
    """
    if not isinstance(data, Mapping):
        raise NetActuateError(f"{label} response must be an object keyed by package id")
    rows = [dict(row) for row in data.values() if isinstance(row, Mapping)]
    rows.sort(key=lambda row: int(row.get("mbpkgid") or 0))
    return rows


def _cloud_network_ip_type_map(ips: CloudNetworkIPs) -> Dict[str, str]:
    """Map every address on a package to its IP type, keyed by every known form.

    Mirrors gona's IPs.GetIPsMap: IPv4 addresses are mapped as given, and
    IPv6 addresses are mapped both as given and, when parseable, in their
    fully expanded form, since a BGP session's customer peer IP may be
    reported in either shape.

    Parameters:
        ips: Package IP addresses to map.
    """
    mapping: Dict[str, str] = {}
    for entry in ips.ipv4:
        mapping[entry.ip] = "ipv4"
    for entry in ips.ipv6:
        mapping[entry.ip] = "ipv6"
        try:
            expanded = ipaddress.ip_address(entry.ip).exploded
        except ValueError:
            expanded = None
        if expanded:
            mapping[expanded] = "ipv6"
    return mapping


def _decode_dedicated_devices(raw: Any) -> List[Dict[str, Any]]:
    """Decode the filter dedicated devices response.

    The rows sit at devices.paginator.data: a paginated list inside a named
    sub object, alongside the column lists the portal uses. When the
    paginator is at the top level instead, the response has already been
    reduced to a bare list, so both shapes are accepted. Each device is
    returned as a raw mapping because the API does not define a fixed
    schema for it.

    Parameters:
        raw: Decoded JSON value returned by the filter endpoint.
    """
    if isinstance(raw, list):
        return [dict(row) for row in raw if isinstance(row, Mapping)]
    if isinstance(raw, Mapping):
        devices = raw.get("devices")
        if isinstance(devices, Mapping):
            paginator = devices.get("paginator")
            if isinstance(paginator, Mapping) and isinstance(paginator.get("data"), list):
                return [dict(row) for row in paginator["data"] if isinstance(row, Mapping)]
    raise NetActuateError("filter dedicated devices response has an unrecognized shape")


def _decode_platform_status(data: Any) -> List[PlatformStatusService]:
    """Decode the platform status response into a list sorted by service and location.

    The API answers with an object keyed by service name, each holding an
    object keyed by location name, mirroring gona's GetPlatformStatus, which
    flattens both maps into sorted slices.

    Parameters:
        data: Decoded JSON value returned by GET platform/status.
    """
    if not isinstance(data, Mapping):
        raise NetActuateError("platform status response must be an object")
    services: List[PlatformStatusService] = []
    for service_name in sorted(data.keys()):
        wire = data[service_name]
        if not isinstance(wire, Mapping):
            raise NetActuateError(f"platform status for {service_name} must be an object")
        locations_map = wire.get("locations")
        locations: List[PlatformStatusLocation] = []
        if isinstance(locations_map, Mapping):
            for location_name in sorted(locations_map.keys()):
                location = PlatformStatusLocation.from_api(locations_map[location_name], location_name)
                location.location = location_name
                locations.append(location)
        services.append(
            PlatformStatusService(
                service=service_name,
                component_id=str(wire.get("component_id", "")),
                locations=locations,
                raw=dict(wire),
            )
        )
    return services


def _looks_contract_gated(status_code: int, code: int, message: str) -> bool:
    text = message.lower()
    return (
        status_code == 412
        or code == 412
        or "contract" in text
        or "not entitled" in text
        or "not enabled" in text
    )


def _ticket_list_path(path: str, open_: Optional[str], include_stats: Optional[str]) -> str:
    """Build a support ticket list path with its optional filters.

    Parameters:
        path: Base ticket list path.
        open_: Optional open state filter, or None to omit it.
        include_stats: Optional flag requesting ticket statistics, or None to omit it.
    """
    values: Dict[str, Any] = {}
    if open_ is not None:
        values["open"] = open_
    if include_stats is not None:
        values["include_stats"] = include_stats
    if values:
        return _page_path(path, **values)
    return path


def _ticket_attachment_path(ticket_id: str, attachment_type: str, rel_id: str, index: int) -> str:
    """Build the path to a support ticket or reply attachment.

    Parameters:
        ticket_id: Support ticket identifier.
        attachment_type: Attachment owner type, for example "ticket" or "reply".
        rel_id: Identifier of the ticket or reply the attachment belongs to.
        index: Zero based attachment index.
    """
    return (
        f"support/tickets/{quote(ticket_id, safe='')}/attachment/"
        f"{quote(attachment_type, safe='')}/{quote(rel_id, safe='')}/{index}"
    )


class Client:
    """Client for NetActuate vAPI2.

    Parameters:
        api_key: API key. When omitted, `NETACTUATE_API_KEY` is used.
        base_url: vAPI2 base URL. Empty means production.
        session: Optional `requests.Session` compatible transport.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "",
        session: Optional[requests.Session] = None,
        timeout: float = 120.0,
    ) -> None:
        self._api_key = _api_key(api_key)
        self.base_url = base_url or V2_BASE_URL
        self.session = session or requests.Session()
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"Client(base_url={self.base_url!r})"

    def list_servers(self) -> List[Server]:
        """Return all cloud servers visible to the account."""
        return [Server.from_api(row) for row in self._get("cloud/servers")]

    def get_server(self, server_id: int) -> Server:
        """Return one cloud server.

        Parameters:
            server_id: vAPI2 `mbpkgid` server identifier.
        """
        return Server.from_api(self._get(f"cloud/server/{server_id}"))

    def create_server(
        self,
        plan: str = "",
        location: int = 0,
        image: int = 0,
        fqdn: str = "",
        ssh_key: str = "",
        ssh_key_id: int = 0,
        password: str = "",
        package_billing: str = "",
        package_billing_contract_id: str = "",
        cloud_config: str = "",
        script_content: str = "",
        params: str = "",
        tag: str = "",
        tag_list: Optional[Sequence[str]] = None,
        cloud_pool_id: Optional[int] = None,
        vpc_id: Optional[int] = None,
    ) -> ServerBuild:
        """Buy and build a new cloud server.

        Parameters:
            plan: Plan code to build.
            location: Location identifier to build in.
            image: Operating system image identifier.
            fqdn: Fully qualified hostname for the new server.
            ssh_key: Public key content to install, when not using ssh_key_id.
            ssh_key_id: Existing SSH key identifier to install.
            password: Root password to set. The API generates one when omitted.
            package_billing: Billing package code, for example "hourly" or "monthly".
            package_billing_contract_id: Contract identifier to bill the package to.
            cloud_config: Cloud-init user data content.
            script_content: Startup script content, sent as user-data.
            params: Additional provider specific parameters.
            tag: Optional single tag name to apply.
            tag_list: Optional complete set of tag names to apply. An empty
                sequence clears tags rather than leaving them unspecified.
            cloud_pool_id: Optional cloud pool identifier to build into.
            vpc_id: Optional VPC identifier to attach the server to.
        """
        values = _server_build_values(
            plan=plan,
            location=location,
            image=image,
            fqdn=fqdn,
            ssh_key=ssh_key,
            ssh_key_id=ssh_key_id,
            password=password,
            package_billing=package_billing,
            package_billing_contract_id=package_billing_contract_id,
            cloud_config=cloud_config,
            script_content=script_content,
            params=params,
            cloud_pool_id=cloud_pool_id,
            vpc_id=vpc_id,
        )
        if tag:
            values["tag"] = tag
        _add_tag_list(values, tag_list)
        return ServerBuild.from_api(self._post_form("cloud/server/buy_build", values))

    def build_server(
        self,
        server_id: int,
        plan: str = "",
        location: int = 0,
        image: int = 0,
        fqdn: str = "",
        ssh_key: str = "",
        ssh_key_id: int = 0,
        password: str = "",
        package_billing: str = "",
        package_billing_contract_id: str = "",
        cloud_config: str = "",
        script_content: str = "",
        params: str = "",
        tag_list: Optional[Sequence[str]] = None,
        cloud_pool_id: Optional[int] = None,
        vpc_id: Optional[int] = None,
    ) -> ServerBuild:
        """Rebuild an existing cloud server.

        There is no single-tag parameter here because the rebuild endpoint
        only honors the complete tag_list form, not a single tag name.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to rebuild.
            plan: Plan code to build.
            location: Location identifier to build in.
            image: Operating system image identifier.
            fqdn: Fully qualified hostname to assign.
            ssh_key: Public key content to install, when not using ssh_key_id.
            ssh_key_id: Existing SSH key identifier to install.
            password: Root password to set. The API generates one when omitted.
            package_billing: Billing package code, for example "hourly" or "monthly".
            package_billing_contract_id: Contract identifier to bill the package to.
            cloud_config: Cloud-init user data content.
            script_content: Startup script content, sent as user-data.
            params: Additional provider specific parameters.
            tag_list: Optional complete set of tag names to apply. An empty
                sequence clears tags rather than leaving them unspecified.
            cloud_pool_id: Optional cloud pool identifier to build into.
            vpc_id: Optional VPC identifier to attach the server to.
        """
        values = _server_build_values(
            plan=plan,
            location=location,
            image=image,
            fqdn=fqdn,
            ssh_key=ssh_key,
            ssh_key_id=ssh_key_id,
            password=password,
            package_billing=package_billing,
            package_billing_contract_id=package_billing_contract_id,
            cloud_config=cloud_config,
            script_content=script_content,
            params=params,
            cloud_pool_id=cloud_pool_id,
            vpc_id=vpc_id,
        )
        _add_tag_list(values, tag_list)
        return ServerBuild.from_api(self._post_form(f"cloud/server/build/{server_id}", values))

    def delete_server(
        self,
        server_id: int,
        cancel_billing: bool = False,
        force_password: Optional[str] = None,
        password: Optional[str] = None,
    ) -> int:
        """Delete a cloud server and return the deleted server id.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to delete.
            cancel_billing: Whether to also cancel billing for the server.
            force_password: Optional password that overrides a delete
                confirmation requirement.
            password: Optional account password confirming the delete.
        """
        body: Dict[str, Any] = {}
        if cancel_billing:
            body["cancel_billing"] = True
        if force_password is not None:
            body["force_password"] = force_password
        if password is not None:
            body["password"] = password
        path = f"cloud/server/{server_id}/delete"
        data = self._post_json(path, body)
        deleted_id = _response_int(data, "id") if isinstance(data, Mapping) else 0
        if not deleted_id:
            raise NetActuateError(
                f"delete server {server_id} returned no id",
                method="POST",
                url=path,
                body=data,
            )
        return deleted_id

    def unlink_server(self, server_id: int) -> None:
        """Unlink a billing package from a location without deleting the server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to unlink.
        """
        self._post_form(f"cloud/server/{server_id}/unlink", {})

    def start_server(self, server_id: int, force: Optional[bool] = None) -> None:
        """Boot up a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to start.
            force: Optional flag forcing the start.
        """
        self._post_json(f"cloud/server/{server_id}/start", _server_action_body(force))

    def stop_server(self, server_id: int, force: Optional[bool] = None) -> None:
        """Shut down a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to stop.
            force: Optional flag forcing the shutdown.
        """
        self._post_json(f"cloud/server/{server_id}/shutdown", _server_action_body(force))

    def reboot_server(self, server_id: int, force: Optional[bool] = None) -> None:
        """Reboot a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to reboot.
            force: Optional flag forcing the reboot.
        """
        self._post_json(f"cloud/server/{server_id}/reboot", _server_action_body(force))

    def run_server_fsck(self, server_id: int) -> None:
        """Start a filesystem check on a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to check.
        """
        self._post_form(f"cloud/server/{server_id}/fsck", {})

    def list_server_ipv4(self, server_id: int) -> List[ServerIPAddress]:
        """Return IPv4 addresses attached to a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return [ServerIPAddress.from_api(row) for row in self._get(f"cloud/server/{server_id}/ipv4")]

    def list_server_ipv6(self, server_id: int) -> List[ServerIPAddress]:
        """Return IPv6 addresses attached to a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return [ServerIPAddress.from_api(row) for row in self._get(f"cloud/server/{server_id}/ipv6")]

    def list_server_jobs(self, server_id: int) -> List[JobStatus]:
        """Return queued NQueue jobs for a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return [JobStatus.from_api(row) for row in self._get(f"cloud/server/{server_id}/jobs")]

    def get_server_job(self, server_id: int, job_id: int) -> JobStatus:
        """Return one queued NQueue job for a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            job_id: Job identifier scoped to the server.
        """
        return JobStatus.from_api(self._get(f"cloud/server/{server_id}/jobs/{job_id}"))

    def reconfigure_server_network(self, server_id: int) -> None:
        """Ask the platform to reconfigure network settings for a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        self._post_form(f"cloud/server/{server_id}/netconfig", {})

    def get_server_network_ips(self, server_id: int) -> Any:
        """Return network IPs attached to a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/server/{server_id}/networkips")

    def reset_server_root_password(
        self, server_id: int, root_pass: str, password: Optional[str] = None
    ) -> Any:
        """Reset the root password for a cloud server.

        The API does not define a fixed schema for the response payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            root_pass: New root password to set.
            password: Optional account password confirming the reset.
        """
        body: Dict[str, Any] = {"rootpass": root_pass}
        if password is not None:
            body["password"] = password
        return self._post_json(f"cloud/server/{server_id}/password", body)

    def start_server_rescue(
        self, server_id: int, rescue_pass: str, password: Optional[str] = None
    ) -> Any:
        """Start rescue mode for a cloud server.

        The API does not define a fixed schema for the response payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            rescue_pass: Password to set for the rescue environment.
            password: Optional account password confirming the request.
        """
        body: Dict[str, Any] = {"rescue_pass": rescue_pass}
        if password is not None:
            body["password"] = password
        return self._post_json(f"cloud/server/{server_id}/rescue_start", body)

    def stop_server_rescue(self, server_id: int) -> None:
        """Stop rescue mode for a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        self._post_form(f"cloud/server/{server_id}/rescue_stop", {})

    def get_server_bgp_sessions(self, server_id: int, group_type: str = "") -> Any:
        """Return BGP sessions attached to a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            group_type: Optional BGP group type to filter by.
        """
        path = f"cloud/server/{server_id}/sessions"
        if group_type:
            path = _page_path(path, group_type=group_type)
        return self._get(path)

    def get_server_status(self, server_id: int) -> ServerStatus:
        """Return status for a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return ServerStatus.from_api(self._get(f"cloud/server/{server_id}/status"))

    def start_server_vnc(self, server_id: int) -> Any:
        """Start a VNC session for a cloud server and return its connection details.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._post_json(f"cloud/server/{server_id}/vnc", {})

    def get_server_vnc_status(self, server_id: int) -> Any:
        """Return VNC status for a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/server/vnc-status/{server_id}")

    def get_server_build_status(self, build_id: int) -> ServerBuildStatus:
        """Return the status of an asynchronous cloud server build.

        Parameters:
            build_id: Build identifier returned when the server was queued.
        """
        return ServerBuildStatus.from_api(self._get(f"cloud/server/build_status/{build_id}"))

    def get_server_deployment_info(self, contract_type: str = "") -> Any:
        """Return cloud server deployment metadata.

        The API does not define a fixed schema for this payload.

        Parameters:
            contract_type: Optional contract type to filter deployment info by.
        """
        path = "cloud/server/deploy/info"
        if contract_type:
            path = _page_path(path, contract_type=contract_type)
        return self._get(path)

    def update_server_options(
        self,
        server_id: int,
        fqdn: Optional[str] = None,
        autorescue: Optional[int] = None,
        description: Optional[str] = None,
        vcpus: Optional[int] = None,
        boot: Optional[str] = None,
        kernel_id: Optional[int] = None,
    ) -> Any:
        """Update mutable options for a cloud server.

        The API does not define a fixed schema for the response payload. Only
        the options given are sent, mirroring gona's
        UpdateServerOptionsRequest.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            fqdn: Optional new fully qualified hostname.
            autorescue: Optional autorescue setting.
            description: Optional new description.
            vcpus: Optional new vCPU count.
            boot: Optional new boot device.
            kernel_id: Optional new boot kernel identifier.
        """
        body: Dict[str, Any] = {}
        if fqdn is not None:
            body["fqdn"] = fqdn
        if autorescue is not None:
            body["autorescue"] = autorescue
        if description is not None:
            body["description"] = description
        if vcpus is not None:
            body["vcpus"] = vcpus
        if boot is not None:
            body["boot"] = boot
        if kernel_id is not None:
            body["kernel_id"] = kernel_id
        return self._put_json(f"cloud/options/{server_id}", body)

    def get_scaling_options(
        self,
        server_id: int,
        include_current_plan: Optional[bool] = None,
        min_ram: Optional[int] = None,
        max_ram: Optional[int] = None,
        min_cpus: Optional[int] = None,
        max_cpus: Optional[int] = None,
    ) -> Any:
        """Return scaling options available for a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            include_current_plan: Optional flag including the current plan
                among the returned options.
            min_ram: Optional minimum RAM filter, in MB.
            max_ram: Optional maximum RAM filter, in MB.
            min_cpus: Optional minimum vCPU filter.
            max_cpus: Optional maximum vCPU filter.
        """
        params: Dict[str, Any] = {}
        if include_current_plan is not None:
            params["include_current_plan"] = "true" if include_current_plan else "false"
        if min_ram is not None:
            params["min_ram"] = min_ram
        if max_ram is not None:
            params["max_ram"] = max_ram
        if min_cpus is not None:
            params["min_cpus"] = min_cpus
        if max_cpus is not None:
            params["max_cpus"] = max_cpus
        path = "cloud/scaling/" + str(server_id)
        if params:
            path = _page_path(path, **params)
        return self._get(path)

    def get_server_monthly_bandwidth(self, server_id: int) -> Any:
        """Return monthly bandwidth data for a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/servermonthlybw/{server_id}")

    def get_bandwidth_stats(self, server_id: int, date: str = "") -> Any:
        """Return bandwidth statistics for a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            date: Optional date to scope the statistics to.
        """
        path = f"cloud/bw_stats/{server_id}"
        if date:
            path = _page_path(path, date=date)
        return self._get(path)

    def get_bandwidth_stats_range(self, server_id: int) -> Any:
        """Return bandwidth statistics for a cloud server over the API's default range.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/bw_stats_range/{server_id}")

    def get_ip_limits(self, server_id: int) -> Any:
        """Return IP limits for a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/iplimits/{server_id}")

    def get_cloud_extras(self, server_id: int) -> Any:
        """Return optional extras available for a cloud server package.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/extras/{server_id}")

    def update_cloud_ipv4_reverse_dns(self, address_id: int, reverse: str) -> None:
        """Update reverse DNS for a cloud IPv4 address.

        Parameters:
            address_id: Cloud IPv4 address identifier.
            reverse: New reverse DNS hostname.
        """
        self._put_json(f"cloud/ipv4/{address_id}", {"reverse": reverse})

    def update_cloud_ipv6_reverse_dns(self, address_id: int, reverse: str) -> None:
        """Update reverse DNS for a cloud IPv6 address.

        Parameters:
            address_id: Cloud IPv6 address identifier.
            reverse: New reverse DNS hostname.
        """
        self._put_json(f"cloud/ipv6/{address_id}", {"reverse": reverse})

    def list_kernels(self) -> List[Kernel]:
        """Return boot kernels available for cloud servers."""
        return [Kernel.from_api(row) for row in self._get("cloud/kernels")]

    def get_cloud_location(self, location_id: int) -> CloudLocation:
        """Return one cloud deployment location.

        Parameters:
            location_id: Cloud location identifier.
        """
        return CloudLocation.from_api(self._get(f"cloud/locations/{location_id}"))

    def get_cloud_pool(self, cloud_pool_id: int) -> CloudPool:
        """Return one cloud pool.

        Parameters:
            cloud_pool_id: Cloud pool identifier.
        """
        return CloudPool.from_api(self._get(f"cloud/pools/{cloud_pool_id}"))

    def get_current_server(self) -> Server:
        """Return the cloud server associated with the caller's source IP."""
        return Server.from_api(self._get("cloud/servers/current"))

    def get_unprovisioned_packages(self) -> Any:
        """Return unprovisioned packages available to build.

        The API does not define a fixed schema for this payload.
        """
        return self._get("cloud/servers/unprovisioned")

    def get_cloud_servers_usage_info(self) -> Any:
        """Return usage statistics for cloud servers on the account.

        The API does not define a fixed schema for this payload.
        """
        return self._get("cloud/servers/usage/info")

    def get_virtual_server_contract(self, server_id: int) -> ContractUsage:
        """Return contract data for a virtual server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return ContractUsage.from_api(self._get(f"cloud/servers/{server_id}/contract"))

    def get_server_summary(self, server_id: int) -> Any:
        """Return summary data for a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
        """
        return self._get(f"cloud/serversummary/{server_id}")

    def attempt_ssh_connection(self, mbpkgid: int, username: str, password: str) -> Any:
        """Attempt an SSH login to a cloud server.

        The API does not define a fixed schema for this payload.

        Parameters:
            mbpkgid: vAPI2 mbpkgid server identifier to test.
            username: Username to authenticate with.
            password: Password to authenticate with.
        """
        body = {"mbpkgid": mbpkgid, "username": username, "password": password}
        return self._post_json("cloud/servers/attempt-ssh", body)

    def get_plan_id(self, plan_name: str) -> Any:
        """Return a plan id by plan name.

        The API does not define a fixed schema for this payload.

        Parameters:
            plan_name: Plan code to look up.
        """
        return self._get("cloud/sizes/plan-id/" + quote(plan_name, safe=""))

    def list_deploy_sizes(
        self, location: str, min_cpu: Optional[int] = None, min_ram: Optional[int] = None
    ) -> List[Size]:
        """Return deploy sizes available at a location.

        Parameters:
            location: Location code to list sizes for.
            min_cpu: Optional minimum vCPU filter.
            min_ram: Optional minimum RAM filter, in MB.
        """
        params = _firewall_vm_query_params(min_cpu=min_cpu, min_ram=min_ram)
        path = "cloud/sizes/" + quote(location, safe="")
        if params:
            path = _page_path(path, **params)
        return [Size.from_api(row) for row in self._get(path)]

    def get_cloud_storage_locations(self, cloud_pool_id: Optional[int] = None) -> Any:
        """Return cloud storage locations.

        The API does not define a fixed schema for this payload.

        Parameters:
            cloud_pool_id: Optional cloud pool identifier to filter by.
        """
        path = "cloud/storage-locations"
        if cloud_pool_id is not None:
            path = _page_path(path, cloud_pool_id=cloud_pool_id)
        return self._get(path)

    def bind_cloud_firewall_set(
        self, server_id: int, firewall_set_id: int, interface_id: int, set_priority: int
    ) -> Any:
        """Bind a firewall set to a cloud server interface.

        The API does not define a fixed schema for this payload.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            firewall_set_id: Firewall set identifier to bind.
            interface_id: Server interface identifier to bind the set to.
            set_priority: Priority to apply the bound set with.
        """
        body = {
            "firewall_set_id": firewall_set_id,
            "interface_id": interface_id,
            "set_priority": set_priority,
        }
        return self._post_json(f"cloud/{server_id}/firewall-sets", body)

    def unbind_cloud_firewall_set(self, server_id: int, firewall_set: str) -> None:
        """Unbind a firewall set from a cloud server.

        Parameters:
            server_id: vAPI2 mbpkgid server identifier.
            firewall_set: Firewall set identifier or name to unbind.
        """
        self._delete(f"cloud/{server_id}/firewall-sets/{quote(firewall_set, safe='')}")

    def create_usage_contract(self, mb_id: int) -> ContractUsage:
        """Create a usage contract for an account.

        Parameters:
            mb_id: Account identifier to create the usage contract for.
        """
        return ContractUsage.from_api(self._post_json("cloud/contract/usage", {"mb_id": mb_id}))

    def parse_cloud_init(self, filename: str, content: bytes) -> Any:
        """Upload and parse a cloud-init script.

        The API does not define a fixed schema for this payload.

        Parameters:
            filename: Name reported for the uploaded file.
            content: Raw cloud-init script content.
        """
        return self._post_multipart("cloud/parse-cloud-init", filename, content)

    def scale_server(
        self, server_id: int, pkg_name: str = "", pkg_id: int = 0, allow_reboot: bool = False
    ) -> int:
        """Change a cloud server's plan and return the NQueue job id.

        Poll the result with get_job_status("scale_vm", job_id).

        Parameters:
            server_id: vAPI2 mbpkgid server identifier to scale.
            pkg_name: New plan package name, when scaling by name.
            pkg_id: New plan package identifier, when scaling by id.
            allow_reboot: Whether the server may be rebooted to apply the scale.
        """
        body: Dict[str, Any] = {"allow_reboot": allow_reboot}
        if pkg_name:
            body["pkg_name"] = pkg_name
        if pkg_id:
            body["pkg_id"] = pkg_id
        return int(self._post_json(f"cloud/scale/{server_id}", body))

    def get_job_status(self, command: str, job_id: int) -> JobStatus:
        """Return the status of an NQueue job.

        Parameters:
            command: NQueue command name the job was queued under, for
                example "scale_vm".
            job_id: Job identifier returned when the job was queued.
        """
        return JobStatus.from_api(self._get(f"cloud/jobs/{command}/{job_id}"))

    def list_services(self) -> List[Service]:
        """Return all account services."""
        return [Service.from_api(row) for row in self._get("services")]

    def list_colocation_services(self, service_id: Optional[int] = None) -> List[ColocationService]:
        """Return colocation services, optionally filtered by service id.

        Parameters:
            service_id: Optional top-level service identifier to filter by.
        """
        path = "services/colocation"
        if service_id is not None:
            path = _page_path(path, service_id=service_id)
        return [ColocationService.from_api(row) for row in self._get(path)]

    def get_colocation_service(self, service_id: int) -> ColocationService:
        """Return one colocation service.

        Parameters:
            service_id: Colocation service identifier.
        """
        return ColocationService.from_api(self._get(f"services/colocation/{service_id}"))

    def list_iptransit_services(self, service_id: Optional[int] = None) -> List[IPTransitService]:
        """Return IP transit services, optionally filtered by service id.

        Parameters:
            service_id: Optional top-level service identifier to filter by.
        """
        path = "services/iptransit"
        if service_id is not None:
            path = _page_path(path, service_id=service_id)
        return [IPTransitService.from_api(row) for row in self._get(path)]

    def get_iptransit_service(self, service_id: int) -> IPTransitService:
        """Return one IP transit service.

        Parameters:
            service_id: IP transit service identifier.
        """
        return IPTransitService.from_api(self._get(f"services/iptransit/{service_id}"))

    def list_iptransit_ip_addresses(
        self, service_iptransit_id: Optional[int] = None
    ) -> List[IPTransitIPAddress]:
        """Return IP transit IP addresses, optionally filtered by service id.

        Parameters:
            service_iptransit_id: Optional IP transit service identifier to filter by.
        """
        path = "services/iptransit/ips"
        if service_iptransit_id is not None:
            path = _page_path(path, service_iptransit_id=service_iptransit_id)
        return [IPTransitIPAddress.from_api(row) for row in self._get(path)]

    def list_iptransit_ports(self, service_iptransit_id: Optional[int] = None) -> List[IPTransitPort]:
        """Return IP transit ports, optionally filtered by IP transit service id.

        Parameters:
            service_iptransit_id: Optional IP transit service identifier to filter by.
        """
        path = "services/iptransit/ports"
        if service_iptransit_id is not None:
            path = _page_path(path, service_iptransit_id=service_iptransit_id)
        return [IPTransitPort.from_api(row) for row in self._get(path)]

    def list_transport_services(self, service_id: Optional[int] = None) -> List[TransportService]:
        """Return transport services, optionally filtered by service id.

        Parameters:
            service_id: Optional top-level service identifier to filter by.
        """
        path = "services/transport"
        if service_id is not None:
            path = _page_path(path, service_id=service_id)
        return [TransportService.from_api(row) for row in self._get(path)]

    def get_transport_service(self, service_id: int) -> TransportService:
        """Return one transport service.

        Parameters:
            service_id: Transport service identifier.
        """
        return TransportService.from_api(self._get(f"services/transport/{service_id}"))

    def list_transport_ports(self, service_transport_id: Optional[int] = None) -> List[TransportPort]:
        """Return transport ports, optionally filtered by transport service id.

        Parameters:
            service_transport_id: Optional transport service identifier to filter by.
        """
        path = "services/transport/ports"
        if service_transport_id is not None:
            path = _page_path(path, service_transport_id=service_transport_id)
        return [TransportPort.from_api(row) for row in self._get(path)]

    def get_platform_status(self) -> List[PlatformStatusService]:
        """Return platform component status grouped by service and location."""
        return _decode_platform_status(self._get("platform/status"))

    def list_platform_change_log(self) -> List[PlatformChangeLogEntry]:
        """Return the platform change log."""
        return [PlatformChangeLogEntry.from_api(row) for row in self._get("platform/change-log")]

    def get_platform_change_log_entry(self, entry_id: int) -> PlatformChangeLogEntry:
        """Return one platform change log entry.

        Parameters:
            entry_id: Change log entry identifier.
        """
        return PlatformChangeLogEntry.from_api(self._get(f"platform/change-log/{entry_id}"))

    def list_platform_datacenters(self, location: str) -> List[Datacenter]:
        """Return datacenters for a location.

        Parameters:
            location: Location code to list datacenters for.
        """
        path = f"platform/datacenters/{quote(location, safe='')}"
        return [Datacenter.from_api(row) for row in self._get(path)]

    def get_platform_looking_glass_init(self) -> PlatformLookingGlassInit:
        """Return the options used to initialize looking glass calls."""
        return PlatformLookingGlassInit.from_api(self._get("platform/looking-glass/init"))

    def execute_platform_looking_glass(
        self,
        action: Optional[str] = None,
        target: Optional[str] = None,
        location: Optional[str] = None,
        full: Optional[int] = None,
    ) -> PlatformLookingGlassResult:
        """Execute a looking glass action.

        Parameters:
            action: Optional looking glass action, for example "ping" or "traceroute".
            target: Optional target host or address.
            location: Optional location to execute the action from.
            full: Optional flag requesting full output.
        """
        path = "platform/looking-glass/execute"
        params: Dict[str, Any] = {}
        if action is not None:
            params["action"] = action
        if target is not None:
            params["target"] = target
        if location is not None:
            params["location"] = location
        if full is not None:
            params["full"] = full
        if params:
            path = _page_path(path, **params)
        return PlatformLookingGlassResult.from_api(self._get(path))

    def get_platform_maintenance_info(self, maintenance_id: int) -> PlatformMaintenanceInfo:
        """Return maintenance detail by id.

        Parameters:
            maintenance_id: Maintenance detail identifier.
        """
        return PlatformMaintenanceInfo.from_api(self._get(f"platform/maintenance-info/{maintenance_id}"))

    def get_platform_incidents(self, location: str) -> PlatformEvents:
        """Return active, upcoming and historic incidents for a location.

        Parameters:
            location: Location code to report incidents for.
        """
        return PlatformEvents.from_api(self._get(f"platform/incidents/{quote(location, safe='')}"))

    def get_platform_incident_history(self, location: str) -> PlatformEvents:
        """Return incident history for a location.

        Parameters:
            location: Location code to report incident history for.
        """
        path = f"platform/incidents/history/{quote(location, safe='')}"
        return PlatformEvents.from_api(self._get(path))

    def get_platform_maintenance(self, location: str) -> PlatformEvents:
        """Return active, upcoming and historic maintenance for a location.

        Parameters:
            location: Location code to report maintenance for.
        """
        return PlatformEvents.from_api(self._get(f"platform/maintenance/{quote(location, safe='')}"))

    def get_platform_maintenance_history(self, location: str) -> PlatformEvents:
        """Return maintenance history for a location.

        Parameters:
            location: Location code to report maintenance history for.
        """
        path = f"platform/maintenance/history/{quote(location, safe='')}"
        return PlatformEvents.from_api(self._get(path))

    def list_zones(self, zone_type: str = "") -> List[DNSZone]:
        """Return DNS zones.

        Parameters:
            zone_type: Optional vAPI2 zone type filter.
        """
        path = "dns/zones"
        if zone_type:
            path = _page_path(path, type=zone_type)
        return [DNSZone.from_api(row) for row in self._get(path)]

    def get_zone(self, zone_id: int) -> DNSZone:
        """Return one DNS zone.

        Parameters:
            zone_id: DNS zone identifier.
        """
        return DNSZone.from_api(self._get(f"dns/zone/{zone_id}"))

    def list_records(self, zone_id: int) -> List[DNSRecord]:
        """Return DNS records for a zone.

        Parameters:
            zone_id: DNS zone identifier.
        """
        return [DNSRecord.from_api(row) for row in self._get(f"dns/records/{zone_id}")]

    def get_record(self, record_id: int) -> DNSRecord:
        """Return one DNS record.

        Parameters:
            record_id: DNS record identifier.
        """
        return DNSRecord.from_api(self._get(f"dns/record/{record_id}"))

    def create_zone(self, name: str, zone_type: str, ip: str = "") -> DNSZone:
        """Create a DNS zone.

        Parameters:
            name: Zone name.
            zone_type: Zone type, for example "master" or "geodns".
            ip: Optional IP to seed a default record with.
        """
        values: Dict[str, Any] = {"name": name, "type": zone_type}
        if ip:
            values["ip"] = ip
        return DNSZone.from_api(self._post_form("dns/zone", values))

    def delete_zone(self, zone_id: int) -> None:
        """Delete a DNS zone.

        Parameters:
            zone_id: DNS zone identifier.
        """
        self._delete(f"dns/zone/{zone_id}")

    def create_record(
        self,
        zone_id: int,
        record_type: str,
        record_content: str,
        name: str = "",
        ttl: int = 0,
        priority: int = 0,
    ) -> DNSRecord:
        """Create a DNS record in a zone.

        Parameters:
            zone_id: DNS zone identifier the record belongs to.
            record_type: Record type, for example "A" or "MX".
            record_content: Record content, for example an IP address.
            name: Record name. Empty means the zone apex.
            ttl: Optional TTL in seconds. Zero leaves the zone default.
            priority: Optional priority, used by MX and SRV records.
        """
        values: Dict[str, Any] = {
            "domain_id": zone_id,
            "name": name,
            "type": record_type,
            "record_content": record_content,
        }
        if ttl:
            values["ttl"] = ttl
        if priority:
            values["prio"] = priority
        return DNSRecord.from_api(self._post_form("dns/record", values))

    def update_record(
        self,
        record_id: int,
        zone_id: int,
        record_type: str,
        record_content: str,
        name: str = "",
        ttl: int = 0,
        priority: int = 0,
    ) -> DNSRecord:
        """Update a DNS record.

        Parameters:
            record_id: DNS record identifier to update.
            zone_id: DNS zone identifier the record belongs to.
            record_type: Record type, for example "A" or "MX".
            record_content: Record content, for example an IP address.
            name: Record name. Empty means the zone apex.
            ttl: Optional TTL in seconds. Zero leaves the zone default.
            priority: Optional priority, used by MX and SRV records.
        """
        values: Dict[str, Any] = {
            "id": record_id,
            "domain_id": zone_id,
            "name": name,
            "type": record_type,
            "record_content": record_content,
        }
        if ttl:
            values["ttl"] = ttl
        if priority:
            values["prio"] = priority
        return DNSRecord.from_api(self._put_form("dns/record", values))

    def delete_record(self, record_id: int) -> None:
        """Delete a DNS record.

        Parameters:
            record_id: DNS record identifier.
        """
        self._delete(f"dns/record/{record_id}")

    def list_tags(self) -> List[Tag]:
        """Return every tag, with each tag's resource assignments embedded."""
        return [Tag.from_api(row) for row in self._get("tags")]

    def get_tag(self, tag_id: int) -> Tag:
        """Return one tag by id.

        There is no single-tag endpoint, so this filters the full tag list.

        Parameters:
            tag_id: Tag identifier.
        """
        for tag in self.list_tags():
            if tag.id == tag_id:
                return tag
        raise NotFoundError(
            f"tag {tag_id} not found",
            method="GET",
            url="tags",
            status_code=404,
            code=404,
        )

    def create_tag(self, name: str, description: str = "", icon: str = "", color: str = "") -> Tag:
        """Create a tag.

        Parameters:
            name: Tag name.
            description: Optional tag description.
            icon: Optional icon identifier.
            color: Optional color identifier.
        """
        body: Dict[str, Any] = {"name": name}
        if description:
            body["description"] = description
        if icon:
            body["icon"] = icon
        if color:
            body["color"] = color
        return Tag.from_api(self._post_json("tags", body))

    def update_tag(
        self,
        tag_id: int,
        name: str,
        description: str = "",
        icon: str = "",
        color: str = "",
        is_default: bool = False,
        is_favorite: bool = False,
        is_locked: bool = False,
        show_dashboard: bool = False,
    ) -> Tag:
        """Update a tag's name, description, icon, color and flags.

        Parameters:
            tag_id: Tag identifier to update.
            name: Tag name.
            description: Optional tag description.
            icon: Optional icon identifier.
            color: Optional color identifier.
            is_default: Whether the tag is applied to new resources by default.
            is_favorite: Whether the tag is marked as a favorite.
            is_locked: Whether the tag is locked against deletion.
            show_dashboard: Whether the tag is shown on the dashboard.
        """
        body: Dict[str, Any] = {
            "name": name,
            "is_default": int(is_default),
            "is_favorite": int(is_favorite),
            "is_locked": int(is_locked),
            "show_dashboard": int(show_dashboard),
        }
        if description:
            body["description"] = description
        if icon:
            body["icon"] = icon
        if color:
            body["color"] = color
        return Tag.from_api(self._put_json(f"tags/{tag_id}", body))

    def delete_tag(self, tag_id: int) -> None:
        """Delete a tag.

        The API refuses to delete a tag that is locked or still assigned to a
        resource, which surfaces as a `NetActuateError`.

        Parameters:
            tag_id: Tag identifier.
        """
        self._delete(f"tags/{tag_id}")

    def assign_tag_resource(self, tag_id: int, resource_name: str, identifier: int) -> None:
        """Attach a tag to a resource. The API treats this as idempotent.

        Parameters:
            tag_id: Tag identifier.
            resource_name: Resource type name, for example "server" or "nke_cluster".
            identifier: Resource's own numeric identifier.
        """
        body = {"resource_name": resource_name, "identifier": str(identifier)}
        self._post_json(f"tags/{tag_id}/assign-resource", body)

    def remove_tag_resource(self, tag_id: int, resource_name: str, identifier: int) -> None:
        """Detach a tag from a resource without deleting the tag itself.

        Parameters:
            tag_id: Tag identifier.
            resource_name: Resource type name, for example "server" or "nke_cluster".
            identifier: Resource's own numeric identifier.
        """
        body = {"resource_name": resource_name, "identifier": str(identifier)}
        self._post_json(f"tags/{tag_id}/remove-resource", body)

    def get_resource_tags(self, resource_name: str, resource_id: int) -> List[Tag]:
        """Return the tags currently assigned to a resource.

        Parameters:
            resource_name: Resource type name, for example "server" or "nke_cluster".
            resource_id: Resource's own numeric identifier.
        """
        path = f"tags/resource/{quote(resource_name, safe='')}/id/{resource_id}"
        return [Tag.from_api(row) for row in self._get(path)]

    def get_tag_resources(self, tag_id: int) -> List[TagResource]:
        """Return the resources currently assigned to a tag.

        Parameters:
            tag_id: Tag identifier.
        """
        return [TagResource.from_api(row) for row in self._get(f"tags/{tag_id}/resources")]

    def get_tag_logs(self, tag_id: int) -> List[TagLog]:
        """Return the log entries recorded for a tag.

        Parameters:
            tag_id: Tag identifier.
        """
        return [TagLog.from_api(row) for row in self._get(f"tags/{tag_id}/logs")]

    def list_ssh_keys(self) -> List[SSHKey]:
        """Return all SSH keys installed for the account."""
        return [SSHKey.from_api(row) for row in self._get("account/ssh_keys")]

    def get_ssh_key(self, key_id: int) -> SSHKey:
        """Return one SSH key.

        vAPI2 answers a missing key with HTTP 200 and a null `data` member
        rather than a 404 or a validation error, so a null or id-less payload
        here is treated as not found rather than as an empty key.

        Parameters:
            key_id: SSH key identifier.
        """
        path = f"account/ssh_key/{key_id}"
        data = self._get(path)
        if not isinstance(data, Mapping) or not data.get("id"):
            raise NotFoundError(
                f"ssh key {key_id} returned no data, so it does not exist",
                method="GET",
                url=path,
                status_code=200,
                code=200,
            )
        return SSHKey.from_api(data)

    def create_ssh_key(self, name: str, key: str) -> SSHKey:
        """Create an SSH key.

        Parameters:
            name: Display name for the key.
            key: Public key content.
        """
        values = {"ssh_key": key, "name": name}
        return SSHKey.from_api(self._post_form("account/ssh_key", values))

    def update_ssh_key(self, key_id: int, name: str, key: str) -> SSHKey:
        """Update an SSH key's name and content.

        Parameters:
            key_id: SSH key identifier to update.
            name: Display name for the key.
            key: Public key content.
        """
        body = {"name": name, "ssh_key": key}
        return SSHKey.from_api(self._patch_json(f"account/ssh_key/{key_id}", body))

    def delete_ssh_key(self, key_id: int) -> None:
        """Delete an SSH key.

        Parameters:
            key_id: SSH key identifier.
        """
        self._delete(f"account/ssh_key/{key_id}")

    def list_firewall_external_ip_sets(self) -> List[FirewallExternalIPSet]:
        """Return the external IP sets usable in firewall match criteria."""
        return [FirewallExternalIPSet.from_api(row) for row in self._get("firewall/external-ipsets")]

    def get_firewall_external_ip_set(self, ip_set_id: int) -> FirewallExternalIPSet:
        """Return one external IP set.

        Parameters:
            ip_set_id: External IP set identifier.
        """
        return FirewallExternalIPSet.from_api(self._get(f"firewall/external-ipsets/{ip_set_id}"))

    def get_firewall_manage_enabled(self) -> FirewallManageEnabled:
        """Return whether cloud firewall management is available for the account."""
        return FirewallManageEnabled.from_api(self._get("firewall/manage/enabled"))

    def list_firewall_sets(self) -> List[FirewallSet]:
        """Return all cloud firewall sets visible to the account."""
        return [FirewallSet.from_api(row) for row in self._get("firewall/sets")]

    def get_firewall_set(self, set_id: int) -> FirewallSet:
        """Return one cloud firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        return FirewallSet.from_api(self._get(f"firewall/sets/{set_id}"))

    def create_firewall_set(self, name: str, description: str = "", enabled: bool = True) -> FirewallSet:
        """Create a cloud firewall set.

        Parameters:
            name: Firewall set name.
            description: Firewall set description.
            enabled: Whether the firewall set is enabled on creation.
        """
        values = {"name": name, "description": description, "enabled": "1" if enabled else "0"}
        return FirewallSet.from_api(self._post_form("firewall/sets", values))

    def update_firewall_set(self, set_id: int, name: str, description: str = "", enabled: bool = True) -> FirewallSet:
        """Update a cloud firewall set's name, description and enabled flag.

        Parameters:
            set_id: Firewall set identifier to update.
            name: Firewall set name.
            description: Firewall set description.
            enabled: Whether the firewall set is enabled.
        """
        values = {"name": name, "description": description, "enabled": "1" if enabled else "0"}
        return FirewallSet.from_api(self._put_form(f"firewall/sets/{set_id}", values))

    def delete_firewall_set(self, set_id: int) -> None:
        """Delete a cloud firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        self._delete(f"firewall/sets/{set_id}")

    def enable_firewall_set(self, set_id: int) -> None:
        """Enable a cloud firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        self._put_form(f"firewall/sets/{set_id}/enable", {})

    def disable_firewall_set(self, set_id: int) -> None:
        """Disable a cloud firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        self._put_form(f"firewall/sets/{set_id}/disable", {})

    def create_draft_firewall_set(self, set_id: int) -> FirewallSet:
        """Create an editable draft copy of a firewall set.

        Parameters:
            set_id: Firewall set identifier to branch a draft from.
        """
        return FirewallSet.from_api(self._post_form(f"firewall/sets/{set_id}/create-draft", {}))

    def publish_draft_firewall_set(self, draft_id: int) -> FirewallSet:
        """Publish a draft firewall set over its parent set.

        Parameters:
            draft_id: Draft firewall set identifier to publish.
        """
        return FirewallSet.from_api(self._post_form(f"firewall/sets/publish-draft/{draft_id}", {}))

    def delete_draft_firewall_set(self, draft_id: int) -> None:
        """Discard a draft firewall set without publishing it.

        Parameters:
            draft_id: Draft firewall set identifier to discard.
        """
        self._delete(f"firewall/sets/delete-draft/{draft_id}")

    def sync_firewall_set_rules(self, set_id: int) -> None:
        """Push a firewall set's current rules to every attached VM.

        Parameters:
            set_id: Firewall set identifier.
        """
        self._post_form(f"firewall/sets/{set_id}/vm/sync-all", {})

    def list_firewall_rules(self, set_id: int) -> List[FirewallRule]:
        """Return all rules in a firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        return [FirewallRule.from_api(row) for row in self._get(f"firewall/sets/{set_id}/rules")]

    def reorder_firewall_rules(
        self, set_id: int, move_id: int, after_id: Optional[int] = None, before_id: Optional[int] = None
    ) -> None:
        """Move a rule to a new position within a draft firewall set.

        Exactly one of `after_id` or `before_id` should be given to say
        where the moved rule lands.

        Parameters:
            set_id: Firewall set identifier the rule belongs to.
            move_id: Firewall rule identifier to move.
            after_id: Optional rule identifier the moved rule should follow.
            before_id: Optional rule identifier the moved rule should precede.
        """
        body: Dict[str, Any] = {"move_id": move_id}
        if after_id is not None:
            body["after_id"] = after_id
        if before_id is not None:
            body["before_id"] = before_id
        self._post_json(f"firewall/sets/{set_id}/rules/re-order", body)

    def get_firewall_rule(self, set_id: int, rule_id: int) -> FirewallRule:
        """Return one rule from a firewall set.

        Parameters:
            set_id: Firewall set identifier the rule belongs to.
            rule_id: Firewall rule identifier.
        """
        return FirewallRule.from_api(self._get(f"firewall/sets/{set_id}/rules/{rule_id}"))

    def create_firewall_rule(
        self,
        set_id: int,
        ip_version: str,
        action: str,
        enabled: bool,
        direction: str = "",
        rule_priority: Optional[int] = None,
        admin_comment: str = "",
        match_criteria: Optional[Mapping[str, Any]] = None,
    ) -> FirewallRule:
        """Create a rule in a firewall set.

        Parameters:
            set_id: Firewall set identifier to create the rule in.
            ip_version: IP version the rule matches, for example "ipv4" or "ipv6".
            action: Action the rule takes, for example "accept" or "drop".
            enabled: Whether the rule is enabled.
            direction: Optional traffic direction, for example "inbound" or "outbound".
            rule_priority: Optional explicit rule priority.
            admin_comment: Optional operator-facing comment.
            match_criteria: Optional match criteria block, passed through as
                the API expects it, for example protocol, source_net,
                destination_net and port range fields.
        """
        body = _firewall_rule_body(
            ip_version, action, enabled, direction, rule_priority, admin_comment, match_criteria
        )
        return FirewallRule.from_api(self._post_json(f"firewall/sets/{set_id}/rules", body))

    def update_firewall_rule(
        self,
        set_id: int,
        rule_id: int,
        ip_version: str,
        action: str,
        enabled: bool,
        direction: str = "",
        rule_priority: Optional[int] = None,
        admin_comment: str = "",
        match_criteria: Optional[Mapping[str, Any]] = None,
    ) -> FirewallRule:
        """Update a rule in a firewall set.

        Parameters:
            set_id: Firewall set identifier the rule belongs to.
            rule_id: Firewall rule identifier to update.
            ip_version: IP version the rule matches, for example "ipv4" or "ipv6".
            action: Action the rule takes, for example "accept" or "drop".
            enabled: Whether the rule is enabled.
            direction: Optional traffic direction, for example "inbound" or "outbound".
            rule_priority: Optional explicit rule priority.
            admin_comment: Optional operator-facing comment.
            match_criteria: Optional match criteria block, passed through as
                the API expects it, for example protocol, source_net,
                destination_net and port range fields.
        """
        body = _firewall_rule_body(
            ip_version, action, enabled, direction, rule_priority, admin_comment, match_criteria
        )
        return FirewallRule.from_api(self._put_json(f"firewall/{set_id}/{rule_id}", body))

    def delete_firewall_rule(self, set_id: int, rule_id: int) -> None:
        """Delete a rule from a firewall set.

        Parameters:
            set_id: Firewall set identifier the rule belongs to.
            rule_id: Firewall rule identifier to delete.
        """
        self._delete(f"firewall/{set_id}/rules/{rule_id}")

    def list_firewall_set_vms(self, set_id: int) -> List[FirewallSetVM]:
        """Return the VMs attached to a firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        return [FirewallSetVM.from_api(row) for row in self._get(f"firewall/sets/{set_id}/vm-list")]

    def list_firewall_set_available_vms(
        self,
        set_id: int,
        extref_account_id: Optional[int] = None,
        vpc_id: Optional[int] = None,
        include_bandwidth: Optional[bool] = None,
        include_ul: Optional[bool] = None,
        check_vpc: Optional[bool] = None,
        disable_interface_id_filter: Optional[bool] = None,
    ) -> List[FirewallSetVM]:
        """Return the VMs that can be attached to a firewall set.

        Parameters:
            set_id: Firewall set identifier.
            extref_account_id: Optional external reference account identifier to filter by.
            vpc_id: Optional VPC identifier to filter by.
            include_bandwidth: Optional flag including bandwidth-only VMs.
            include_ul: Optional flag including unlimited-bandwidth VMs.
            check_vpc: Optional flag restricting results to the given VPC.
            disable_interface_id_filter: Optional flag disabling the interface id filter.
        """
        path = f"firewall/sets/{set_id}/available-vm-list"
        params = _firewall_vm_query_params(
            extref_acct_id=extref_account_id,
            vpc_id=vpc_id,
            bw=include_bandwidth,
            ul=include_ul,
            check_vpc=check_vpc,
            disable_interface_id_filter=disable_interface_id_filter,
        )
        if params:
            path = _page_path(path, **params)
        return [FirewallSetVM.from_api(row) for row in self._get(path)]

    def list_firewall_set_related_vms(
        self, mbpkgid: int, disable_interface_id_filter: Optional[bool] = None
    ) -> List[FirewallSetVM]:
        """Return the firewall set attachments for a VM.

        Parameters:
            mbpkgid: VM package identifier.
            disable_interface_id_filter: Optional flag disabling the interface id filter.
        """
        path = f"firewall/sets/vm/{mbpkgid}/related"
        params = _firewall_vm_query_params(disable_interface_id_filter=disable_interface_id_filter)
        if params:
            path = _page_path(path, **params)
        return [FirewallSetVM.from_api(row) for row in self._get(path)]

    def attach_firewall_set_vm(
        self, set_id: int, mbpkgid: int, interface_id: int, set_priority: int
    ) -> List[FirewallSetVM]:
        """Attach a VM interface to a firewall set.

        Parameters:
            set_id: Firewall set identifier to attach to.
            mbpkgid: VM package identifier to attach.
            interface_id: VM network interface identifier to attach.
            set_priority: Priority of this firewall set on the VM interface.
        """
        body = {
            "vm_list": [
                {"mbpkgid": mbpkgid, "interface_id": interface_id, "set_priority": set_priority}
            ]
        }
        return [
            FirewallSetVM.from_api(row)
            for row in self._post_json(f"firewall/sets/{set_id}/vm/attach", body)
        ]

    def detach_firewall_set_vm(self, set_id: int, mbpkgid: int) -> None:
        """Detach a VM from a firewall set.

        Parameters:
            set_id: Firewall set identifier.
            mbpkgid: VM package identifier to detach.
        """
        self._post_form(f"firewall/sets/{set_id}/vm/detach/{mbpkgid}", {})

    def detach_firewall_set_vm_relation(self, relation_id: int) -> None:
        """Detach a VM from a firewall set by attachment relation id.

        Parameters:
            relation_id: Firewall set VM attachment relation identifier.
        """
        self._post_form(f"firewall/sets/vm/detach/{relation_id}", {})

    def detach_all_firewall_set_vms(self, set_id: int) -> None:
        """Detach every VM from a firewall set.

        Parameters:
            set_id: Firewall set identifier.
        """
        self._post_form(f"firewall/sets/{set_id}/vm/detach-all", {})

    def list_vlans(self) -> List[VLAN]:
        """Return all customer VLANs visible to the account."""
        return [VLAN.from_api(row) for row in self._get("cloud/networking/vlans")]

    def get_customer_vlan(self, customer_vlan_id: int) -> VLAN:
        """Return one customer VLAN.

        Parameters:
            customer_vlan_id: Customer VLAN identifier.
        """
        return VLAN.from_api(self._get(f"cloud/networking/vlans/{customer_vlan_id}"))

    def list_customer_vlans_at_location(self, location_id: int) -> List[VLAN]:
        """Return customer VLANs provisioned at a location.

        Parameters:
            location_id: Location identifier.
        """
        return [
            VLAN.from_api(row) for row in self._get(f"cloud/networking/locations/{location_id}/vlans")
        ]

    def list_server_nics(self, mbpkg_id: int) -> List[ServerNIC]:
        """Return the network interfaces attached to a server.

        Parameters:
            mbpkg_id: vAPI2 `mbpkgid` server identifier.
        """
        return [ServerNIC.from_api(row) for row in self._get(f"cloud/networking/nics/{mbpkg_id}")]

    def attach_server_nic(self, mbpkg_id: int, customer_vlan_id: int) -> ServerNIC:
        """Attach a new network interface on a customer VLAN to a server.

        Parameters:
            mbpkg_id: vAPI2 `mbpkgid` server identifier to attach the interface to.
            customer_vlan_id: Customer VLAN identifier to attach.
        """
        body = {"customer_vlan_id": customer_vlan_id}
        return _decode_server_nic(self._post_json(f"cloud/networking/nics/{mbpkg_id}", body))

    def update_server_nic(
        self, nic_id: int, mbpkg_id: int, customer_vlan_id: int, attach_order: int
    ) -> ServerNIC:
        """Update a server network interface's VLAN and attach order.

        Parameters:
            nic_id: Network interface identifier to update.
            mbpkg_id: vAPI2 `mbpkgid` server identifier the interface belongs to.
            customer_vlan_id: Customer VLAN identifier to attach.
            attach_order: Position of the interface among the server's interfaces.
        """
        body = {
            "mbpkgid": mbpkg_id,
            "customer_vlan_id": customer_vlan_id,
            "attach_order": attach_order,
        }
        return _decode_server_nic(self._put_json(f"cloud/networking/nics/{nic_id}", body))

    def detach_server_nic(self, mbpkg_id: int, nic_id: int) -> None:
        """Detach a network interface from a server.

        Parameters:
            mbpkg_id: vAPI2 `mbpkgid` server identifier the interface belongs to.
            nic_id: Network interface identifier to detach.
        """
        self._delete(_page_path(f"cloud/networking/nics/{nic_id}", mbpkgid=mbpkg_id))

    def list_legacy_tickets(self) -> List[Ticket]:
        """Return archived legacy support tickets."""
        return [Ticket.from_api(row) for row in self._get("support/legacy-tickets")]

    def list_tickets(
        self, open_: Optional[str] = None, include_stats: Optional[str] = None
    ) -> List[Ticket]:
        """Return support tickets, optionally filtered.

        Parameters:
            open_: Optional open state filter.
            include_stats: Optional flag requesting ticket statistics be included.
        """
        path = _ticket_list_path("support/tickets", open_, include_stats)
        return [Ticket.from_api(row) for row in self._get(path)]

    def create_ticket(
        self,
        subject: str,
        message: str,
        department: int,
        urgency: str = "",
        files: Optional[Sequence[str]] = None,
    ) -> Ticket:
        """Create a support ticket.

        Parameters:
            subject: Ticket subject line.
            message: Initial ticket message body.
            department: Department identifier to route the ticket to.
            urgency: Optional urgency level.
            files: Optional attachment references to include.
        """
        body: Dict[str, Any] = {"subject": subject, "message": message, "department": department}
        if urgency:
            body["urgency"] = urgency
        if files:
            body["files"] = list(files)
        return Ticket.from_api(self._post_json("support/tickets", body))

    def list_old_tickets(
        self, open_: Optional[str] = None, include_stats: Optional[str] = None
    ) -> List[Ticket]:
        """Return legacy support tickets, optionally filtered.

        Parameters:
            open_: Optional open state filter.
            include_stats: Optional flag requesting ticket statistics be included.
        """
        path = _ticket_list_path("support/tickets-old", open_, include_stats)
        return [Ticket.from_api(row) for row in self._get(path)]

    def get_old_ticket(self, ticket_id: str) -> Ticket:
        """Return one legacy support ticket by id.

        Parameters:
            ticket_id: Legacy support ticket identifier.
        """
        return Ticket.from_api(self._get(f"support/tickets-old/{quote(ticket_id, safe='')}"))

    def list_ticket_departments(self) -> List[TicketDepartment]:
        """Return the support ticket departments."""
        return [
            TicketDepartment.from_api(row) for row in self._get("support/tickets/departments")
        ]

    def get_ticket(self, ticket_id: str) -> Ticket:
        """Return one support ticket by id.

        Parameters:
            ticket_id: Support ticket identifier.
        """
        return Ticket.from_api(self._get(f"support/tickets/{quote(ticket_id, safe='')}"))

    def list_ticket_replies(self, ticket_id: str) -> List[TicketReply]:
        """Return the replies recorded on a support ticket.

        Parameters:
            ticket_id: Support ticket identifier.
        """
        path = f"support/tickets/{quote(ticket_id, safe='')}/replies"
        return [TicketReply.from_api(row) for row in self._get(path)]

    def get_ticket_attachment(
        self,
        ticket_id: str,
        attachment_type: str,
        rel_id: str,
        index: int,
        without_data: Optional[int] = None,
    ) -> TicketAttachment:
        """Return metadata for a support ticket or reply attachment.

        Parameters:
            ticket_id: Support ticket identifier the attachment belongs to.
            attachment_type: Attachment owner type, for example "ticket" or "reply".
            rel_id: Identifier of the ticket or reply the attachment belongs to.
            index: Zero based attachment index.
            without_data: Optional flag suppressing the attachment's inline data.
        """
        path = _ticket_attachment_path(ticket_id, attachment_type, rel_id, index)
        if without_data is not None:
            path = _page_path(path, without_data=without_data)
        return TicketAttachment.from_api(self._get(path))

    def download_ticket_attachment(
        self, ticket_id: str, attachment_type: str, rel_id: str, index: int
    ) -> bytes:
        """Return the binary content of a support ticket or reply attachment.

        Parameters:
            ticket_id: Support ticket identifier the attachment belongs to.
            attachment_type: Attachment owner type, for example "ticket" or "reply".
            rel_id: Identifier of the ticket or reply the attachment belongs to.
            index: Zero based attachment index.
        """
        path = _ticket_attachment_path(ticket_id, attachment_type, rel_id, index) + "/download"
        return self._get_raw(path)

    def preview_ticket_attachment(
        self, ticket_id: str, attachment_type: str, rel_id: str, index: int
    ) -> bytes:
        """Return the inline preview content of a support ticket or reply attachment.

        Parameters:
            ticket_id: Support ticket identifier the attachment belongs to.
            attachment_type: Attachment owner type, for example "ticket" or "reply".
            rel_id: Identifier of the ticket or reply the attachment belongs to.
            index: Zero based attachment index.
        """
        path = _ticket_attachment_path(ticket_id, attachment_type, rel_id, index) + "/preview"
        return self._get_raw(path)

    def close_ticket(self, ticket_id: str) -> None:
        """Close a support ticket.

        Parameters:
            ticket_id: Support ticket identifier to close.
        """
        self._post_json(f"support/tickets/{quote(ticket_id, safe='')}/close", {})

    def close_ticket_alias(self, ticket_id: str) -> None:
        """Close a support ticket through the alternate close path.

        Parameters:
            ticket_id: Support ticket identifier to close.
        """
        self._post_json(f"support/tickets/close/{quote(ticket_id, safe='')}", {})

    def reply_to_ticket(
        self, ticket_id: str, message: str, files: Optional[Sequence[str]] = None
    ) -> TicketReply:
        """Reply to a support ticket.

        Parameters:
            ticket_id: Support ticket identifier to reply to.
            message: Reply message body.
            files: Optional attachment references to include.
        """
        path = f"support/tickets/{quote(ticket_id, safe='')}/reply"
        return self._reply_to_ticket(path, message, files)

    def reply_to_ticket_alias(
        self, ticket_id: str, message: str, files: Optional[Sequence[str]] = None
    ) -> TicketReply:
        """Reply to a support ticket through the alternate reply path.

        Parameters:
            ticket_id: Support ticket identifier to reply to.
            message: Reply message body.
            files: Optional attachment references to include.
        """
        path = f"support/tickets/reply/{quote(ticket_id, safe='')}"
        return self._reply_to_ticket(path, message, files)

    def _reply_to_ticket(
        self, path: str, message: str, files: Optional[Sequence[str]]
    ) -> TicketReply:
        body: Dict[str, Any] = {"message": message}
        if files:
            body["files"] = list(files)
        return TicketReply.from_api(self._post_json(path, body))

    def list_secret_lists(self) -> List[SecretList]:
        """Return all secret lists visible to the account."""
        return [SecretList.from_api(row) for row in self._get("secrets/lists")]

    def get_secret_list(self, list_id: int) -> SecretList:
        """Return one secret list by id.

        Parameters:
            list_id: Secret list identifier.
        """
        return SecretList.from_api(self._get(f"secrets/lists/{list_id}"))

    def create_secret_list(self, name: str) -> SecretList:
        """Create a secret list.

        Parameters:
            name: Secret list name.
        """
        values = {"name": name}
        return SecretList.from_api(self._post_form("secrets/lists", values))

    def update_secret_list(self, list_id: int, name: str) -> SecretList:
        """Update a secret list's name.

        Parameters:
            list_id: Secret list identifier to update.
            name: Secret list name.
        """
        values = {"name": name}
        return SecretList.from_api(self._post_form(f"secrets/lists/{list_id}", values))

    def delete_secret_list(self, list_id: int) -> None:
        """Delete a secret list.

        Parameters:
            list_id: Secret list identifier.
        """
        self._delete(f"secrets/lists/{list_id}")

    def list_secret_list_values(self, list_id: int) -> List[SecretListValue]:
        """Return the values stored in a secret list.

        Parameters:
            list_id: Secret list identifier.
        """
        return [
            SecretListValue.from_api(row) for row in self._get(f"secrets/lists/{list_id}/values")
        ]

    def list_all_secret_values(self) -> List[SecretListValue]:
        """Return every secret value visible to the account."""
        return [SecretListValue.from_api(row) for row in self._get("secrets/all-values")]

    def get_secret_list_value(self, list_id: int, value_id: int) -> SecretListValue:
        """Return one secret list value by id.

        Parameters:
            list_id: Secret list identifier the value belongs to.
            value_id: Secret list value identifier.
        """
        path = f"secrets/lists/{list_id}/values/{value_id}"
        return SecretListValue.from_api(self._get(path))

    def create_secret_list_value(self, list_id: int, key: str, value: str) -> SecretListValue:
        """Create a value in a secret list.

        Parameters:
            list_id: Secret list identifier to create the value in.
            key: Secret key name.
            value: Secret value content.
        """
        values = {"secret_key": key, "secret_value": value}
        return SecretListValue.from_api(self._post_form(f"secrets/lists/{list_id}/values", values))

    def update_secret_list_value(
        self, list_id: int, value_id: int, key: str, value: str
    ) -> SecretListValue:
        """Update a value in a secret list.

        Parameters:
            list_id: Secret list identifier the value belongs to.
            value_id: Secret list value identifier to update.
            key: Secret key name.
            value: Secret value content.
        """
        values = {"secret_key": key, "secret_value": value}
        path = f"secrets/lists/{list_id}/values/{value_id}"
        return SecretListValue.from_api(self._post_form(path, values))

    def delete_secret_list_value(self, list_id: int, value_id: int) -> None:
        """Delete a value from a secret list.

        Parameters:
            list_id: Secret list identifier the value belongs to.
            value_id: Secret list value identifier to delete.
        """
        self._delete(f"secrets/lists/{list_id}/values/{value_id}")

    def list_dedicated_devices(
        self,
        per_page: Optional[int] = None,
        nic: str = "",
        cpu_type: str = "",
        gpu_type: str = "",
        disk_type: str = "",
        cores: str = "",
        ram_mb: str = "",
        disk_mib: str = "",
        dc_name: str = "",
        region_name: str = "",
    ) -> List[Dict[str, Any]]:
        """Return available dedicated devices matching the optional filters.

        Each device is returned as a raw mapping because the API does not
        define a fixed schema for it.

        Parameters:
            per_page: Optional page size.
            nic: Optional network interface card filter.
            cpu_type: Optional CPU type filter.
            gpu_type: Optional GPU type filter.
            disk_type: Optional disk type filter.
            cores: Optional core count filter.
            ram_mb: Optional RAM size filter, in MB.
            disk_mib: Optional disk size filter, in MiB.
            dc_name: Optional datacenter name filter.
            region_name: Optional region name filter.
        """
        params: Dict[str, Any] = {}
        if per_page is not None:
            params["per_page"] = per_page
        for name, value in (
            ("nic", nic),
            ("cpu_type", cpu_type),
            ("gpu_type", gpu_type),
            ("disk_type", disk_type),
            ("cores", cores),
            ("ram_mb", ram_mb),
            ("disk_mib", disk_mib),
            ("dc_name", dc_name),
            ("region_name", region_name),
        ):
            if value:
                params[name] = value
        path = "dedicated/filter-dedicated-devices"
        if params:
            path = _page_path(path, **params)
        return _decode_dedicated_devices(self._get(path))

    def list_dedicated_locations(self) -> List[DedicatedLocation]:
        """Return locations that support dedicated servers."""
        return [DedicatedLocation.from_api(row) for row in self._get("dedicated/locations")]

    def list_dedicated_device_os_profiles(
        self, device_id: int, is_buyable: Optional[bool] = None
    ) -> List[DedicatedOSProfile]:
        """Return OS profiles compatible with a dedicated device.

        Parameters:
            device_id: Dedicated device identifier.
            is_buyable: Optional flag restricting results to buyable profiles.
        """
        path = f"dedicated/os/device/{device_id}"
        if is_buyable is not None:
            path = _page_path(path, is_buyable="1" if is_buyable else "0")
        return [DedicatedOSProfile.from_api(row) for row in self._get(path)]

    def list_dedicated_plans(self, location_id: int) -> List[Dict[str, Any]]:
        """Return dedicated server plans available at a location.

        Each plan is returned as a raw mapping because the API does not
        define a fixed schema for it.

        Parameters:
            location_id: Dedicated location identifier to list plans for.
        """
        path = f"dedicated/plans/{location_id}"
        data = self._get(path)
        if not isinstance(data, list):
            raise NetActuateError(
                f"list dedicated plans for location {location_id} returned a non-list response",
                method="GET",
                url=path,
                body=data,
            )
        return [dict(row) for row in data if isinstance(row, Mapping)]

    def deploy_dedicated_server(
        self,
        mbpkgid: int,
        fqdn: str = "",
        profile: int = 0,
        disk_layout: Optional[int] = None,
        root_password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        ssh_key_id: Optional[int] = None,
        build_script: Optional[str] = None,
    ) -> ServerBuild:
        """Deploy an already purchased dedicated server package.

        Parameters:
            mbpkgid: Dedicated server package identifier to deploy.
            fqdn: Fully qualified hostname to assign.
            profile: OS profile identifier to build.
            disk_layout: Optional disk layout identifier.
            root_password: Optional root password to set.
            ssh_key: Optional public key content to install, when not using ssh_key_id.
            ssh_key_id: Optional existing SSH key identifier to install.
            build_script: Optional startup build script content.
        """
        body = _dedicated_build_body(
            fqdn, profile, disk_layout, root_password, ssh_key, ssh_key_id, build_script
        )
        return ServerBuild.from_api(self._post_json(f"dedicated/server/build/{mbpkgid}", body))

    def buy_dedicated_server(self, device_id: int) -> ServerBuild:
        """Purchase a dedicated device without deploying it.

        Parameters:
            device_id: Dedicated device identifier to purchase.
        """
        return ServerBuild.from_api(self._post_form(f"dedicated/server/buy/{device_id}", {}))

    def buy_and_deploy_dedicated_server(
        self,
        device_id: int,
        fqdn: str = "",
        profile: int = 0,
        disk_layout: Optional[int] = None,
        root_password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        ssh_key_id: Optional[int] = None,
        build_script: Optional[str] = None,
    ) -> ServerBuild:
        """Purchase a dedicated device and deploy it in one call.

        Parameters:
            device_id: Dedicated device identifier to purchase and deploy.
            fqdn: Fully qualified hostname to assign.
            profile: OS profile identifier to build.
            disk_layout: Optional disk layout identifier.
            root_password: Optional root password to set.
            ssh_key: Optional public key content to install, when not using ssh_key_id.
            ssh_key_id: Optional existing SSH key identifier to install.
            build_script: Optional startup build script content.
        """
        body = _dedicated_build_body(
            fqdn, profile, disk_layout, root_password, ssh_key, ssh_key_id, build_script
        )
        return ServerBuild.from_api(
            self._post_json(f"dedicated/server/buy_build/{device_id}", body)
        )

    def update_dedicated_server_ipv4_reverse(self, mbpkgid: int, address_id: int, reverse: str) -> None:
        """Update reverse DNS for a dedicated server IPv4 address.

        Parameters:
            mbpkgid: Dedicated server package identifier the address belongs to.
            address_id: IPv4 address identifier to update.
            reverse: Reverse DNS hostname to set.
        """
        body = {"mbpkgid": mbpkgid, "id": address_id, "reverse": reverse}
        self._put_json("dedicated/server/ipv4_reverse", body)

    def soft_reset_dedicated_server(self, mbpkgid: int) -> None:
        """Ask the platform to soft reset a dedicated server.

        Parameters:
            mbpkgid: Dedicated server package identifier to reset.
        """
        self._post_json(f"dedicated/server/soft-reset/{mbpkgid}", None)

    def delete_dedicated_server(
        self, mbpkgid: int, force: Optional[bool] = None, password: Optional[str] = None
    ) -> None:
        """Delete a dedicated server package.

        Parameters:
            mbpkgid: Dedicated server package identifier to delete.
            force: Optional flag forcing the deletion.
            password: Optional password required by the platform for this action.
        """
        self._post_json(f"dedicated/server/{mbpkgid}/delete", _dedicated_action_body(force, password))

    def reboot_dedicated_server(
        self, mbpkgid: int, force: Optional[bool] = None, password: Optional[str] = None
    ) -> None:
        """Ask the platform to reboot a dedicated server.

        Parameters:
            mbpkgid: Dedicated server package identifier to reboot.
            force: Optional flag forcing the reboot.
            password: Optional password required by the platform for this action.
        """
        self._post_json(f"dedicated/server/{mbpkgid}/reboot", _dedicated_action_body(force, password))

    def shutdown_dedicated_server(
        self, mbpkgid: int, force: Optional[bool] = None, password: Optional[str] = None
    ) -> None:
        """Ask the platform to shut down a dedicated server.

        Parameters:
            mbpkgid: Dedicated server package identifier to shut down.
            force: Optional flag forcing the shutdown.
            password: Optional password required by the platform for this action.
        """
        self._post_json(f"dedicated/server/{mbpkgid}/shutdown", _dedicated_action_body(force, password))

    def start_dedicated_server(
        self, mbpkgid: int, force: Optional[bool] = None, password: Optional[str] = None
    ) -> None:
        """Ask the platform to start a dedicated server.

        Parameters:
            mbpkgid: Dedicated server package identifier to start.
            force: Optional flag forcing the start.
            password: Optional password required by the platform for this action.
        """
        self._post_json(f"dedicated/server/{mbpkgid}/start", _dedicated_action_body(force, password))

    def get_dedicated_server_power_status(
        self, mbpkgid: int, force: Optional[bool] = None, password: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the power status for a dedicated server.

        The response is returned as a raw mapping because the API does not
        define a fixed schema for it.

        Parameters:
            mbpkgid: Dedicated server package identifier.
            force: Optional flag forwarded to the platform for this action.
            password: Optional password forwarded to the platform for this action.
        """
        path = f"dedicated/server/{mbpkgid}/status"
        data = self._post_json(path, _dedicated_action_body(force, password))
        if not isinstance(data, Mapping):
            raise NetActuateError(
                f"dedicated server {mbpkgid} power status returned a non-object response",
                method="POST",
                url=path,
                body=data,
            )
        return dict(data)

    def list_dedicated_servers(self) -> List[DedicatedServer]:
        """Return dedicated servers for the account."""
        return [DedicatedServer.from_api(row) for row in self._get("dedicated/servers")]

    def list_images(self) -> List[Image]:
        """Return custom images owned by the account."""
        return [Image.from_api(row) for row in self._get("cloud/images/my")]

    def get_image(self, image_id: int) -> Image:
        """Return one custom image.

        Parameters:
            image_id: Custom image identifier.
        """
        return Image.from_api(self._get(f"cloud/images/{image_id}"))

    def create_image(
        self,
        mbpkgid: int,
        image_name: str,
        image_description: str = "",
        keep_ssh_userdirs: bool = False,
    ) -> int:
        """Create a custom image from a server and return the queued job id.

        Poll the result with get_image_queue_status or wait_for_image_queue.

        Parameters:
            mbpkgid: Server package identifier to image.
            image_name: Display name for the new image.
            image_description: Optional description for the new image.
            keep_ssh_userdirs: Whether to keep per user SSH directories in the image.
        """
        values: Dict[str, Any] = {"mbpkgid": mbpkgid, "image_name": image_name}
        if image_description:
            values["image_description"] = image_description
        if keep_ssh_userdirs:
            values["keep_ssh_userdirs"] = "1"
        path = "cloud/images/create"
        data = self._post_form(path, values)
        queue_id = _response_int(data, "queue_id") if isinstance(data, Mapping) else 0
        if not queue_id:
            raise NetActuateError(
                f"create image for server {mbpkgid} returned no queue id",
                method="POST",
                url=path,
                body=data,
            )
        return queue_id

    def edit_image(self, image_id: int, name: str, description: str) -> None:
        """Update a custom image's name and description.

        Parameters:
            image_id: Custom image identifier to update.
            name: New display name for the image.
            description: New description for the image.
        """
        body = {"os": name, "description": description}
        self._patch_json(f"cloud/images/{image_id}/edit", body)

    def delete_image(self, image_id: int) -> int:
        """Delete a custom image and return the queued job id.

        Parameters:
            image_id: Custom image identifier to delete.
        """
        path = f"cloud/images/{image_id}/delete"
        data = self._delete(path)
        queue_id = _response_int(data, "queue_id") if isinstance(data, Mapping) else 0
        if not queue_id:
            raise NetActuateError(
                f"delete image {image_id} returned no queue id", method="DELETE", url=path, body=data
            )
        return queue_id

    def get_image_queue_status(self, queue_id: int) -> ImageQueueStatus:
        """Return the status of a queued custom image job.

        Parameters:
            queue_id: Image job queue identifier.
        """
        return ImageQueueStatus.from_api(self._get(f"cloud/images/queue_status/{queue_id}"))

    def wait_for_image_queue(
        self, queue_id: int, max_tries: int = 600, interval: float = 3.0
    ) -> ImageQueueStatus:
        """Poll a queued custom image job until it completes or fails.

        Parameters:
            queue_id: Image job queue identifier.
            max_tries: Maximum number of polls before giving up.
            interval: Seconds to sleep between polls.
        """
        path = f"cloud/images/queue_status/{queue_id}"
        for _ in range(max_tries):
            status = self.get_image_queue_status(queue_id)
            if status.status == "Complete":
                return status
            if status.status == "Failed":
                raise NetActuateError(
                    f"image job {queue_id} failed: {status.response}", method="GET", url=path
                )
            time.sleep(interval)
        raise NetActuateError(f"timeout waiting for image job {queue_id} to complete", method="GET", url=path)

    def list_base_images(self) -> List[Image]:
        """Return base images available for cloud server deployment."""
        return [Image.from_api(row) for row in self._get("cloud/images/base")]

    def list_private_images(self) -> List[Image]:
        """Return private images available to the account."""
        return [Image.from_api(row) for row in self._get("cloud/images/private")]

    def replace_image(self, image_id: int, replace_id: int) -> Any:
        """Replace an image with another image.

        The API does not define a fixed schema for this payload.

        Parameters:
            image_id: Image identifier to replace.
            replace_id: Identifier of the image that replaces it.
        """
        return self._post_json(f"cloud/images/{image_id}/replace_image", {"replace_id": replace_id})

    def get_images_provisioning_jobs_count(self) -> Any:
        """Return the count of image provisioning jobs currently queued.

        The API does not define a fixed schema for this payload.
        """
        return self._get("cloud/images-provisioning-jobs-count")

    def create_bgp_group(self, name: str, description: str = "", group_type: str = "") -> BGPGroup:
        """Create an account BGP group.

        Parameters:
            name: Group name.
            description: Group description.
            group_type: Optional group type, for example "anycast".
        """
        body: Dict[str, Any] = {"name": name, "description": description}
        if group_type:
            body["group_type"] = group_type
        return BGPGroup.from_api(self._post_json("bgp/bgpgroup", body))

    def get_bgp_group(self, group_id: int) -> BGPGroup:
        """Return one account BGP group.

        Parameters:
            group_id: BGP group identifier.
        """
        return BGPGroup.from_api(self._get(f"bgp/bgpgroup/{group_id}"))

    def list_bgp_groups(self, group_type: str = "") -> List[BGPGroup]:
        """Return account BGP groups, optionally filtered by group type.

        Parameters:
            group_type: Optional group type to filter by. The API defaults
                to "anycast" when omitted.
        """
        path = "bgp/bgpgroups"
        if group_type:
            path = _page_path(path, group_type=group_type)
        return [BGPGroup.from_api(row) for row in self._get(path)]

    def bind_bgp_group_firewall_set(
        self, group_id: int, identifier: int, firewall_set_id: int, interface_number: int, set_priority: int
    ) -> BGPGroupFirewallSetBinding:
        """Bind a firewall set to a BGP group interface.

        Parameters:
            group_id: BGP group identifier to bind the firewall set to.
            identifier: Value for the request's own "id" field, required by
                the API alongside the BGP group id.
            firewall_set_id: Firewall set identifier to bind.
            interface_number: Interface number to bind the firewall set on.
            set_priority: Priority of the firewall set on that interface.
        """
        body = {
            "id": identifier,
            "firewall_set_id": firewall_set_id,
            "interface_number": interface_number,
            "set_priority": set_priority,
        }
        return BGPGroupFirewallSetBinding.from_api(
            self._post_json(f"bgp/bgp-groups/{group_id}/firewall-sets", body)
        )

    def unbind_bgp_group_firewall_set(self, group_id: int, firewall_set_id: int) -> None:
        """Remove a firewall set binding from a BGP group.

        Parameters:
            group_id: BGP group identifier.
            firewall_set_id: Firewall set identifier to unbind.
        """
        self._delete(f"bgp/bgp-groups/{group_id}/firewall-sets/{firewall_set_id}")

    def refresh_bgp_group_sessions(self, group_id: int) -> None:
        """Ask the platform to refresh every session in a BGP group.

        Parameters:
            group_id: BGP group identifier.
        """
        self._post_form(f"bgp/bgpgroup/{group_id}/refresh", {})

    def start_bgp_group_sessions(self, group_id: int) -> None:
        """Ask the platform to start every session in a BGP group.

        Parameters:
            group_id: BGP group identifier.
        """
        self._post_form(f"bgp/bgpgroup/{group_id}/start", {})

    def stop_bgp_group_sessions(self, group_id: int) -> None:
        """Ask the platform to stop every session in a BGP group.

        Parameters:
            group_id: BGP group identifier.
        """
        self._post_form(f"bgp/bgpgroup/{group_id}/stop", {})

    def refresh_bgp_session(self, session_id: int) -> None:
        """Ask the platform to refresh a BGP session.

        Parameters:
            session_id: BGP session identifier.
        """
        self._post_form(f"bgp/bgpsession/{session_id}/refresh", {})

    def start_bgp_session(self, session_id: int) -> None:
        """Ask the platform to start a BGP session.

        Parameters:
            session_id: BGP session identifier.
        """
        self._post_form(f"bgp/bgpsession/{session_id}/start", {})

    def stop_bgp_session(self, session_id: int) -> None:
        """Ask the platform to stop a BGP session.

        Parameters:
            session_id: BGP session identifier.
        """
        self._post_form(f"bgp/bgpsession/{session_id}/stop", {})

    def get_bgp_summary(self) -> Dict[str, Any]:
        """Return the account BGP summary as a raw mapping.

        The API does not define a fixed schema for this payload.
        """
        data = self._get("bgp/bgpsummary")
        if not isinstance(data, Mapping):
            raise NetActuateError("BGP summary response must be an object", method="GET", url="bgp/bgpsummary", body=data)
        return dict(data)

    def get_bgp_dashboard(self, group_type: str = "", flap_window: Optional[int] = None) -> Dict[str, Any]:
        """Return BGP dashboard data as a raw mapping.

        The API does not define a fixed schema for this payload.

        Parameters:
            group_type: Optional group type to filter by.
            flap_window: Optional flap window, in seconds, to filter by.
        """
        path = "bgp/dashboard"
        if group_type:
            path = _page_path(path, group_type=group_type)
        if flap_window is not None:
            path = _page_path(path, flap_window=flap_window)
        data = self._get(path)
        if not isinstance(data, Mapping):
            raise NetActuateError("BGP dashboard response must be an object", method="GET", url=path, body=data)
        return dict(data)

    def buy_bgp_prefixes(
        self,
        name: str,
        agreement_id: int,
        group_id: int = 0,
        asn_id: int = 0,
        anycast_profile: int = 0,
    ) -> BGPPrefix:
        """Purchase anycast BGP prefixes for the account.

        Parameters:
            name: Name for the purchased prefix.
            agreement_id: Legal agreement identifier accepted for the purchase.
            group_id: Optional BGP group identifier to attach the prefix to.
            asn_id: Optional ASN identifier, required when group_id is omitted.
            anycast_profile: Optional anycast profile identifier.
        """
        body: Dict[str, Any] = {"name": name, "agreement_id": agreement_id}
        if group_id:
            body["group_id"] = group_id
        if asn_id:
            body["asn_id"] = asn_id
        if anycast_profile:
            body["anycast_profile"] = anycast_profile
        return BGPPrefix.from_api(self._post_json("bgp/bgpbuyprefixes", body))

    def get_bgp_prefix(self, prefix_id: int) -> BGPPrefix:
        """Return one account BGP prefix.

        Parameters:
            prefix_id: BGP prefix identifier.
        """
        return BGPPrefix.from_api(self._get(f"bgp/bgpprefix/{prefix_id}"))

    def list_bgp_prefixes(self, group_type: str = "") -> List[BGPPrefix]:
        """Return account BGP prefixes, optionally filtered by group type.

        Parameters:
            group_type: Optional group type to filter by. The API defaults
                to "anycast" when omitted.
        """
        path = "bgp/bgpprefixes"
        if group_type:
            path = _page_path(path, group_type=group_type)
        return [BGPPrefix.from_api(row) for row in self._get(path)]

    def list_bgp_asns(self, group_type: str = "") -> List[BGPASN]:
        """Return account ASNs, optionally filtered by group type.

        Parameters:
            group_type: Optional group type to filter by. The API defaults
                to "anycast" when omitted.
        """
        path = "bgp/bgpasns"
        if group_type:
            path = _page_path(path, group_type=group_type)
        return [BGPASN.from_api(row) for row in self._get(path)]

    def get_bgp_asn(self, asn_id: int) -> BGPASN:
        """Return one account ASN.

        Parameters:
            asn_id: BGP ASN identifier.
        """
        return BGPASN.from_api(self._get(f"bgp/bgpasn?id={asn_id}"))

    def list_account_agreements(self) -> List[AccountAgreement]:
        """Return legal agreements available to the account."""
        return [AccountAgreement.from_api(row) for row in self._get("account/agreements")]

    def get_contract_usage(self) -> ContractUsage:
        """Return the account's current usage contract."""
        return ContractUsage.from_api(self._get("cloud/contract/usage"))

    def get_datacenter_by_iata(self, iata: str) -> int:
        """Return the datacenter id for an IATA airport code.

        Parameters:
            iata: IATA airport code identifying the datacenter.
        """
        return Datacenter.from_api(self._get(f"platform/datacenters-by-iata/{quote(iata, safe='')}")).id

    def list_sizes(self) -> List[Size]:
        """Return every deploy size offered across all locations."""
        return [Size.from_api(row) for row in self._get("cloud/sizes")]

    def list_plans(self) -> List[Plan]:
        """Return every purchasable plan offered across all locations."""
        return [Plan.from_api(row) for row in self._get("cloud/sizes")]

    def list_boot_profiles(self) -> List[BootProfile]:
        """Return every cloud boot profile."""
        return [BootProfile.from_api(row) for row in self._get("cloud/boot-profiles")]

    def list_server_disks(self, mbpkgid: int) -> List[Dict[str, Any]]:
        """Return the cloud disks attached to a server.

        Each disk is returned as a raw mapping because the API does not yet
        expose per-disk fields; observed live responses return only empty
        lists.

        Parameters:
            mbpkgid: vAPI2 mbpkgid server identifier.
        """
        data = self._get(f"cloud/disks/{mbpkgid}")
        if not isinstance(data, list):
            raise NetActuateError(
                f"list server disks for {mbpkgid} returned a non-list response",
                method="GET",
                url=f"cloud/disks/{mbpkgid}",
                body=data,
            )
        return [dict(row) for row in data if isinstance(row, Mapping)]

    def list_dedicated_os_profiles(self) -> List[DedicatedOS]:
        """Return every dedicated OS profile offered by the platform."""
        return [DedicatedOS.from_api(row) for row in self._get("dedicated/os")]

    def list_dedicated_rescue_os(self) -> List[DedicatedRescueOS]:
        """Return every dedicated rescue OS profile offered by the platform."""
        return [DedicatedRescueOS.from_api(row) for row in self._get("dedicated/os/rescue-system-list")]

    def list_dedicated_disk_layouts(self, os_id: int) -> List[DedicatedDiskLayout]:
        """Return the dedicated disk layouts available for an OS profile.

        Parameters:
            os_id: Dedicated OS profile identifier to list disk layouts for.
        """
        return [DedicatedDiskLayout.from_api(row) for row in self._get(f"dedicated/disklayouts/{os_id}")]

    def list_ddos_attacks(self) -> List[DDoSAttack]:
        """Return every recorded DDoS attack on the account, active or historical."""
        return [DDoSAttack.from_api(row) for row in self._get("ddos/attacks")]

    def list_active_ddos_attacks(self) -> List[DDoSAttack]:
        """Return DDoS attacks currently in progress on the account."""
        return [DDoSAttack.from_api(row) for row in self._get("ddos/attacks/active")]

    def get_ddos_dashboard(
        self,
        period: Optional[int] = None,
        include_ended: Optional[bool] = None,
        limit: Optional[int] = None,
    ) -> DDoSDashboard:
        """Return the DDoS dashboard summary.

        Parameters:
            period: Optional window, in seconds, to summarize.
            include_ended: Optional flag including attacks that have already ended.
            limit: Optional maximum number of top attacks to return.
        """
        path = "ddos/dashboard"
        params: Dict[str, Any] = {}
        if period is not None:
            params["period"] = period
        if include_ended is not None:
            params["include_ended"] = "true" if include_ended else "false"
        if limit is not None:
            params["limit"] = limit
        if params:
            path = _page_path(path, **params)
        return DDoSDashboard.from_api(self._get(path))

    def list_ddos_rules(self) -> List[DDoSRule]:
        """Return every DDoS mitigation rule on the account."""
        return [DDoSRule.from_api(row) for row in self._get("ddos/rules")]

    def get_ddos_rule(self, rule_id: int) -> DDoSRule:
        """Return one DDoS mitigation rule.

        Parameters:
            rule_id: DDoS rule identifier.
        """
        return DDoSRule.from_api(self._get(f"ddos/rule/{rule_id}"))

    def list_access_control_subnets(self) -> List[AccessControlSubnet]:
        """Return every subnet permitted to access the account."""
        return [
            AccessControlSubnet.from_api(row)
            for row in self._get("account/user-access-control-subnet-list")
        ]

    def get_access_control_subnet(self, subnet_id: int) -> AccessControlSubnet:
        """Return one access control subnet.

        Parameters:
            subnet_id: Access control subnet identifier.
        """
        return AccessControlSubnet.from_api(self._get(f"account/user-access-control-subnet/{subnet_id}"))

    def create_access_control_subnet(self, label: str, subnet: str) -> AccessControlSubnet:
        """Create an access control subnet.

        Parameters:
            label: Display label for the subnet.
            subnet: Subnet in CIDR notation.
        """
        body = {"label": label, "subnet": subnet}
        return AccessControlSubnet.from_api(self._post_json("account/user-access-control-subnet", body))

    def update_access_control_subnet(
        self, subnet_id: int, label: Optional[str] = None, subnet: Optional[str] = None
    ) -> AccessControlSubnet:
        """Update an access control subnet's label or CIDR.

        Parameters:
            subnet_id: Access control subnet identifier to update.
            label: Optional new display label.
            subnet: Optional new subnet in CIDR notation.
        """
        body: Dict[str, Any] = {}
        if label is not None:
            body["label"] = label
        if subnet is not None:
            body["subnet"] = subnet
        path = f"account/user-access-control-subnet/{subnet_id}"
        return AccessControlSubnet.from_api(self._patch_json(path, body))

    def delete_access_control_subnet(self, subnet_id: int) -> None:
        """Delete an access control subnet.

        Parameters:
            subnet_id: Access control subnet identifier to delete.
        """
        self._delete(f"account/user-access-control-subnet/{subnet_id}")

    def get_metal_build_status(self, build_id: int) -> MetalBuildStatus:
        """Return the status of a metal device build.

        Parameters:
            build_id: Build identifier returned by create or build metal calls.
        """
        return MetalBuildStatus.from_api(self._get(f"dedicated/server/build_status/{build_id}"))

    def create_metal_server(
        self,
        location: Optional[int] = None,
        device: Optional[int] = None,
        ssh_key: str = "",
        ssh_key_id: Optional[int] = None,
        password: str = "",
        build_script: str = "",
        disk_layout: Optional[int] = None,
        profile: Optional[int] = None,
        hostname: str = "",
    ) -> MetalBuild:
        """Purchase and build a metal device in one call.

        Mirrors gona's CreateMetal, which form-encodes every field and omits
        each one left at its zero value.

        Parameters:
            location: Optional location identifier.
            device: Optional device identifier to purchase.
            ssh_key: Optional public key content to install.
            ssh_key_id: Optional existing SSH key identifier to install.
            password: Optional root password to set.
            build_script: Optional startup build script content.
            disk_layout: Optional disk layout identifier.
            profile: Optional OS profile identifier to build.
            hostname: Optional fully qualified hostname to assign.
        """
        values = _metal_optional_values(ssh_key, ssh_key_id, password, build_script, disk_layout, profile, hostname)
        if location is not None:
            values["location"] = location
        if device is not None:
            values["device_id"] = device
        return MetalBuild.from_api(self._post_form("dedicated/server/buy_build", values))

    def build_metal_server(
        self,
        device_id: int,
        mbpkgid: int,
        ssh_key: str = "",
        ssh_key_id: Optional[int] = None,
        password: str = "",
        build_script: str = "",
        disk_layout: Optional[int] = None,
        profile: Optional[int] = None,
        hostname: str = "",
    ) -> MetalBuild:
        """Build a previously purchased metal device.

        Mirrors gona's BuildMetal: mbpkgid is always sent, and every other
        field is form-encoded and omitted when left at its zero value.

        Parameters:
            device_id: Device identifier to rebuild, used in the request path.
            mbpkgid: Purchased package identifier to build.
            ssh_key: Optional public key content to install.
            ssh_key_id: Optional existing SSH key identifier to install.
            password: Optional root password to set.
            build_script: Optional startup build script content.
            disk_layout: Optional disk layout identifier.
            profile: Optional OS profile identifier to build.
            hostname: Optional fully qualified hostname to assign.
        """
        values = _metal_optional_values(ssh_key, ssh_key_id, password, build_script, disk_layout, profile, hostname)
        values["mbpkgid"] = mbpkgid
        return MetalBuild.from_api(self._post_form(f"dedicated/server/re_build/{device_id}", values))

    def get_metal_server(self, server_id: int) -> DedicatedServer:
        """Return one metal device by its dedicated server identifier.

        Uses the same decoded shape as `list_dedicated_servers`, since both
        endpoints answer with the same underlying resource.

        Parameters:
            server_id: Dedicated server identifier.
        """
        return DedicatedServer.from_api(self._get(f"dedicated/servers/{server_id}"))

    def get_bgp_session(self, session_id: int) -> BGPSession:
        """Return one BGP session.

        Parameters:
            session_id: BGP session identifier.
        """
        return BGPSession.from_api(self._get(f"bgp/bgpsession/{session_id}"))

    def list_bgp_sessions(self, mbpkgid: int) -> List[BGPSession]:
        """Return BGP sessions whose customer peer IP belongs to a package.

        Mirrors gona's GetBGPSessions: the full session list is fetched, then
        filtered to sessions whose customer peer IP matches one of the
        package's own IPv4 or IPv6 addresses, and each match is re-fetched
        for its full detail.

        Parameters:
            mbpkgid: Package identifier whose IPs the sessions must match.
        """
        all_sessions = [BGPSession.from_api(row) for row in self._get("bgp/bgpsessions")]
        if not all_sessions:
            return []
        ips = self.get_cloud_network_ips(mbpkgid)
        ip_types = _cloud_network_ip_type_map(ips)
        if not ip_types:
            return []
        sessions: List[BGPSession] = []
        for session in all_sessions:
            if session.customer_ip in ip_types:
                sessions.append(self.get_bgp_session(session.id))
        return sessions

    def create_bgp_session(
        self, mbpkgid: int, group_id: int, ipv6: bool = False, redundant: bool = False
    ) -> BGPSession:
        """Create one or more BGP sessions for a package.

        Parameters:
            mbpkgid: Contract BGP package identifier.
            group_id: BGP group identifier to create the session in.
            ipv6: Whether to create an IPv6 session.
            redundant: Whether to force session redundancy.
        """
        values: Dict[str, Any] = {"mbpkgid": mbpkgid, "group_id": group_id}
        if ipv6:
            values["ipv6"] = "1"
        if redundant:
            values["redundant"] = "1"
        return BGPSession.from_api(self._post_form("bgp/bgpcreatesessions", values))

    def delete_bgp_session(self, session_id: int) -> None:
        """Delete a single BGP session.

        Parameters:
            session_id: BGP session identifier to delete.
        """
        self._post_json(f"bgp/bgpsession/{session_id}/delete", None)

    def list_billing_packages(self) -> List[BillingPackage]:
        """Return every billing package on the account."""
        return [BillingPackage.from_api(row) for row in self._get("cloud/billing-packages")]

    def list_cloud_pools(self) -> List[CloudPool]:
        """Return every cloud pool visible to the account."""
        return [CloudPool.from_api(row) for row in self._get("cloud/pools")]

    def get_cloud_capacity(self, cloud_pool_id: int, location_id: int) -> List[CloudCapacity]:
        """Return available cloud package capacity at a location within a pool.

        Parameters:
            cloud_pool_id: Cloud pool identifier.
            location_id: Location identifier.
        """
        path = f"cloud/capacity?cloud_pool_id={cloud_pool_id}&location_id={location_id}"
        return [CloudCapacity.from_api(row) for row in self._get(path)]

    def list_dedicated_capacity(self) -> List[DedicatedCapacity]:
        """Return available dedicated device capacity for the account."""
        return [DedicatedCapacity.from_api(row) for row in self._get("dedicated/capacity")]

    def list_colocation_packages(self) -> List[ColocationPackage]:
        """Return every colocation package on the account, sorted by mbpkgid."""
        rows = _sorted_by_mbpkgid(self._get("colo/packages"), "colocation packages")
        return [ColocationPackage.from_api(row) for row in rows]

    def get_colocation_package(self, mbpkgid: int) -> ColocationPackage:
        """Return one colocation package.

        Parameters:
            mbpkgid: Colocation package identifier.
        """
        return ColocationPackage.from_api(self._get(f"colo/package/{mbpkgid}"))

    def list_transit_packages(self) -> List[TransitPackage]:
        """Return every IP transit package on the account, sorted by mbpkgid."""
        rows = _sorted_by_mbpkgid(self._get("transit/packages"), "transit packages")
        return [TransitPackage.from_api(row) for row in rows]

    def get_transit_package(self, mbpkgid: int) -> TransitPackage:
        """Return one IP transit package.

        Parameters:
            mbpkgid: Transit package identifier.
        """
        return TransitPackage.from_api(self._get(f"transit/package/{mbpkgid}"))

    def list_packages(self) -> List[Package]:
        """Return every purchased cloud package on the account."""
        return [Package.from_api(row) for row in self._get("cloud/packages")]

    def get_package(self, package_id: int) -> Package:
        """Return one purchased cloud package.

        Parameters:
            package_id: Package identifier.
        """
        return Package.from_api(self._get(f"cloud/package/{package_id}"))

    def cancel_package(
        self,
        mbpkgid: int,
        domu_package: Optional[str] = None,
        comments: Optional[str] = None,
        cancel_type: str = "",
        agree: int = 0,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a purchased package.

        The response is returned as a raw mapping because the API does not
        define a fixed schema for it.

        Parameters:
            mbpkgid: Package identifier to cancel.
            domu_package: Optional DomU package identifier.
            comments: Optional cancellation comments.
            cancel_type: Cancellation type.
            agree: Agreement flag required by the platform for this action.
            password: Optional password required by the platform for this action.
        """
        body: Dict[str, Any] = {"mbpkgid": mbpkgid, "cancel_type": cancel_type, "agree": agree}
        if domu_package is not None:
            body["domU_package"] = domu_package
        if comments is not None:
            body["comments"] = comments
        if password is not None:
            body["password"] = password
        data = self._post_json("cloud/package/cancel/", body)
        if not isinstance(data, Mapping):
            raise NetActuateError(
                "cancel package returned a non-object response",
                method="POST",
                url="cloud/package/cancel/",
                body=data,
            )
        return dict(data)

    def get_location_by_current_ip(self) -> LocationByCurrentIP:
        """Return the platform location detected from the caller's current IP."""
        return LocationByCurrentIP.from_api(self._get("location"))

    def get_graph(self, port: int, time_range: str) -> Any:
        """Return graph data for a switch port and time range.

        The response is returned as-is because the API does not define a
        fixed schema for it.

        Parameters:
            port: Switch port identifier.
            time_range: One of daily, weekly, monthly or yearly.
        """
        path = _page_path("graphs/graph", port=port, time=time_range)
        return self._get(path)

    def list_cloud_locations(self) -> List[CloudLocationListing]:
        """Return every available cloud deployment location."""
        return [CloudLocationListing.from_api(row) for row in self._get("cloud/locations")]

    def list_operating_systems(self) -> List[CloudOS]:
        """Return every operating system template offered for cloud server builds."""
        return [CloudOS.from_api(row) for row in self._get("cloud/images")]

    def get_cloud_network_ips(self, mbpkgid: int) -> CloudNetworkIPs:
        """Return the IPv4 and IPv6 addresses attached to a package.

        Parameters:
            mbpkgid: Package identifier.
        """
        return CloudNetworkIPs.from_api(self._get(f"cloud/networkips/{mbpkgid}"))

    def _get(self, path: str) -> Any:
        response = self._request("GET", path)
        return response

    def _post_form(self, path: str, values: Mapping[str, Any]) -> Any:
        return self._request("POST", path, form_data=values)

    def _post_json(self, path: str, body: Optional[Mapping[str, Any]]) -> Any:
        return self._request("POST", path, json_body=body)

    def _put_form(self, path: str, values: Mapping[str, Any]) -> Any:
        return self._request("PUT", path, form_data=values)

    def _put_json(self, path: str, body: Mapping[str, Any]) -> Any:
        return self._request("PUT", path, json_body=body)

    def _patch_json(self, path: str, body: Mapping[str, Any]) -> Any:
        return self._request("PATCH", path, json_body=body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def _post_multipart(self, path: str, filename: str, content: bytes) -> Any:
        """Perform a multipart/form-data POST with a single file field named "file".

        Parameters:
            path: Relative vAPI2 path to post to.
            filename: Name reported for the uploaded file.
            content: Raw file content.
        """
        return self._request("POST", path, files={"file": (filename, content)})

    def _request(
        self,
        method: str,
        path: str,
        json_body: Any = None,
        form_data: Any = None,
        files: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        url = _with_key(urljoin(self.base_url, path), self._api_key)
        if files is not None:
            response = self.session.request(method, url, files=files, timeout=self.timeout)
        elif form_data is not None:
            response = self.session.request(method, url, data=form_data, timeout=self.timeout)
        else:
            response = self.session.request(method, url, json=json_body, timeout=self.timeout)
        payload = _json(response)
        code = int(payload.get("code") or 0)
        message = str(payload.get("message") or "")
        result = str(payload.get("result") or "").lower()

        not_found = _fields_match(
            payload.get("fields"),
            [
                ("id", "must be a valid zone id"),
                ("id", "must be a valid record id"),
                ("mbpkgid", "must be a valid mbpkgid"),
                ("mbpkgid", "must be a valid package"),
            ],
        )
        if response.status_code == 404 or code == 404 or not_found:
            raise NotFoundError(
                not_found or message or "resource not found",
                method=method,
                url=url,
                status_code=response.status_code,
                code=code,
                body=payload.get("data", payload.get("fields")),
            )
        if _looks_contract_gated(response.status_code, code, message):
            raise ContractError(message or "contract gated capability refused", method=method, url=url, status_code=response.status_code, code=code)
        if (
            response.status_code < 200
            or response.status_code >= 300
            or (code and (code < 200 or code >= 300))
            or (result and result not in ("success", "ok"))
        ):
            raise NetActuateError(message or "API request failed", method=method, url=url, status_code=response.status_code, code=code, body=payload.get("data"))
        return payload.get("data")

    def _get_raw(self, path: str) -> bytes:
        """Perform a GET request and return the raw response body.

        Used for endpoints such as ticket attachment downloads and previews
        that answer with the binary payload directly rather than the
        code/message/data envelope.

        Parameters:
            path: Relative vAPI2 path to request.
        """
        url = _with_key(urljoin(self.base_url, path), self._api_key)
        response = self.session.request("GET", url, timeout=self.timeout)
        if response.status_code < 200 or response.status_code >= 300:
            raise NetActuateError(
                "got an error response",
                method="GET",
                url=url,
                status_code=response.status_code,
                body=getattr(response, "text", ""),
            )
        return response.content


class V3Client:
    """Client for NetActuate vAPI3.

    Parameters:
        api_key: API key. When omitted, `NETACTUATE_API_KEY` is used.
        base_url: vAPI3 base URL. Empty means production.
        session: Optional `requests.Session` compatible transport.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "",
        session: Optional[requests.Session] = None,
        timeout: float = 120.0,
    ) -> None:
        self._api_key = _api_key(api_key)
        self.base_url = base_url or V3_BASE_URL
        self.session = session or requests.Session()
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"V3Client(base_url={self.base_url!r})"

    def list_vpcs(self) -> List[VPC]:
        """Return all VPCs visible to the account."""
        return [VPC.from_api(row) for row in self._get_list("/vpcs")]

    def get_vpc(self, vpc_id: int) -> VPC:
        """Return one VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        return VPC.from_api(self._request("GET", f"/vpcs/{vpc_id}"))

    def list_vpc_locations(self) -> List[VPCLocation]:
        """Return the locations where VPCs can be created."""
        data = self._request("GET", "/vpcs/locations")
        if not isinstance(data, list):
            raise NetActuateError("VPC locations response must be a list")
        return [VPCLocation.from_api(row) for row in data]

    def create_vpc(
        self,
        label: str,
        description: str = "",
        location_id: int = 0,
        network: Optional[Mapping[str, Any]] = None,
        nameservers: Optional[Mapping[str, Any]] = None,
        firewalls: Optional[Mapping[str, Any]] = None,
        defaults: Optional[Mapping[str, Any]] = None,
    ) -> VPC:
        """Create a VPC.

        Parameters:
            label: Display label for the VPC.
            description: Optional description.
            location_id: Location identifier to create the VPC in.
            network: Optional network block, passed through as the API expects it.
            nameservers: Optional nameservers block, passed through as the API expects it.
            firewalls: Optional firewalls block, passed through as the API expects it.
            defaults: Optional defaults block, passed through as the API expects it.
        """
        body: Dict[str, Any] = {
            "label": label,
            "description": description,
            "location_id": location_id,
        }
        if network is not None:
            body["network"] = dict(network)
        if nameservers is not None:
            body["nameservers"] = dict(nameservers)
        if firewalls is not None:
            body["firewalls"] = dict(firewalls)
        if defaults is not None:
            body["defaults"] = dict(defaults)
        return VPC.from_api(self._post_json("/vpcs", body))

    def update_vpc(
        self,
        vpc_id: int,
        label: str = "",
        description: str = "",
        firewalls: Optional[Mapping[str, Any]] = None,
    ) -> VPC:
        """Update a VPC's label, description and firewall toggles.

        Parameters:
            vpc_id: VPC identifier to update.
            label: Optional new display label.
            description: Optional new description.
            firewalls: Optional firewalls block, passed through as the API expects it.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if description:
            body["description"] = description
        if firewalls is not None:
            body["firewalls"] = dict(firewalls)
        return VPC.from_api(self._patch_json(f"/vpcs/{vpc_id}", body))

    def delete_vpc(self, vpc_id: int) -> None:
        """Delete a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        self._delete(f"/vpcs/{vpc_id}")

    def add_vpc_standby_gateway(self, vpc_id: int) -> None:
        """Add a redundant standby gateway to a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        self._post_json(f"/vpcs/{vpc_id}/gateway/standby", None)

    def delete_vpc_standby_gateway(self, vpc_id: int) -> None:
        """Remove the redundant standby gateway from a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        self._delete(f"/vpcs/{vpc_id}/gateway/standby")

    def get_vpc_ip_reservations(self, vpc_id: int) -> VPCIPReservations:
        """Return the gateway, interface and VM IP reservations for a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        return VPCIPReservations.from_api(self._request("GET", f"/vpcs/{vpc_id}/ip-reservations"))

    def get_vpc_ssh_settings(self, vpc_id: int) -> VPCSSHSettings:
        """Return the bastion SSH settings for a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        return VPCSSHSettings.from_api(self._request("GET", f"/vpcs/{vpc_id}/ssh"))

    def update_vpc_ssh_settings(self, vpc_id: int, port: Optional[int] = None) -> VPCSSHSettings:
        """Update the bastion SSH port for a VPC.

        Parameters:
            vpc_id: VPC identifier.
            port: New bastion SSH port, or None to clear it.
        """
        return VPCSSHSettings.from_api(self._patch_json(f"/vpcs/{vpc_id}/ssh", {"port": port}))

    def list_vpc_ssh_keys(self, vpc_id: int) -> List[VPCSSHKey]:
        """Return the SSH keys enabled on a VPC's bastion.

        Parameters:
            vpc_id: VPC identifier.
        """
        return [VPCSSHKey.from_api(row) for row in self._get_list(f"/vpcs/{vpc_id}/ssh/keys")]

    def get_vpc_ssh_key(self, vpc_id: int, ssh_key_id: int) -> VPCSSHKey:
        """Return one SSH key enabled on a VPC's bastion.

        Lists the VPC's SSH keys and filters by id, since there is no
        single-key get endpoint, and raises NotFoundError when no key
        matches so a caller can tell gone from failed.

        Parameters:
            vpc_id: VPC identifier.
            ssh_key_id: SSH key identifier to look up.
        """
        path = f"/vpcs/{vpc_id}/ssh/keys"
        for key in self.list_vpc_ssh_keys(vpc_id):
            if key.effective_id == ssh_key_id:
                return key
        raise NotFoundError(
            f"SSH key {ssh_key_id} not found in VPC {vpc_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def enable_vpc_ssh_key(self, vpc_id: int, ssh_key_id: int, enabled: bool) -> None:
        """Enable or disable an SSH key on a VPC's bastion.

        Parameters:
            vpc_id: VPC identifier.
            ssh_key_id: SSH key identifier to enable or disable.
            enabled: True to enable the key, False to disable it.
        """
        self._patch_json(f"/vpcs/{vpc_id}/ssh/keys/{ssh_key_id}", {"enabled": enabled})

    def delete_vpc_ssh_key(self, vpc_id: int, ssh_key_id: int) -> None:
        """Remove an SSH key from a VPC's bastion.

        The API models removal as disabling the key; there is no separate
        delete endpoint.

        Parameters:
            vpc_id: VPC identifier.
            ssh_key_id: SSH key identifier to remove.
        """
        self.enable_vpc_ssh_key(vpc_id, ssh_key_id, False)

    def wait_for_vpc_ready(self, vpc_id: int, interval: float = 60.0, timeout: float = 600.0) -> VPC:
        """Poll a VPC until its status reaches Running or the timeout elapses.

        Parameters:
            vpc_id: VPC identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        deadline = time.monotonic() + timeout
        vpc = self.get_vpc(vpc_id)
        if vpc.metadata.get("status") == "Running":
            return vpc
        while time.monotonic() < deadline:
            time.sleep(max(min(interval, deadline - time.monotonic()), 0))
            vpc = self.get_vpc(vpc_id)
            if vpc.metadata.get("status") == "Running":
                return vpc
        raise NetActuateError(
            f"timeout waiting for VPC {vpc_id} to become ready after {timeout} seconds",
            method="GET",
            url=f"/vpcs/{vpc_id}",
        )

    def create_vpc_backend_template(
        self,
        vpc_id: int,
        name: str = "",
        description: str = "",
        backend_hosts: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> VPCBackendTemplate:
        """Create a backend template for a VPC.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            name: Optional template name.
            description: Optional template description.
            backend_hosts: Optional backend hosts to seed the template with, each
                a mapping with name, address and internal_address keys.
        """
        body: Dict[str, Any] = {}
        if name:
            body["name"] = name
        if description:
            body["description"] = description
        if backend_hosts is not None:
            body["backendHosts"] = [_encode_backend_host(host) for host in backend_hosts]
        return VPCBackendTemplate.from_api(
            self._post_json(f"/vpcs/{vpc_id}/backend-templates", body)
        )

    def get_vpc_backend_template(self, vpc_id: int, template_id: int) -> VPCBackendTemplate:
        """Return one VPC backend template.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier.
        """
        return VPCBackendTemplate.from_api(
            self._request("GET", f"/vpcs/{vpc_id}/backend-templates/{template_id}")
        )

    def list_vpc_backend_templates(self, vpc_id: int) -> List[VPCBackendTemplate]:
        """Return all backend templates for a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        return [
            VPCBackendTemplate.from_api(row)
            for row in self._get_list(f"/vpcs/{vpc_id}/backend-templates")
        ]

    def update_vpc_backend_template(
        self, vpc_id: int, template_id: int, name: str = "", description: str = ""
    ) -> VPCBackendTemplate:
        """Update a backend template's name and description.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier to update.
            name: Optional new template name.
            description: Optional new template description.
        """
        body: Dict[str, Any] = {}
        if name:
            body["name"] = name
        if description:
            body["description"] = description
        return VPCBackendTemplate.from_api(
            self._patch_json(f"/vpcs/{vpc_id}/backend-templates/{template_id}", body)
        )

    def replace_vpc_backend_template(
        self,
        vpc_id: int,
        template_id: int,
        backend_hosts: Sequence[Mapping[str, Any]],
        name: str = "",
        description: str = "",
    ) -> VPCBackendTemplate:
        """Replace a backend template's hosts, name and description.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier to replace.
            backend_hosts: Complete set of backend hosts the template should hold
                afterward, each a mapping with name, address and internal_address keys.
            name: Optional new template name.
            description: Optional new template description.
        """
        body: Dict[str, Any] = {
            "backendHosts": [_encode_backend_host(host) for host in backend_hosts]
        }
        if name:
            body["name"] = name
        if description:
            body["description"] = description
        return VPCBackendTemplate.from_api(
            self._put_json(f"/vpcs/{vpc_id}/backend-templates/{template_id}", body)
        )

    def delete_vpc_backend_template(self, vpc_id: int, template_id: int) -> None:
        """Delete a backend template.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier.
        """
        self._delete(f"/vpcs/{vpc_id}/backend-templates/{template_id}")

    def create_vpc_backend(self, vpc_id: int, template_id: int, address: str, name: str = "") -> VPCBackend:
        """Add a backend host to a template.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier to add the host to.
            address: Backend host address.
            name: Optional backend host name.
        """
        body: Dict[str, Any] = {"address": address}
        if name:
            body["name"] = name
        return VPCBackend.from_api(
            self._post_json(f"/vpcs/{vpc_id}/backend-templates/{template_id}/backends", body)
        )

    def replace_vpc_backends(
        self, vpc_id: int, template_id: int, backend_hosts: Sequence[Mapping[str, Any]]
    ) -> List[VPCBackend]:
        """Replace every backend host in a template.

        The endpoint answers with an object carrying the backend hosts, not a
        bare array, so the response is unwrapped before decoding.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier whose hosts are replaced.
            backend_hosts: Complete set of backend hosts the template should hold
                afterward, each a mapping with name, address and internal_address keys.
        """
        body = {"backendHosts": [_encode_backend_host(host) for host in backend_hosts]}
        data = self._put_json(f"/vpcs/{vpc_id}/backend-templates/{template_id}/backends", body)
        return [VPCBackend.from_api(row) for row in _unwrap_backend_hosts(data)]

    def list_vpc_backends(self, vpc_id: int, template_id: int) -> List[VPCBackend]:
        """Return all backend hosts in a template.

        The endpoint answers with an object carrying the backend hosts, not a
        bare array, so the response is unwrapped before decoding.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier.
        """
        data = self._request("GET", f"/vpcs/{vpc_id}/backend-templates/{template_id}/backends")
        return [VPCBackend.from_api(row) for row in _unwrap_backend_hosts(data)]

    def get_vpc_backend(self, vpc_id: int, template_id: int, backend_id: int) -> VPCBackend:
        """Return one backend host from a template.

        Lists the template's backend hosts and filters by id, since there is
        no single-backend get endpoint, and raises NotFoundError when no host
        matches so a caller can tell gone from failed.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier.
            backend_id: Backend host identifier.
        """
        path = f"/vpcs/{vpc_id}/backend-templates/{template_id}/backends"
        for backend in self.list_vpc_backends(vpc_id, template_id):
            if backend.backend_host_id == backend_id:
                return backend
        raise NotFoundError(
            f"backend {backend_id} not found in template {template_id} VPC {vpc_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_vpc_backend(
        self, vpc_id: int, template_id: int, backend_id: int, name: str = "", address: str = ""
    ) -> VPCBackend:
        """Update a backend host's name and address.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier.
            backend_id: Backend host identifier to update.
            name: Optional new name.
            address: Optional new address.
        """
        body: Dict[str, Any] = {}
        if name:
            body["name"] = name
        if address:
            body["address"] = address
        return VPCBackend.from_api(
            self._patch_json(
                f"/vpcs/{vpc_id}/backend-templates/{template_id}/backends/{backend_id}", body
            )
        )

    def delete_vpc_backend(self, vpc_id: int, template_id: int, backend_id: int) -> None:
        """Delete a backend host from a template.

        Parameters:
            vpc_id: VPC identifier the template belongs to.
            template_id: Backend template identifier.
            backend_id: Backend host identifier.
        """
        self._delete(f"/vpcs/{vpc_id}/backend-templates/{template_id}/backends/{backend_id}")

    def create_vpc_floating_ip(self, vpc_id: int, ip_version: int, ptr: str = "") -> int:
        """Create a floating IP on a VPC.

        Parameters:
            vpc_id: VPC identifier to create the floating IP on.
            ip_version: IP version of the floating IP, 4 or 6.
            ptr: Optional PTR record for the floating IP.
        """
        body: Dict[str, Any] = {"ipVersion": ip_version}
        if ptr:
            body["ptr"] = ptr
        data = self._post_json(f"/vpcs/{vpc_id}/floating-ips", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("VPC floating IP create response must be an object")
        return _response_int(data, "floatingIpId")

    def list_vpc_floating_ips(self, vpc_id: int) -> List[VPCFloatingIP]:
        """Return all floating IPs attached to a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        return [VPCFloatingIP.from_api(row) for row in self._get_list(f"/vpcs/{vpc_id}/floating-ips")]

    def get_vpc_floating_ip(self, vpc_id: int, floating_ip_id: int) -> VPCFloatingIP:
        """Return one floating IP attached to a VPC.

        Lists the VPC's floating IPs and filters by id, since there is no
        single-floating-IP get endpoint, and raises NotFoundError when no
        floating IP matches so a caller can tell gone from failed.

        Parameters:
            vpc_id: VPC identifier.
            floating_ip_id: Floating IP identifier to look up.
        """
        path = f"/vpcs/{vpc_id}/floating-ips"
        for floating_ip in self.list_vpc_floating_ips(vpc_id):
            if floating_ip.floating_ip_id == floating_ip_id:
                return floating_ip
        raise NotFoundError(
            f"floating IP {floating_ip_id} not found in VPC {vpc_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_vpc_floating_ip(self, vpc_id: int, floating_ip_id: int, ptr: str) -> None:
        """Update a floating IP's PTR record.

        Parameters:
            vpc_id: VPC identifier the floating IP belongs to.
            floating_ip_id: Floating IP identifier to update.
            ptr: New PTR record.
        """
        self._patch_json(f"/vpcs/{vpc_id}/floating-ips/{floating_ip_id}", {"ptr": ptr})

    def delete_vpc_floating_ip(self, vpc_id: int, floating_ip_id: int) -> None:
        """Delete a floating IP from a VPC.

        Parameters:
            vpc_id: VPC identifier the floating IP belongs to.
            floating_ip_id: Floating IP identifier to delete.
        """
        self._delete(f"/vpcs/{vpc_id}/floating-ips/{floating_ip_id}")

    def list_cloud_floating_ipv4(self) -> List[CloudFloatingIPv4]:
        """Return all cloud floating IPv4 addresses on the account."""
        return [CloudFloatingIPv4.from_api(row) for row in self._get_list("/cloud/networking/floating-ips/ipv4")]

    def create_cloud_floating_ipv4(
        self, ptr_domain: Optional[str] = None, vlan_id: Optional[int] = None
    ) -> CloudFloatingIPv4:
        """Add a floating IPv4 address to the account.

        Parameters:
            ptr_domain: Optional PTR domain to assign to the address.
            vlan_id: Optional customer VLAN identifier to assign the address on.
        """
        body: Dict[str, Any] = {}
        if ptr_domain is not None:
            body["ptrDomain"] = ptr_domain
        if vlan_id is not None:
            body["vlanId"] = vlan_id
        return CloudFloatingIPv4.from_api(self._post_json("/cloud/networking/floating-ips/ipv4", body))

    def delete_cloud_floating_ipv4(self, floating_ipv4_id: int) -> None:
        """Delete a cloud floating IPv4 address.

        Parameters:
            floating_ipv4_id: Floating IPv4 address identifier.
        """
        self._delete(f"/cloud/networking/floating-ips/ipv4/{floating_ipv4_id}")

    def list_cloud_floating_ipv4_vms(self, floating_ipv4_id: int) -> List[CloudFloatingIPv4VM]:
        """Return the VMs allowed to access a cloud floating IPv4 address.

        Parameters:
            floating_ipv4_id: Floating IPv4 address identifier.
        """
        return [
            CloudFloatingIPv4VM.from_api(row)
            for row in self._get_list(f"/cloud/networking/floating-ips/ipv4/{floating_ipv4_id}/vms")
        ]

    def grant_cloud_floating_ipv4_vms(
        self, floating_ipv4_id: int, mbpkgids: Sequence[int], revoke_existing: Optional[bool] = None
    ) -> None:
        """Grant VMs access to a cloud floating IPv4 address.

        Parameters:
            floating_ipv4_id: Floating IPv4 address identifier.
            mbpkgids: VM package identifiers to grant access to.
            revoke_existing: Optional flag revoking every other VM's access first.
        """
        body: Dict[str, Any] = {"vms": [{"mbpkgid": mbpkgid} for mbpkgid in mbpkgids]}
        if revoke_existing is not None:
            body["revokeExisting"] = revoke_existing
        self._post_json(f"/cloud/networking/floating-ips/ipv4/{floating_ipv4_id}/vms/mass-grant", body)

    def revoke_cloud_floating_ipv4_vms(self, floating_ipv4_id: int, mbpkgids: Sequence[int]) -> None:
        """Revoke VM access to a cloud floating IPv4 address.

        Parameters:
            floating_ipv4_id: Floating IPv4 address identifier.
            mbpkgids: VM package identifiers to revoke access from.
        """
        body = {"vms": [{"mbpkgid": mbpkgid} for mbpkgid in mbpkgids]}
        self._post_json(f"/cloud/networking/floating-ips/ipv4/{floating_ipv4_id}/vms/mass-revoke", body)

    def list_cloud_networking_locations(self) -> List[CloudNetworkingLocation]:
        """Return the cloud location to datacenter mappings."""
        data = self._request("GET", "/cloud/networking/locations")
        if not isinstance(data, list):
            raise NetActuateError("cloud networking locations response must be a list")
        return [CloudNetworkingLocation.from_api(row) for row in data]

    def create_vpc_firewall_rule(
        self,
        vpc_id: int,
        ip_version: int,
        direction: str,
        protocol: str = "",
        description: str = "",
        network: str = "",
        port: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Create a gateway firewall rule for a VPC.

        Parameters:
            vpc_id: VPC identifier to create the rule on.
            ip_version: IP version the rule applies to, 4 or 6.
            direction: Traffic direction, inbound or outbound.
            protocol: Optional protocol the rule matches.
            description: Optional rule description.
            network: Optional CIDR network the rule matches.
            port: Optional port range, passed through as the API expects it.
        """
        body: Dict[str, Any] = {"ipVersion": ip_version, "direction": direction}
        if protocol:
            body["protocol"] = protocol
        if description:
            body["description"] = description
        if network:
            body["network"] = network
        if port is not None:
            body["port"] = dict(port)
        data = self._post_json(f"/vpcs/{vpc_id}/gateway/rules/firewall", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("VPC firewall rule create response must be an object")
        return _response_int(data, "firewallRuleId")

    def list_vpc_firewall_rules_all(self, vpc_id: int) -> List[VPCFirewallRule]:
        """Return every gateway firewall rule for a VPC, across IP versions.

        Parameters:
            vpc_id: VPC identifier.
        """
        return [
            VPCFirewallRule.from_api(row)
            for row in self._get_list(f"/vpcs/{vpc_id}/gateway/rules/firewall")
        ]

    def list_vpc_firewall_rules(self, vpc_id: int, ip_version: int) -> List[VPCFirewallRule]:
        """Return the gateway firewall rules for a VPC at one IP version.

        Parameters:
            vpc_id: VPC identifier.
            ip_version: IP version to list rules for, 4 or 6.
        """
        path = f"/vpcs/{vpc_id}/gateway/rules/firewall/ipv{ip_version}"
        return [VPCFirewallRule.from_api(row) for row in self._get_list(path)]

    def get_vpc_firewall_rule(self, vpc_id: int, rule_id: int, ip_version: int) -> VPCFirewallRule:
        """Return one gateway firewall rule for a VPC.

        Lists the VPC's firewall rules at the given IP version and filters
        by id, since there is no single-rule get endpoint, and raises
        NotFoundError when no rule matches so a caller can tell gone from
        failed.

        Parameters:
            vpc_id: VPC identifier.
            rule_id: Firewall rule identifier to look up.
            ip_version: IP version the rule was created under, 4 or 6.
        """
        path = f"/vpcs/{vpc_id}/gateway/rules/firewall/ipv{ip_version}"
        for rule in self.list_vpc_firewall_rules(vpc_id, ip_version):
            if rule.firewall_rule_id == rule_id:
                return rule
        raise NotFoundError(
            f"firewall rule {rule_id} not found in VPC {vpc_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_vpc_firewall_rule(
        self,
        vpc_id: int,
        rule_id: int,
        direction: str = "",
        ip_version: int = 0,
        protocol: str = "",
        description: str = "",
        network: str = "",
        port: Optional[Mapping[str, Any]] = None,
    ) -> VPCFirewallRule:
        """Update a gateway firewall rule.

        Parameters:
            vpc_id: VPC identifier the rule belongs to.
            rule_id: Firewall rule identifier to update.
            direction: Optional new traffic direction.
            ip_version: Optional new IP version, 4 or 6.
            protocol: Optional new protocol.
            description: Optional new description.
            network: Optional new CIDR network.
            port: Optional new port range, passed through as the API expects it.
        """
        body: Dict[str, Any] = {}
        if direction:
            body["direction"] = direction
        if ip_version:
            body["ipVersion"] = ip_version
        if protocol:
            body["protocol"] = protocol
        if description:
            body["description"] = description
        if network:
            body["network"] = network
        if port is not None:
            body["port"] = dict(port)
        return VPCFirewallRule.from_api(
            self._patch_json(f"/vpcs/{vpc_id}/gateway/rules/firewall/{rule_id}", body)
        )

    def delete_vpc_firewall_rule(self, vpc_id: int, rule_id: int) -> None:
        """Delete a gateway firewall rule.

        Parameters:
            vpc_id: VPC identifier the rule belongs to.
            rule_id: Firewall rule identifier to delete.
        """
        self._delete(f"/vpcs/{vpc_id}/gateway/rules/firewall/{rule_id}")

    def apply_vpc_firewall_changes(self, vpc_id: int) -> None:
        """Apply pending gateway firewall rule changes for a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        self._post_json(f"/vpcs/{vpc_id}/gateway/rules/firewall/apply-changes")

    def create_vpc_snat_rule(
        self,
        vpc_id: int,
        ip_version: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> VPCSNATRule:
        """Create a gateway SNAT rule for a VPC.

        Parameters:
            vpc_id: VPC identifier to create the rule on.
            ip_version: IP version the rule applies to, 4 or 6.
            protocol: Optional protocol the rule matches.
            description: Optional rule description.
            match: Optional match block, passed through as the API expects it.
            translation: Optional translation block, passed through as the API expects it.
            priority: Optional priority block, passed through as the API expects it.
        """
        body: Dict[str, Any] = {"ipVersion": ip_version}
        if protocol:
            body["protocol"] = protocol
        if description:
            body["description"] = description
        if match is not None:
            body["match"] = dict(match)
        if translation is not None:
            body["translation"] = dict(translation)
        if priority is not None:
            body["priority"] = dict(priority)
        return VPCSNATRule.from_api(self._post_json(f"/vpcs/{vpc_id}/gateway/rules/snat", body))

    def list_vpc_snat_rules_all(self, vpc_id: int) -> List[VPCSNATRule]:
        """Return every gateway SNAT rule for a VPC, across IP versions.

        Parameters:
            vpc_id: VPC identifier.
        """
        return [
            VPCSNATRule.from_api(row) for row in self._get_list(f"/vpcs/{vpc_id}/gateway/rules/snat")
        ]

    def list_vpc_snat_rules(self, vpc_id: int, ip_version: int) -> List[VPCSNATRule]:
        """Return the gateway SNAT rules for a VPC at one IP version.

        Parameters:
            vpc_id: VPC identifier.
            ip_version: IP version to list rules for, 4 or 6.
        """
        path = f"/vpcs/{vpc_id}/gateway/rules/snat/ipv{ip_version}"
        return [VPCSNATRule.from_api(row) for row in self._get_list(path)]

    def get_vpc_snat_rule(self, vpc_id: int, rule_id: int, ip_version: int) -> VPCSNATRule:
        """Return one gateway SNAT rule for a VPC.

        Lists the VPC's SNAT rules at the given IP version and filters by
        id, since there is no single-rule get endpoint, and raises
        NotFoundError when no rule matches so a caller can tell gone from
        failed.

        Parameters:
            vpc_id: VPC identifier.
            rule_id: SNAT rule identifier to look up.
            ip_version: IP version the rule was created under, 4 or 6.
        """
        path = f"/vpcs/{vpc_id}/gateway/rules/snat/ipv{ip_version}"
        for rule in self.list_vpc_snat_rules(vpc_id, ip_version):
            if rule.snat_rule_id == rule_id:
                return rule
        raise NotFoundError(
            f"SNAT rule {rule_id} not found in VPC {vpc_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_vpc_snat_rule(
        self,
        vpc_id: int,
        rule_id: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> VPCSNATRule:
        """Update a gateway SNAT rule.

        Parameters:
            vpc_id: VPC identifier the rule belongs to.
            rule_id: SNAT rule identifier to update.
            protocol: Optional new protocol.
            description: Optional new description.
            match: Optional new match block, passed through as the API expects it.
            translation: Optional new translation block, passed through as the API expects it.
            priority: Optional new priority block, passed through as the API expects it.
        """
        body: Dict[str, Any] = {}
        if protocol:
            body["protocol"] = protocol
        if description:
            body["description"] = description
        if match is not None:
            body["match"] = dict(match)
        if translation is not None:
            body["translation"] = dict(translation)
        if priority is not None:
            body["priority"] = dict(priority)
        return VPCSNATRule.from_api(
            self._patch_json(f"/vpcs/{vpc_id}/gateway/rules/snat/{rule_id}", body)
        )

    def delete_vpc_snat_rule(self, vpc_id: int, rule_id: int) -> None:
        """Delete a gateway SNAT rule.

        Parameters:
            vpc_id: VPC identifier the rule belongs to.
            rule_id: SNAT rule identifier to delete.
        """
        self._delete(f"/vpcs/{vpc_id}/gateway/rules/snat/{rule_id}")

    def apply_vpc_snat_changes(self, vpc_id: int) -> None:
        """Apply pending gateway SNAT rule changes for a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        self._post_json(f"/vpcs/{vpc_id}/gateway/rules/snat/apply-changes")

    def create_vpc_dnat_rule(
        self,
        vpc_id: int,
        ip_version: int,
        translation: Mapping[str, Any],
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> VPCDNATRule:
        """Create a gateway DNAT rule for a VPC.

        Parameters:
            vpc_id: VPC identifier to create the rule on.
            ip_version: IP version the rule applies to, 4 or 6.
            translation: Translation block the rule applies, passed through as
                the API expects it. The API requires an address in this block.
            protocol: Optional protocol the rule matches.
            description: Optional rule description.
            match: Optional match block, passed through as the API expects it.
            priority: Optional priority block, passed through as the API expects it.
        """
        body: Dict[str, Any] = {"ipVersion": ip_version, "translation": dict(translation)}
        if protocol:
            body["protocol"] = protocol
        if description:
            body["description"] = description
        if match is not None:
            body["match"] = dict(match)
        if priority is not None:
            body["priority"] = dict(priority)
        return VPCDNATRule.from_api(self._post_json(f"/vpcs/{vpc_id}/gateway/rules/dnat", body))

    def list_vpc_dnat_rules_all(self, vpc_id: int) -> List[VPCDNATRule]:
        """Return every gateway DNAT rule for a VPC, across IP versions.

        Parameters:
            vpc_id: VPC identifier.
        """
        return [
            VPCDNATRule.from_api(row) for row in self._get_list(f"/vpcs/{vpc_id}/gateway/rules/dnat")
        ]

    def list_vpc_dnat_rules(self, vpc_id: int, ip_version: int) -> List[VPCDNATRule]:
        """Return the gateway DNAT rules for a VPC at one IP version.

        Parameters:
            vpc_id: VPC identifier.
            ip_version: IP version to list rules for, 4 or 6.
        """
        path = f"/vpcs/{vpc_id}/gateway/rules/dnat/ipv{ip_version}"
        return [VPCDNATRule.from_api(row) for row in self._get_list(path)]

    def get_vpc_dnat_rule(self, vpc_id: int, rule_id: int, ip_version: int) -> VPCDNATRule:
        """Return one gateway DNAT rule for a VPC.

        Lists the VPC's DNAT rules at the given IP version and filters by
        id, since there is no single-rule get endpoint, and raises
        NotFoundError when no rule matches so a caller can tell gone from
        failed.

        Parameters:
            vpc_id: VPC identifier.
            rule_id: DNAT rule identifier to look up.
            ip_version: IP version the rule was created under, 4 or 6.
        """
        path = f"/vpcs/{vpc_id}/gateway/rules/dnat/ipv{ip_version}"
        for rule in self.list_vpc_dnat_rules(vpc_id, ip_version):
            if rule.dnat_rule_id == rule_id:
                return rule
        raise NotFoundError(
            f"DNAT rule {rule_id} not found in VPC {vpc_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_vpc_dnat_rule(
        self,
        vpc_id: int,
        rule_id: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> VPCDNATRule:
        """Update a gateway DNAT rule.

        Parameters:
            vpc_id: VPC identifier the rule belongs to.
            rule_id: DNAT rule identifier to update.
            protocol: Optional new protocol.
            description: Optional new description.
            match: Optional new match block, passed through as the API expects it.
            translation: Optional new translation block, passed through as the API expects it.
            priority: Optional new priority block, passed through as the API expects it.
        """
        body: Dict[str, Any] = {}
        if protocol:
            body["protocol"] = protocol
        if description:
            body["description"] = description
        if match is not None:
            body["match"] = dict(match)
        if translation is not None:
            body["translation"] = dict(translation)
        if priority is not None:
            body["priority"] = dict(priority)
        return VPCDNATRule.from_api(
            self._patch_json(f"/vpcs/{vpc_id}/gateway/rules/dnat/{rule_id}", body)
        )

    def delete_vpc_dnat_rule(self, vpc_id: int, rule_id: int) -> None:
        """Delete a gateway DNAT rule.

        Parameters:
            vpc_id: VPC identifier the rule belongs to.
            rule_id: DNAT rule identifier to delete.
        """
        self._delete(f"/vpcs/{vpc_id}/gateway/rules/dnat/{rule_id}")

    def apply_vpc_dnat_changes(self, vpc_id: int) -> None:
        """Apply pending gateway DNAT rule changes for a VPC.

        Parameters:
            vpc_id: VPC identifier.
        """
        self._post_json(f"/vpcs/{vpc_id}/gateway/rules/dnat/apply-changes")

    def list_storage_types(self) -> List[StorageType]:
        """Return the storage types available to the account."""
        return _decode_storage_types(self._request("GET", "/storage"))

    def create_storage_bucket(
        self,
        location_id: int,
        label: str,
        capacity: int = 0,
        private: Optional[bool] = None,
        enable_auto_scaling: Optional[bool] = None,
    ) -> int:
        """Create a storage bucket and return its bucket id.

        Parameters:
            location_id: Location identifier to create the bucket in.
            label: Display label for the bucket.
            capacity: Optional requested capacity in GB.
            private: Optional flag marking the bucket private.
            enable_auto_scaling: Optional flag enabling capacity auto scaling.
        """
        body: Dict[str, Any] = {"locationId": location_id, "label": label}
        if capacity:
            body["capacity"] = capacity
        if private is not None:
            body["private"] = private
        if enable_auto_scaling is not None:
            body["enableAutoScaling"] = enable_auto_scaling
        data = self._post_json("/storage/buckets", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("storage bucket create response must be an object")
        return _response_int(data, "bucketId")

    def list_storage_buckets(self) -> List[StorageBucket]:
        """Return all storage buckets visible to the account."""
        return [StorageBucket.from_api(row) for row in self._get_list("/storage/buckets?limit=1000")]

    def get_storage_bucket(self, bucket_id: int) -> StorageBucket:
        """Return one storage bucket.

        Parameters:
            bucket_id: Storage bucket identifier.
        """
        return StorageBucket.from_api(self._request("GET", f"/storage/buckets/{bucket_id}"))

    def update_storage_bucket(
        self,
        bucket_id: int,
        label: str = "",
        capacity: int = 0,
        enable_auto_scaling: Optional[bool] = None,
        private: Optional[bool] = None,
    ) -> None:
        """Update a storage bucket's label, capacity, auto scaling and privacy.

        Parameters:
            bucket_id: Storage bucket identifier to update.
            label: Optional new display label.
            capacity: Optional new requested capacity in GB.
            enable_auto_scaling: Optional flag enabling capacity auto scaling.
            private: Optional flag marking the bucket private.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if capacity:
            body["capacity"] = capacity
        if enable_auto_scaling is not None:
            body["enableAutoScaling"] = enable_auto_scaling
        if private is not None:
            body["private"] = private
        self._patch_json(f"/storage/buckets/{bucket_id}", body)

    def delete_storage_bucket(self, bucket_id: int) -> None:
        """Delete a storage bucket.

        Parameters:
            bucket_id: Storage bucket identifier.
        """
        self._delete(f"/storage/buckets/{bucket_id}")

    def convert_storage_bucket_to_store(self, bucket_id: int) -> int:
        """Convert a storage bucket into an object store and return the new object store id.

        Parameters:
            bucket_id: Storage bucket identifier to convert.
        """
        data = self._post_json(f"/storage/buckets/{bucket_id}/convert-to-store")
        if not isinstance(data, Mapping):
            raise NetActuateError("storage bucket convert response must be an object")
        return _response_int(data, "objectStoreId")

    def wait_for_storage_bucket_ready(
        self, bucket_id: int, interval: float = 10.0, timeout: float = 120.0
    ) -> StorageBucket:
        """Poll a storage bucket until it reports ready or the timeout elapses.

        Parameters:
            bucket_id: Storage bucket identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        return self._wait_for_storage_ready(
            self.get_storage_bucket, bucket_id, f"/storage/buckets/{bucket_id}", interval, timeout, "storage bucket"
        )

    def create_storage_object_store(
        self,
        location_id: int,
        label: str,
        capacity: int = 0,
        enable_auto_scaling: Optional[bool] = None,
    ) -> int:
        """Create an object store and return its object store id.

        Parameters:
            location_id: Location identifier to create the object store in.
            label: Display label for the object store.
            capacity: Optional requested capacity in GB.
            enable_auto_scaling: Optional flag enabling capacity auto scaling.
        """
        body: Dict[str, Any] = {"locationId": location_id, "label": label}
        if capacity:
            body["capacity"] = capacity
        if enable_auto_scaling is not None:
            body["enableAutoScaling"] = enable_auto_scaling
        data = self._post_json("/storage/object-stores", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("storage object store create response must be an object")
        return _response_int(data, "objectStoreId")

    def list_storage_object_stores(self) -> List[StorageObjectStore]:
        """Return all object stores visible to the account."""
        return [
            StorageObjectStore.from_api(row)
            for row in self._get_list("/storage/object-stores?limit=1000")
        ]

    def get_storage_object_store(self, object_store_id: int) -> StorageObjectStore:
        """Return one object store.

        Parameters:
            object_store_id: Object store identifier.
        """
        return StorageObjectStore.from_api(
            self._request("GET", f"/storage/object-stores/{object_store_id}")
        )

    def update_storage_object_store(
        self,
        object_store_id: int,
        label: str = "",
        capacity: int = 0,
        enable_auto_scaling: Optional[bool] = None,
    ) -> None:
        """Update an object store's label, capacity and auto scaling.

        Parameters:
            object_store_id: Object store identifier to update.
            label: Optional new display label.
            capacity: Optional new requested capacity in GB.
            enable_auto_scaling: Optional flag enabling capacity auto scaling.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if capacity:
            body["capacity"] = capacity
        if enable_auto_scaling is not None:
            body["enableAutoScaling"] = enable_auto_scaling
        self._patch_json(f"/storage/object-stores/{object_store_id}", body)

    def delete_storage_object_store(self, object_store_id: int) -> None:
        """Delete an object store.

        Parameters:
            object_store_id: Object store identifier.
        """
        self._delete(f"/storage/object-stores/{object_store_id}")

    def wait_for_storage_object_store_ready(
        self, object_store_id: int, interval: float = 10.0, timeout: float = 120.0
    ) -> StorageObjectStore:
        """Poll an object store until it reports ready or the timeout elapses.

        Parameters:
            object_store_id: Object store identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        return self._wait_for_storage_ready(
            self.get_storage_object_store,
            object_store_id,
            f"/storage/object-stores/{object_store_id}",
            interval,
            timeout,
            "storage object store",
        )

    def create_storage_block_namespace(
        self,
        location_id: int,
        label: str,
        capacity: int = 0,
        enable_auto_scaling: Optional[bool] = None,
    ) -> int:
        """Create a block namespace and return its block namespace id.

        Parameters:
            location_id: Location identifier to create the block namespace in.
            label: Display label for the block namespace.
            capacity: Optional requested capacity in GB.
            enable_auto_scaling: Optional flag enabling capacity auto scaling.
        """
        body: Dict[str, Any] = {"locationId": location_id, "label": label}
        if capacity:
            body["capacity"] = capacity
        if enable_auto_scaling is not None:
            body["enableAutoScaling"] = enable_auto_scaling
        data = self._post_json("/storage/block-namespaces", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("storage block namespace create response must be an object")
        return _response_int(data, "blockNamespaceId")

    def list_storage_block_namespaces(self) -> List[StorageBlockNamespace]:
        """Return all block namespaces visible to the account."""
        return [
            StorageBlockNamespace.from_api(row)
            for row in self._get_list("/storage/block-namespaces?limit=1000")
        ]

    def get_storage_block_namespace(self, block_namespace_id: int) -> StorageBlockNamespace:
        """Return one block namespace.

        Parameters:
            block_namespace_id: Block namespace identifier.
        """
        return StorageBlockNamespace.from_api(
            self._request("GET", f"/storage/block-namespaces/{block_namespace_id}")
        )

    def update_storage_block_namespace(
        self,
        block_namespace_id: int,
        label: str = "",
        capacity: int = 0,
        enable_auto_scaling: Optional[bool] = None,
    ) -> None:
        """Update a block namespace's label, capacity and auto scaling.

        Parameters:
            block_namespace_id: Block namespace identifier to update.
            label: Optional new display label.
            capacity: Optional new requested capacity in GB.
            enable_auto_scaling: Optional flag enabling capacity auto scaling.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if capacity:
            body["capacity"] = capacity
        if enable_auto_scaling is not None:
            body["enableAutoScaling"] = enable_auto_scaling
        self._patch_json(f"/storage/block-namespaces/{block_namespace_id}", body)

    def delete_storage_block_namespace(self, block_namespace_id: int) -> None:
        """Delete a block namespace.

        Parameters:
            block_namespace_id: Block namespace identifier.
        """
        self._delete(f"/storage/block-namespaces/{block_namespace_id}")

    def wait_for_storage_block_namespace_ready(
        self, block_namespace_id: int, interval: float = 10.0, timeout: float = 120.0
    ) -> StorageBlockNamespace:
        """Poll a block namespace until it reports ready or the timeout elapses.

        Parameters:
            block_namespace_id: Block namespace identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        return self._wait_for_storage_ready(
            self.get_storage_block_namespace,
            block_namespace_id,
            f"/storage/block-namespaces/{block_namespace_id}",
            interval,
            timeout,
            "storage block namespace",
        )

    def create_storage_block_volume(self, location_id: int, label: str, capacity: int = 0) -> int:
        """Create a block volume and return its block volume id.

        Parameters:
            location_id: Location identifier to create the block volume in.
            label: Display label for the block volume.
            capacity: Optional requested capacity in GB.
        """
        body: Dict[str, Any] = {"locationId": location_id, "label": label}
        if capacity:
            body["capacity"] = capacity
        data = self._post_json("/storage/block-volumes", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("storage block volume create response must be an object")
        return _response_int(data, "blockVolumeId")

    def list_storage_block_volumes(self) -> List[StorageBlockVolume]:
        """Return all block volumes on the account.

        Uses the plain list endpoint because the single-volume get cannot be
        trusted for the block volume id; see `get_storage_block_volume`.
        """
        return [StorageBlockVolume.from_api(row) for row in self._get_list("/storage/block-volumes")]

    def get_storage_block_volume(self, block_volume_id: int) -> StorageBlockVolume:
        """Return one block volume.

        The single-volume get endpoint can answer with object-store-shaped
        metadata that omits the block volume id. When that happens the id
        that was requested is filled back in, since the get succeeded on
        that id, rather than surface a volume with no id at all.

        Parameters:
            block_volume_id: Block volume identifier.
        """
        volume = StorageBlockVolume.from_api(
            self._request("GET", f"/storage/block-volumes/{block_volume_id}")
        )
        if volume.block_volume_id == 0:
            volume.block_volume_id = block_volume_id
        return volume

    def update_storage_block_volume(
        self, block_volume_id: int, label: str = "", capacity: int = 0
    ) -> None:
        """Update a block volume's label and capacity.

        Parameters:
            block_volume_id: Block volume identifier to update.
            label: Optional new display label.
            capacity: Optional new requested capacity in GB.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if capacity:
            body["capacity"] = capacity
        self._patch_json(f"/storage/block-volumes/{block_volume_id}", body)

    def delete_storage_block_volume(self, block_volume_id: int) -> None:
        """Delete a block volume.

        Parameters:
            block_volume_id: Block volume identifier.
        """
        self._delete(f"/storage/block-volumes/{block_volume_id}")

    def wait_for_storage_block_volume_ready(
        self, block_volume_id: int, interval: float = 10.0, timeout: float = 120.0
    ) -> StorageBlockVolume:
        """Poll a block volume until it reports ready or the timeout elapses.

        Parameters:
            block_volume_id: Block volume identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        return self._wait_for_storage_ready(
            self.get_storage_block_volume,
            block_volume_id,
            f"/storage/block-volumes/{block_volume_id}",
            interval,
            timeout,
            "storage block volume",
        )

    def list_storage_locations(self) -> List[StorageLocation]:
        """Return the locations where storage resources can be created."""
        data = self._request("GET", "/storage/locations")
        if not isinstance(data, list):
            raise NetActuateError("storage locations response must be a list")
        return [StorageLocation.from_api(row) for row in data]

    def _wait_for_storage_ready(
        self,
        getter: Any,
        resource_id: int,
        path: str,
        interval: float,
        timeout: float,
        label: str,
    ) -> Any:
        """Poll a storage resource getter until its metadata reports ready.

        Parameters:
            getter: Bound method that takes the resource id and returns a
                decoded storage model with a metadata mapping.
            resource_id: Identifier passed to the getter on each poll.
            path: Request path recorded on the timeout error.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
            label: Resource kind named in the timeout error.
        """
        deadline = time.monotonic() + timeout
        resource = getter(resource_id)
        if resource.metadata.get("ready"):
            return resource
        while time.monotonic() < deadline:
            time.sleep(max(min(interval, deadline - time.monotonic()), 0))
            resource = getter(resource_id)
            if resource.metadata.get("ready"):
                return resource
        raise NetActuateError(
            f"timeout waiting for {label} {resource_id} to become ready after {timeout} seconds",
            method="GET",
            url=path,
        )

    def list_nke_versions(self) -> List[str]:
        """Return the Kubernetes versions available for new NKE clusters."""
        data = self._request("GET", "/nke/versions")
        if not isinstance(data, list):
            raise NetActuateError("NKE versions response must be a list")
        return [str(version) for version in data]

    def list_nke_clusters(self) -> List[NKECluster]:
        """Return all NKE clusters visible to the account."""
        return [NKECluster.from_api(row) for row in self._get_list("/nke/clusters")]

    def get_nke_cluster(self, cluster_id: int) -> NKECluster:
        """Return one NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return NKECluster.from_api(self._request("GET", f"/nke/clusters/{cluster_id}"))

    def create_nke_cluster(
        self,
        name: str,
        version: str,
        replicas: int,
        minimum_nodes: int,
        maximum_nodes: int,
        package_id: int,
        location_id: int,
        contract_id: Optional[int] = None,
        do_autoscaling: bool = False,
        do_dual_stack: bool = False,
        networking: Optional[Mapping[str, Any]] = None,
        kubernetes_dashboard: Optional[bool] = None,
        tag_ids: Optional[Sequence[int]] = None,
    ) -> int:
        """Create an NKE cluster and return its cluster id.

        Parameters:
            name: Cluster name.
            version: Kubernetes version to build, from `list_nke_versions`.
            replicas: Initial worker node count.
            minimum_nodes: Minimum worker node count for autoscaling.
            maximum_nodes: Maximum worker node count for autoscaling.
            package_id: Billing package identifier for the worker nodes.
            location_id: Location identifier to build the cluster in.
            contract_id: Optional contract identifier to bill the cluster to.
            do_autoscaling: Whether the worker node count autoscales between
                minimum_nodes and maximum_nodes.
            do_dual_stack: Whether the cluster is provisioned dual stack.
            networking: Optional networking block, passed through as the API
                expects it, for example vpcId, podCidr and serviceCidr.
            kubernetes_dashboard: Optional flag requesting the Kubernetes
                dashboard addon at creation.
            tag_ids: Optional tag identifiers to apply to the cluster.
        """
        billing: Dict[str, Any] = {"packageId": package_id, "locationId": location_id}
        if contract_id is not None:
            billing["contractId"] = contract_id
        body: Dict[str, Any] = {
            "name": name,
            "version": version,
            "replicas": replicas,
            "minimumNodes": minimum_nodes,
            "maximumNodes": maximum_nodes,
            "doAutoscaling": do_autoscaling,
            "doDualStack": do_dual_stack,
            "billing": billing,
        }
        if networking is not None:
            body["networking"] = dict(networking)
        if kubernetes_dashboard is not None:
            body["addonsToInstall"] = {"kubernetesDashboard": kubernetes_dashboard}
        if tag_ids:
            body["tags"] = [{"tagId": tag_id} for tag_id in tag_ids]
        data = self._post_json("/nke/clusters", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create NKE cluster response must be an object")
        return _response_int(data, "clusterId")

    def update_nke_cluster(
        self,
        cluster_id: int,
        name: str = "",
        version: str = "",
        do_autoscaling: Optional[bool] = None,
        package_id: Optional[int] = None,
        minimum_nodes: Optional[int] = None,
        maximum_nodes: Optional[int] = None,
        tag_ids: Optional[Sequence[int]] = None,
    ) -> None:
        """Update an NKE cluster's name, version, billing, node bounds and tags.

        Parameters:
            cluster_id: NKE cluster identifier to update.
            name: Optional new cluster name.
            version: Optional Kubernetes version to upgrade to.
            do_autoscaling: Optional new autoscaling flag.
            package_id: Optional new billing package identifier for worker nodes.
            minimum_nodes: Optional new minimum worker node count. Required to
                change node bounds at all, since it is not itself optional on
                the API's nodes block.
            maximum_nodes: Optional new maximum worker node count. Only sent
                when minimum_nodes is also given, and None clears the maximum
                rather than leaving it unspecified.
            tag_ids: Optional complete set of tag identifiers to apply.
        """
        body: Dict[str, Any] = {}
        if name:
            body["name"] = name
        if version:
            body["version"] = version
        if do_autoscaling is not None:
            body["doAutoscaling"] = do_autoscaling
        if package_id is not None:
            body["billing"] = {"packageId": package_id}
        if minimum_nodes is not None:
            body["nodes"] = {"minimum": minimum_nodes, "maximum": maximum_nodes}
        if tag_ids:
            body["tags"] = [{"tagId": tag_id} for tag_id in tag_ids]
        self._patch_json(f"/nke/clusters/{cluster_id}", body)

    def delete_nke_cluster(self, cluster_id: int) -> None:
        """Delete an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        self._delete(f"/nke/clusters/{cluster_id}")

    def generate_nke_kubeconfig(self, cluster_id: int, expiration_seconds: int = 3600) -> str:
        """Create a new access token and kubeconfig for a cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
            expiration_seconds: Token lifetime in seconds. Default 3600, maximum 3153600000.
        """
        data = self._post_json(
            f"/nke/clusters/{cluster_id}/kubeconfig", {"expirationSeconds": expiration_seconds}
        )
        if isinstance(data, str):
            return data
        return str(data)

    def create_nke_access_urls(self, cluster_id: int) -> NKEAccessURLs:
        """Create secure access URLs for an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return NKEAccessURLs.from_api(self._post_json(f"/nke/clusters/{cluster_id}/create-access-urls"))

    def list_nke_cluster_logs(self, cluster_id: int) -> List[NKELogEntry]:
        """Return the log entries recorded for an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return [
            NKELogEntry.from_api(row) for row in self._get_list(f"/nke/clusters/{cluster_id}/logs")
        ]

    def list_nke_worker_nodes(self, cluster_id: int) -> List[NKEWorkerNode]:
        """Return the worker nodes belonging to an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return [
            NKEWorkerNode.from_api(row)
            for row in self._get_list(f"/nke/clusters/{cluster_id}/worker-nodes")
        ]

    def get_nke_worker_node(self, cluster_id: int, worker_node_id: int) -> NKEWorkerNode:
        """Return one worker node.

        Parameters:
            cluster_id: NKE cluster identifier the worker node belongs to.
            worker_node_id: Worker node identifier.
        """
        path = f"/nke/clusters/{cluster_id}/worker-nodes/{worker_node_id}"
        return NKEWorkerNode.from_api(self._request("GET", path))

    def update_nke_worker_node(
        self,
        cluster_id: int,
        worker_node_id: int,
        label: str = "",
        tag_ids: Optional[Sequence[int]] = None,
    ) -> NKEWorkerNode:
        """Update a worker node's label and tags.

        Parameters:
            cluster_id: NKE cluster identifier the worker node belongs to.
            worker_node_id: Worker node identifier to update.
            label: Optional new display label.
            tag_ids: Optional complete set of tag identifiers to apply.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if tag_ids:
            body["tags"] = [{"tagId": tag_id} for tag_id in tag_ids]
        path = f"/nke/clusters/{cluster_id}/worker-nodes/{worker_node_id}"
        return NKEWorkerNode.from_api(self._patch_json(path, body))

    def delete_nke_worker_node(self, cluster_id: int, worker_node_id: int) -> None:
        """Delete a worker node from an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier the worker node belongs to.
            worker_node_id: Worker node identifier to delete.
        """
        self._delete(f"/nke/clusters/{cluster_id}/worker-nodes/{worker_node_id}")

    def wait_for_nke_worker_nodes(
        self, cluster_id: int, minimum: int, interval: float = 60.0, timeout: float = 900.0
    ) -> List[NKEWorkerNode]:
        """Poll until an NKE cluster lists at least a minimum number of worker nodes.

        A cluster can report Healthy before its worker nodes appear in the
        worker node listing, so polling the nodes themselves closes that window.

        Parameters:
            cluster_id: NKE cluster identifier to poll.
            minimum: Minimum worker node count to wait for. A non-positive
                value returns the current listing immediately.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        if minimum <= 0:
            return self.list_nke_worker_nodes(cluster_id)
        deadline = time.monotonic() + timeout
        nodes = self.list_nke_worker_nodes(cluster_id)
        if len(nodes) >= minimum:
            return nodes
        while time.monotonic() < deadline:
            time.sleep(max(min(interval, deadline - time.monotonic()), 0))
            nodes = self.list_nke_worker_nodes(cluster_id)
            if len(nodes) >= minimum:
                return nodes
        raise NetActuateError(
            f"timeout waiting for NKE cluster {cluster_id} to reach {minimum} worker nodes "
            f"after {timeout} seconds",
            method="GET",
            url=f"/nke/clusters/{cluster_id}/worker-nodes",
        )

    def wait_for_nke_cluster_healthy(
        self, cluster_id: int, interval: float = 60.0, timeout: float = 900.0
    ) -> NKECluster:
        """Poll an NKE cluster until its status reaches Healthy or the timeout elapses.

        Raises immediately, without waiting out the timeout, when the
        cluster reports a Failed or Error status.

        Parameters:
            cluster_id: NKE cluster identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
        """
        deadline = time.monotonic() + timeout
        while True:
            cluster = self.get_nke_cluster(cluster_id)
            status = str(cluster.status.get("cluster", ""))
            if status in ("Failed", "Error"):
                raise NetActuateError(
                    f"NKE cluster {cluster_id} entered failed state: {status}",
                    method="GET",
                    url=f"/nke/clusters/{cluster_id}",
                )
            if status == "Healthy":
                return cluster
            if time.monotonic() >= deadline:
                raise NetActuateError(
                    f"timeout waiting for NKE cluster {cluster_id} to become healthy "
                    f"after {timeout} seconds",
                    method="GET",
                    url=f"/nke/clusters/{cluster_id}",
                )
            time.sleep(max(min(interval, deadline - time.monotonic()), 0))

    def list_addon_catalog(self) -> List[NKEAddonCatalogEntry]:
        """Return the catalog of addon types installable on NKE clusters."""
        return [NKEAddonCatalogEntry.from_api(row) for row in self._get_list("/nke/addons")]

    def list_cluster_addons(self, cluster_id: int) -> List[NKEAddon]:
        """Return the addons installed on an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return [
            NKEAddon.from_api(row) for row in self._get_list(f"/nke/clusters/{cluster_id}/addons")
        ]

    def get_cluster_addon(self, cluster_id: int, addon_type: str) -> NKEAddon:
        """Return one addon installed on an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
            addon_type: Addon type, for example "netactuate-dns" or "storage".
        """
        path = f"/nke/clusters/{cluster_id}/addons/{addon_type}"
        return NKEAddon.from_api(self._request("GET", path))

    def create_cluster_addon(
        self,
        cluster_id: int,
        addon_type: str,
        version: str = "",
        channel: str = "",
        config: Optional[Mapping[str, Any]] = None,
    ) -> NKEAddon:
        """Install an addon on an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
            addon_type: Addon type to install, for example "netactuate-dns" or "storage".
            version: Optional addon version. Empty selects the catalog default.
            channel: Optional release channel.
            config: Optional addon-specific configuration block, passed
                through as the API expects it for the given addon_type, for
                example {"zone": ..., "mode": ...} for the DNS addon.
        """
        body: Dict[str, Any] = {"addonType": addon_type}
        if version:
            body["version"] = version
        if channel:
            body["channel"] = channel
        if config is not None:
            body["config"] = dict(config)
        return NKEAddon.from_api(self._post_json(f"/nke/clusters/{cluster_id}/addons", body))

    def update_cluster_addon(
        self,
        cluster_id: int,
        addon_type: str,
        version: str = "",
        channel: str = "",
        config: Optional[Mapping[str, Any]] = None,
    ) -> NKEAddon:
        """Update an addon installed on an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
            addon_type: Addon type to update, for example "netactuate-dns" or "storage".
            version: Optional new addon version.
            channel: Optional new release channel.
            config: Optional addon-specific configuration block, passed
                through as the API expects it for the given addon_type.
        """
        body: Dict[str, Any] = {}
        if version:
            body["version"] = version
        if channel:
            body["channel"] = channel
        if config is not None:
            body["config"] = dict(config)
        path = f"/nke/clusters/{cluster_id}/addons/{addon_type}"
        return NKEAddon.from_api(self._patch_json(path, body))

    def delete_cluster_addon(self, cluster_id: int, addon_type: str) -> None:
        """Remove an addon from an NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
            addon_type: Addon type to remove, for example "netactuate-dns" or "storage".
        """
        self._delete(f"/nke/clusters/{cluster_id}/addons/{addon_type}")

    def list_cluster_dns_zones(self, cluster_id: int) -> List[NKEClusterDNSZone]:
        """Return the DNS zones an NKE cluster's DNS addon manages.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return [
            NKEClusterDNSZone.from_api(row)
            for row in self._get_list(f"/nke/clusters/{cluster_id}/dns-zones")
        ]

    def create_oidc_client(
        self,
        label: str = "",
        description: str = "",
        jwks_uri: Optional[str] = None,
        account_default: bool = False,
        enforce_allow_list: bool = False,
        ttl: int = 0,
        default_audience: str = "",
    ) -> int:
        """Create an OIDC client and return its id.

        Parameters:
            label: Optional display label.
            description: Optional description.
            jwks_uri: Optional JWKS URI used to validate externally issued tokens.
            account_default: Whether this client is the account's default OIDC client.
            enforce_allow_list: Whether tokens are restricted to allow-listed VMs and servers.
            ttl: Optional token TTL in seconds.
            default_audience: Optional default token audience.
        """
        body: Dict[str, Any] = {
            "accountDefault": account_default,
            "enforceAllowList": enforce_allow_list,
        }
        if label:
            body["label"] = label
        if description:
            body["description"] = description
        if jwks_uri is not None:
            body["jwksUri"] = jwks_uri
        if ttl:
            body["ttl"] = ttl
        if default_audience:
            body["defaultAudience"] = default_audience
        data = self._post_json("/oidc/clients", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create OIDC client response must be an object")
        return _response_int(data, "clientId")

    def list_oidc_clients(self) -> List[OIDCClient]:
        """Return all OIDC clients on the account."""
        return self._list_oidc_clients_page("/oidc/clients?limit=1000")

    def _list_oidc_clients_page(self, path: str) -> List[OIDCClient]:
        data = self._request("GET", path)
        if not isinstance(data, Mapping):
            raise NetActuateError("OIDC clients response must be an object")
        tenant = data.get("tenant")
        wrapper = data.get("clients")
        rows = wrapper.get("data") if isinstance(wrapper, Mapping) else None
        if not isinstance(rows, list):
            raise NetActuateError("OIDC clients response is missing clients data")

        clients = [OIDCClient.from_api(row, tenant=tenant) for row in rows]

        meta = _meta(wrapper.get("meta"))
        if meta.get("total") and meta.get("limit") and meta["offset"] + meta["limit"] < meta["total"]:
            next_path = _page_path(path, offset=meta["offset"] + meta["limit"], limit=meta["limit"])
            clients.extend(self._list_oidc_clients_page(next_path))
        return clients

    def get_oidc_client(self, client_id: int) -> OIDCClient:
        """Return one OIDC client, with its keys, auth logs and change logs.

        There is no single endpoint carrying every field: the base fields
        come from `list_oidc_clients`, and the label, description, jwksUri
        and timestamps are then overlaid from the detail endpoint, along
        with the keys, auth logs and change logs it also carries. Raises
        `NotFoundError` when the client id is absent from `list_oidc_clients`.

        Parameters:
            client_id: OIDC client identifier.
        """
        path = f"/oidc/clients/{client_id}"
        detail = self._request("GET", path)
        if not isinstance(detail, Mapping):
            raise NetActuateError(f"OIDC client {client_id} detail response must be an object")

        client = None
        for candidate in self.list_oidc_clients():
            if candidate.client_id == client_id:
                client = candidate
                break
        if client is None:
            raise NotFoundError(
                f"OIDC client {client_id} not found in client list",
                method="GET",
                url=path,
                status_code=404,
                code=404,
            )

        metadata = detail.get("metadata")
        if isinstance(metadata, Mapping):
            client.created_on = str(metadata.get("createdOn", client.created_on))
            client.last_used_on = metadata.get("lastUsedOn", client.last_used_on)
            client.label = str(metadata.get("label", client.label))
            client.description = str(metadata.get("description", client.description))
            client.jwks_uri = metadata.get("jwksUri", client.jwks_uri)

        keys = _nested_list_data(detail.get("keys"))
        if keys is not None:
            client.keys = [OIDCClientKey.from_api(row) for row in keys]

        logs = detail.get("logs")
        if isinstance(logs, Mapping):
            auth_logs = _nested_list_data(logs.get("auth"))
            if auth_logs is not None:
                client.auth_logs = [OIDCClientAuthLog.from_api(row) for row in auth_logs]
            change_logs = _nested_list_data(logs.get("changes"))
            if change_logs is not None:
                client.change_logs = [OIDCClientChangeLog.from_api(row) for row in change_logs]

        return client

    def update_oidc_client(
        self,
        client_id: int,
        label: str = "",
        description: str = "",
        jwks_uri: Optional[str] = None,
        account_default: Optional[bool] = None,
        enforce_allow_list: Optional[bool] = None,
        ttl: int = 0,
        default_audience: str = "",
    ) -> None:
        """Update an OIDC client.

        Parameters:
            client_id: OIDC client identifier to update.
            label: Optional new display label.
            description: Optional new description.
            jwks_uri: Optional new JWKS URI.
            account_default: Optional new account-default flag.
            enforce_allow_list: Optional new allow-list enforcement flag.
            ttl: Optional new token TTL in seconds.
            default_audience: Optional new default token audience.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if description:
            body["description"] = description
        if jwks_uri is not None:
            body["jwksUri"] = jwks_uri
        if account_default is not None:
            body["accountDefault"] = account_default
        if enforce_allow_list is not None:
            body["enforceAllowList"] = enforce_allow_list
        if ttl:
            body["ttl"] = ttl
        if default_audience:
            body["defaultAudience"] = default_audience
        self._patch_json(f"/oidc/clients/{client_id}", body)

    def delete_oidc_client(self, client_id: int) -> None:
        """Delete an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
        """
        self._delete(f"/oidc/clients/{client_id}")

    def create_oidc_client_keys(
        self, client_id: int, keys: Sequence[Mapping[str, Any]]
    ) -> List[OIDCClientKey]:
        """Add one or more public keys to an OIDC client.

        Parameters:
            client_id: OIDC client identifier to add keys to.
            keys: One entry per key to create, each a mapping with
                `public_key` (required) and optional `label` and `description`.
        """
        items = []
        for key in keys:
            item: Dict[str, Any] = {"publicKey": key.get("public_key", key.get("publicKey", ""))}
            label = key.get("label")
            if label:
                item["label"] = label
            description = key.get("description")
            if description:
                item["description"] = description
            items.append(item)
        data = self._post_json(f"/oidc/clients/{client_id}/keys", {"keys": items})
        if not isinstance(data, Mapping):
            raise NetActuateError(f"create OIDC client {client_id} keys response must be an object")
        rows = data.get("keys")
        if not isinstance(rows, list):
            raise NetActuateError(f"create OIDC client {client_id} keys response is missing keys")
        return [OIDCClientKey.from_api(row) for row in rows]

    def list_oidc_client_keys(self, client_id: int) -> List[OIDCClientKey]:
        """Return the public keys registered to an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
        """
        return [
            OIDCClientKey.from_api(row)
            for row in self._get_list(f"/oidc/clients/{client_id}/keys?limit=1000")
        ]

    def update_oidc_client_key(
        self, client_id: int, key_id: int, label: str = "", description: str = ""
    ) -> None:
        """Update an OIDC client key's label and description.

        Parameters:
            client_id: OIDC client identifier the key belongs to.
            key_id: OIDC client key identifier to update.
            label: Optional new display label.
            description: Optional new description.
        """
        body: Dict[str, Any] = {}
        if label:
            body["label"] = label
        if description:
            body["description"] = description
        self._patch_json(f"/oidc/clients/{client_id}/keys/{key_id}", body)

    def delete_oidc_client_key(self, client_id: int, key_id: int) -> None:
        """Revoke an OIDC client key.

        Deleting a key revokes it. Revoking an already-revoked key answers
        HTTP 400 with "the key is revoked", which is treated as an already
        achieved, idempotent success rather than an error.

        Parameters:
            client_id: OIDC client identifier the key belongs to.
            key_id: OIDC client key identifier to revoke.
        """
        try:
            self._delete(f"/oidc/clients/{client_id}/keys/{key_id}")
        except NetActuateError as exc:
            if "the key is revoked" in exc.message.lower():
                return
            raise

    def add_oidc_client_vms(self, client_id: int, mbpkgids: Sequence[int]) -> None:
        """Allow VMs to access an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
            mbpkgids: VM package identifiers to allow.
        """
        body = {"vms": [{"mbpkgid": mbpkgid} for mbpkgid in mbpkgids]}
        self._post_json(f"/oidc/clients/{client_id}/allow-list/vms", body)

    def add_oidc_client_bare_metal_servers(self, client_id: int, mbpkgids: Sequence[int]) -> None:
        """Allow bare metal servers to access an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
            mbpkgids: Bare metal server package identifiers to allow.
        """
        body = {"servers": [{"mbpkgid": mbpkgid} for mbpkgid in mbpkgids]}
        self._post_json(f"/oidc/clients/{client_id}/allow-list/bare-metal", body)

    def remove_oidc_client_vm(self, client_id: int, mbpkgid: int) -> None:
        """Revoke a VM's access to an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
            mbpkgid: VM package identifier to revoke.
        """
        self._delete(f"/oidc/clients/{client_id}/allow-list/vms/{mbpkgid}")

    def remove_oidc_client_bare_metal_server(self, client_id: int, mbpkgid: int) -> None:
        """Revoke a bare metal server's access to an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
            mbpkgid: Bare metal server package identifier to revoke.
        """
        self._delete(f"/oidc/clients/{client_id}/allow-list/bare-metal/{mbpkgid}")

    def list_oidc_client_vms(self, client_id: int) -> List[OIDCClientVM]:
        """Return the VMs allowed to access an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
        """
        data = self._request("GET", f"/oidc/clients/{client_id}/allow-list/vms")
        if not isinstance(data, Mapping) or not isinstance(data.get("vms"), list):
            raise NetActuateError(f"OIDC client {client_id} VMs response is missing vms")
        return [OIDCClientVM.from_api(row) for row in data["vms"]]

    def list_oidc_client_bare_metal_servers(self, client_id: int) -> List[OIDCClientBareMetalServer]:
        """Return the bare metal servers allowed to access an OIDC client.

        Parameters:
            client_id: OIDC client identifier.
        """
        data = self._request("GET", f"/oidc/clients/{client_id}/allow-list/bare-metal")
        if not isinstance(data, Mapping) or not isinstance(data.get("servers"), list):
            raise NetActuateError(f"OIDC client {client_id} bare metal servers response is missing servers")
        return [OIDCClientBareMetalServer.from_api(row) for row in data["servers"]]

    def list_oidc_client_auth_logs(self, client_id: int) -> List[OIDCClientAuthLog]:
        """Return an OIDC client's authentication log entries.

        Parameters:
            client_id: OIDC client identifier.
        """
        return [
            OIDCClientAuthLog.from_api(row)
            for row in self._get_list(f"/oidc/clients/{client_id}/auth-logs?limit=1000")
        ]

    def list_oidc_client_change_logs(self, client_id: int) -> List[OIDCClientChangeLog]:
        """Return an OIDC client's change log entries.

        Parameters:
            client_id: OIDC client identifier.
        """
        return [
            OIDCClientChangeLog.from_api(row)
            for row in self._get_list(f"/oidc/clients/{client_id}/change-logs?limit=1000")
        ]

    def list_magic_meshes(self) -> List[MagicMesh]:
        """Return all magic meshes visible to the account."""
        return [MagicMesh.from_api(row) for row in self._get_list("/cloud-routing/meshes?limit=1000")]

    def create_magic_mesh(
        self, name: str, description: Optional[str] = None, router_ids: Optional[Sequence[int]] = None
    ) -> int:
        """Create a magic mesh and return its mesh id.

        Parameters:
            name: Mesh name.
            description: Optional mesh description.
            router_ids: Optional router identifiers to add to the mesh at creation time.
        """
        body: Dict[str, Any] = {"name": name}
        if description is not None:
            body["description"] = description
        if router_ids:
            body["routers"] = [{"routerId": router_id} for router_id in router_ids]
        data = self._post_json("/cloud-routing/meshes", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("magic mesh create response must be an object")
        return _response_int(data, "meshId")

    def get_magic_mesh(self, mesh_id: int) -> MagicMesh:
        """Return one magic mesh.

        Parameters:
            mesh_id: Magic mesh identifier.
        """
        return MagicMesh.from_api(self._request("GET", f"/cloud-routing/meshes/{mesh_id}"))

    def update_magic_mesh(
        self, mesh_id: int, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        """Update a magic mesh's name or description.

        Parameters:
            mesh_id: Magic mesh identifier.
            name: New mesh name, when changing it.
            description: New mesh description, when changing it.
        """
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        self._patch_json(f"/cloud-routing/meshes/{mesh_id}", body)

    def delete_magic_mesh(self, mesh_id: int) -> None:
        """Delete a magic mesh.

        Parameters:
            mesh_id: Magic mesh identifier.
        """
        self._delete(f"/cloud-routing/meshes/{mesh_id}")

    def list_mesh_routers(self, mesh_id: int) -> List[MeshRouter]:
        """Return the routers attached to a magic mesh.

        Parameters:
            mesh_id: Magic mesh identifier.
        """
        return [MeshRouter.from_api(row) for row in self._get_list(f"/cloud-routing/meshes/{mesh_id}/routers")]

    def add_router_to_mesh(self, mesh_id: int, router_id: int) -> None:
        """Add a router to a magic mesh.

        Parameters:
            mesh_id: Magic mesh identifier.
            router_id: Router identifier to add.
        """
        self._post_json(f"/cloud-routing/meshes/{mesh_id}/routers", {"routerId": router_id})

    def remove_router_from_mesh(self, mesh_id: int, router_id: int) -> None:
        """Remove a router from a magic mesh.

        Parameters:
            mesh_id: Magic mesh identifier.
            router_id: Router identifier to remove.
        """
        self._delete(f"/cloud-routing/meshes/{mesh_id}/routers/{router_id}")

    def list_routers(self) -> List[Router]:
        """Return all cloud routers visible to the account."""
        return [Router.from_api(row) for row in self._get_list("/cloud-routing/routers?limit=1000")]

    def get_router(self, router_id: int) -> Router:
        """Return one cloud router.

        Parameters:
            router_id: Router identifier.
        """
        return Router.from_api(self._request("GET", f"/cloud-routing/routers/{router_id}"))

    def get_router_config(self, router_id: int) -> RouterConfig:
        """Return the full configuration of a cloud router.

        Parameters:
            router_id: Router identifier.
        """
        return RouterConfig.from_api(self._request("GET", f"/cloud-routing/routers/{router_id}/config"))

    def list_router_config_interfaces(self, router_id: int) -> Any:
        """Return the router-wide interface configuration as raw JSON.

        Parameters:
            router_id: Router identifier.
        """
        return self._request("GET", f"/cloud-routing/routers/{router_id}/config/interfaces")

    def invalidate_router_config_cache(self, router_id: int) -> None:
        """Mark the API's cached router configuration stale.

        Parameters:
            router_id: Router identifier.
        """
        self._post_json(f"/cloud-routing/routers/{router_id}/config/invalidate-cache")

    def create_router(
        self, package_id: int, location_id: int, name: Optional[str] = None, description: Optional[str] = None
    ) -> int:
        """Create a cloud router and return its router id.

        Parameters:
            package_id: Package identifier for the server backing the router.
            location_id: Location identifier to create the router in.
            name: Optional router name.
            description: Optional router description.
        """
        if not package_id:
            raise ValueError("package_id is required")
        if not location_id:
            raise ValueError("location_id is required")
        body: Dict[str, Any] = {"packageId": package_id, "locationId": location_id}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        data = self._post_json("/cloud-routing/routers", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router response must be an object")
        return _response_int(data, "routerId")

    def update_router(self, router_id: int, name: Optional[str] = None, description: Optional[str] = None) -> Router:
        """Update a cloud router's name or description.

        Parameters:
            router_id: Router identifier to update.
            name: New router name, when changing it.
            description: New router description, when changing it.
        """
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        return Router.from_api(self._patch_json(f"/cloud-routing/routers/{router_id}", body))

    def delete_router(self, router_id: int) -> None:
        """Delete a cloud router.

        Parameters:
            router_id: Router identifier to delete.
        """
        self._delete(f"/cloud-routing/routers/{router_id}")

    def wait_for_router_ready(
        self,
        router_id: int,
        interval: float = 10.0,
        timeout: float = 600.0,
        stall_after: float = 300.0,
    ) -> Router:
        """Poll a cloud router until it reports ready or its build stalls.

        Folds gona's WaitForRouterReady and WaitForRouterReadyTimeout into one
        call with a timeout parameter. A healthy build finishes in about five
        minutes and reports timestamped steps as it completes them, so rather
        than only watching elapsed time this tracks how many steps have
        completed and raises once none complete for stall_after seconds,
        since a stalled build never sets readyOn and would otherwise run out
        the full timeout to fail.

        Parameters:
            router_id: Router identifier to poll.
            interval: Seconds to wait between polls.
            timeout: Maximum seconds to wait before raising.
            stall_after: Maximum seconds without build progress before raising.
        """
        deadline = time.monotonic() + timeout
        last_done = 0
        last_progress = time.monotonic()

        def _poll() -> Optional[Router]:
            nonlocal last_done, last_progress
            router = self.get_router(router_id)
            if router.ready_on is not None:
                return router
            done = sum(1 for step in router.build if step.date)
            if done > last_done:
                last_done = done
                last_progress = time.monotonic()
            stalled = time.monotonic() - last_progress
            if stalled > stall_after:
                pending = next((step.text for step in router.build if not step.date), "")
                raise NetActuateError(
                    f"router {router_id} build has made no progress for {stalled:.0f}s: "
                    f"{done} of {len(router.build)} steps complete, stuck on {pending!r}",
                    method="GET",
                    url=f"/cloud-routing/routers/{router_id}",
                )
            return None

        router = _poll()
        if router is not None:
            return router
        while time.monotonic() < deadline:
            time.sleep(max(min(interval, deadline - time.monotonic()), 0))
            router = _poll()
            if router is not None:
                return router
        raise NetActuateError(
            f"timeout waiting for router {router_id} to become ready after {timeout} seconds",
            method="GET",
            url=f"/cloud-routing/routers/{router_id}",
        )

    def list_router_vrfs(self, router_id: int) -> Dict[str, RouterVRFConfig]:
        """Return the VRF configuration for a cloud router, keyed by VRF name.

        Parameters:
            router_id: Router identifier.
        """
        data = self._request("GET", f"/cloud-routing/routers/{router_id}/config/vrfs")
        if not isinstance(data, Mapping):
            raise NetActuateError("router VRF list response must be an object")
        return {key: RouterVRFConfig.from_api(row) for key, row in data.items()}

    def create_router_vrf(
        self, router_id: int, name: Optional[str] = None, description: Optional[str] = None
    ) -> int:
        """Create a VRF on a cloud router and return its VRF id.

        Parameters:
            router_id: Router identifier to create the VRF on.
            name: Optional VRF name.
            description: Optional VRF description.
        """
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        data = self._post_json(f"/cloud-routing/routers/{router_id}/config/vrfs", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF response must be an object")
        return _response_int(data, "vrfId")

    def get_router_vrf(self, router_id: int, vrf_id: int) -> RouterVRFConfig:
        """Return one VRF on a cloud router.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        return RouterVRFConfig.from_api(
            self._request("GET", f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}")
        )

    def update_router_vrf(
        self, router_id: int, vrf_id: int, name: Optional[str] = None, description: Optional[str] = None
    ) -> int:
        """Update a VRF's name or description and return its VRF id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to update.
            name: New VRF name, when changing it.
            description: New VRF description, when changing it.
        """
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        data = self._put_json(f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF response must be an object")
        return _response_int(data, "vrfId")

    def delete_router_vrf(self, router_id: int, vrf_id: int) -> None:
        """Delete a VRF from a cloud router.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to delete.
        """
        self._delete(f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}")

    def get_router_vrf_bgp(self, router_id: int, vrf_id: int) -> RouterVRFBGPConfig:
        """Return the BGP configuration of a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        return RouterVRFBGPConfig.from_api(
            self._request("GET", f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp")
        )

    def update_router_vrf_bgp(
        self,
        router_id: int,
        vrf_id: int,
        networks: Optional[Sequence[str]] = None,
        local_asn: Optional[str] = None,
    ) -> RouterVRFBGPUpdateResult:
        """Update the BGP configuration of a router VRF.

        Mirrors gona's UpdateRouterVRFBGPRequest: networks and asn are both
        omitted unless given, matching their omitempty tags.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            networks: Optional complete set of subnets to advertise.
            local_asn: Optional new local ASN.
        """
        body: Dict[str, Any] = {}
        if networks:
            body["networks"] = [{"subnet": subnet} for subnet in networks]
        if local_asn is not None:
            asn_body: Dict[str, Any] = {}
            if local_asn:
                asn_body["local"] = local_asn
            body["asn"] = asn_body
        return RouterVRFBGPUpdateResult.from_api(
            self._put_json(f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp", body)
        )

    def list_router_vrf_bgp_neighbors(self, router_id: int, vrf_id: int) -> List[RouterVRFBGPNeighbor]:
        """Return the BGP neighbors configured for a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp/neighbors"
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise NetActuateError("router VRF BGP neighbor list response must be a list")
        return [RouterVRFBGPNeighbor.from_api(row) for row in data]

    def create_router_vrf_bgp_neighbor(
        self,
        router_id: int,
        vrf_id: int,
        address: str,
        remote_asn: int,
        is_shutdown: bool = False,
        do_as_override: bool = False,
        do_next_help_self: bool = False,
        enabled_ipv4: bool = False,
        enabled_ipv6: bool = False,
        source_address: Optional[str] = None,
        ebgp_multihop: Optional[int] = None,
        md5_secret: str = "",
        import_route_map: Optional[Mapping[str, Any]] = None,
        export_route_map: Optional[Mapping[str, Any]] = None,
        name: str = "",
        description: str = "",
    ) -> int:
        """Create a BGP neighbor on a router VRF and return its neighbor id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the neighbor on.
            address: Neighbor IP address.
            remote_asn: Neighbor's remote ASN.
            is_shutdown: Whether the neighbor is administratively shut down.
            do_as_override: Whether AS override is enabled.
            do_next_help_self: Whether next-hop-self is enabled.
            enabled_ipv4: Whether IPv4 is enabled for the neighbor.
            enabled_ipv6: Whether IPv6 is enabled for the neighbor.
            source_address: Optional source address override.
            ebgp_multihop: Optional eBGP multihop count.
            md5_secret: Optional MD5 authentication secret.
            import_route_map: Optional import route map in API shape
                (doDefaultDrop and rules).
            export_route_map: Optional export route map in API shape.
            name: Optional neighbor name.
            description: Optional neighbor description.
        """
        body = _router_vrf_bgp_neighbor_body(
            address,
            remote_asn,
            is_shutdown,
            do_as_override,
            do_next_help_self,
            enabled_ipv4,
            enabled_ipv6,
            source_address,
            ebgp_multihop,
            md5_secret,
            import_route_map,
            export_route_map,
            name,
            description,
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp/neighbors"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF BGP neighbor response must be an object")
        return _response_int(data, "neighborId")

    def get_router_vrf_bgp_neighbor(self, router_id: int, vrf_id: int, neighbor_id: int) -> RouterVRFBGPNeighbor:
        """Return one BGP neighbor on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            neighbor_id: BGP neighbor identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp/neighbors/{neighbor_id}"
        return RouterVRFBGPNeighbor.from_api(self._request("GET", path))

    def update_router_vrf_bgp_neighbor(
        self,
        router_id: int,
        vrf_id: int,
        neighbor_id: int,
        address: str,
        remote_asn: int,
        is_shutdown: bool = False,
        do_as_override: bool = False,
        do_next_help_self: bool = False,
        enabled_ipv4: bool = False,
        enabled_ipv6: bool = False,
        source_address: Optional[str] = None,
        ebgp_multihop: Optional[int] = None,
        md5_secret: str = "",
        import_route_map: Optional[Mapping[str, Any]] = None,
        export_route_map: Optional[Mapping[str, Any]] = None,
        name: str = "",
        description: str = "",
    ) -> int:
        """Update a BGP neighbor on a router VRF and return its neighbor id.

        Parameters mirror create_router_vrf_bgp_neighbor: gona's update
        request carries the same complete shape as create rather than a
        partial patch, so every field is resent in full.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            neighbor_id: BGP neighbor identifier to update.
            address: Neighbor IP address.
            remote_asn: Neighbor's remote ASN.
            is_shutdown: Whether the neighbor is administratively shut down.
            do_as_override: Whether AS override is enabled.
            do_next_help_self: Whether next-hop-self is enabled.
            enabled_ipv4: Whether IPv4 is enabled for the neighbor.
            enabled_ipv6: Whether IPv6 is enabled for the neighbor.
            source_address: Optional source address override.
            ebgp_multihop: Optional eBGP multihop count.
            md5_secret: Optional MD5 authentication secret.
            import_route_map: Optional import route map in API shape.
            export_route_map: Optional export route map in API shape.
            name: Optional neighbor name.
            description: Optional neighbor description.
        """
        body = _router_vrf_bgp_neighbor_body(
            address,
            remote_asn,
            is_shutdown,
            do_as_override,
            do_next_help_self,
            enabled_ipv4,
            enabled_ipv6,
            source_address,
            ebgp_multihop,
            md5_secret,
            import_route_map,
            export_route_map,
            name,
            description,
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp/neighbors/{neighbor_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF BGP neighbor response must be an object")
        return _response_int(data, "neighborId")

    def delete_router_vrf_bgp_neighbor(self, router_id: int, vrf_id: int, neighbor_id: int) -> None:
        """Delete a BGP neighbor from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            neighbor_id: BGP neighbor identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/bgp/neighbors/{neighbor_id}"
        self._delete(path)

    def list_router_static_routes(self, router_id: int, vrf_id: int) -> List[RouterStaticRoute]:
        """Return the static routes configured on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/static-routes"
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise NetActuateError("router static route list response must be a list")
        return [RouterStaticRoute.from_api(row) for row in data]

    def create_router_static_route(
        self,
        router_id: int,
        vrf_id: int,
        network: str,
        via_next_hop: str = "",
        via_interface_id: Optional[int] = None,
        via_tunnel_id: Optional[int] = None,
        via_ip_sec_peer_id: Optional[int] = None,
        description: str = "",
        distance: Optional[int] = None,
    ) -> int:
        """Create a static route on a router VRF and return its route id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the route on.
            network: Destination network in CIDR notation.
            via_next_hop: Optional next-hop IP address.
            via_interface_id: Optional next-hop interface identifier.
            via_tunnel_id: Optional next-hop tunnel identifier.
            via_ip_sec_peer_id: Optional next-hop IPsec peer identifier.
            description: Optional route description.
            distance: Optional administrative distance.
        """
        body = _router_static_route_body(
            network, via_next_hop, via_interface_id, via_tunnel_id, via_ip_sec_peer_id, description, distance
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/static-routes"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router static route response must be an object")
        return _response_int(data, "staticRouteId")

    def get_router_static_route(self, router_id: int, vrf_id: int, route_id: int) -> RouterStaticRoute:
        """Return one static route on a router VRF.

        Lists the VRF's static routes and filters by id, since there is no
        single-route get endpoint, and raises NotFoundError when no route
        matches so a caller can tell gone from failed.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            route_id: Static route identifier to look up.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/static-routes"
        for route in self.list_router_static_routes(router_id, vrf_id):
            if route.route_id == route_id:
                return route
        raise NotFoundError(
            f"static route {route_id} not found for VRF {vrf_id} on router {router_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_router_static_route(
        self,
        router_id: int,
        vrf_id: int,
        route_id: int,
        network: str,
        via_next_hop: str = "",
        via_interface_id: Optional[int] = None,
        via_tunnel_id: Optional[int] = None,
        via_ip_sec_peer_id: Optional[int] = None,
        description: str = "",
        distance: Optional[int] = None,
    ) -> int:
        """Update a static route on a router VRF and return its route id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            route_id: Static route identifier to update.
            network: Destination network in CIDR notation.
            via_next_hop: Optional next-hop IP address.
            via_interface_id: Optional next-hop interface identifier.
            via_tunnel_id: Optional next-hop tunnel identifier.
            via_ip_sec_peer_id: Optional next-hop IPsec peer identifier.
            description: Optional route description.
            distance: Optional administrative distance.
        """
        body = _router_static_route_body(
            network, via_next_hop, via_interface_id, via_tunnel_id, via_ip_sec_peer_id, description, distance
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/static-routes/{route_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router static route response must be an object")
        return _response_int(data, "staticRouteId")

    def delete_router_static_route(self, router_id: int, vrf_id: int, route_id: int) -> None:
        """Delete a static route from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            route_id: Static route identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/static-routes/{route_id}"
        self._delete(path)

    def create_router_prefix_list(
        self,
        router_id: int,
        name: str,
        ip_version: int,
        description: str = "",
        rules: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> int:
        """Create a prefix list on a cloud router and return its prefix list id.

        Parameters:
            router_id: Router identifier to create the prefix list on.
            name: Prefix list name.
            ip_version: IP version the prefix list matches.
            description: Optional prefix list description.
            rules: Rules to send, each a mapping with action and prefix keys.
        """
        body = _router_prefix_list_body(name, ip_version, description, rules)
        data = self._post_json(f"/cloud-routing/routers/{router_id}/config/prefix-lists", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router prefix list response must be an object")
        return _response_int(data, "prefixListId")

    def list_router_prefix_lists(self, router_id: int) -> List[RouterPrefixList]:
        """Return the prefix lists configured on a cloud router.

        Parameters:
            router_id: Router identifier.
        """
        data = self._request("GET", f"/cloud-routing/routers/{router_id}/config/prefix-lists")
        if not isinstance(data, list):
            raise NetActuateError("router prefix list list response must be a list")
        return [RouterPrefixList.from_api(row) for row in data]

    def get_router_prefix_list(self, router_id: int, prefix_list_id: int) -> RouterPrefixList:
        """Return one prefix list on a cloud router.

        Lists the router's prefix lists and filters by id, since there is no
        single-list get endpoint, and raises NotFoundError when no list
        matches so a caller can tell gone from failed.

        Parameters:
            router_id: Router identifier.
            prefix_list_id: Prefix list identifier to look up.
        """
        path = f"/cloud-routing/routers/{router_id}/config/prefix-lists"
        for prefix_list in self.list_router_prefix_lists(router_id):
            if prefix_list.prefix_list_id == prefix_list_id:
                return prefix_list
        raise NotFoundError(
            f"prefix list {prefix_list_id} not found on router {router_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_router_prefix_list(
        self,
        router_id: int,
        prefix_list_id: int,
        name: str,
        ip_version: int,
        description: str = "",
        rules: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> int:
        """Update a prefix list on a cloud router and return its prefix list id.

        Parameters:
            router_id: Router identifier.
            prefix_list_id: Prefix list identifier to update.
            name: Prefix list name.
            ip_version: IP version the prefix list matches.
            description: Optional prefix list description.
            rules: Rules to send, each a mapping with action and prefix keys.
        """
        body = _router_prefix_list_body(name, ip_version, description, rules)
        path = f"/cloud-routing/routers/{router_id}/config/prefix-lists/{prefix_list_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router prefix list response must be an object")
        return _response_int(data, "prefixListId")

    def delete_router_prefix_list(self, router_id: int, prefix_list_id: int) -> None:
        """Delete a prefix list from a cloud router.

        Parameters:
            router_id: Router identifier.
            prefix_list_id: Prefix list identifier to delete.
        """
        self._delete(f"/cloud-routing/routers/{router_id}/config/prefix-lists/{prefix_list_id}")

    def get_router_ntp_config(self, router_id: int) -> RouterNTPConfig:
        """Return the NTP service configuration of a cloud router.

        Parameters:
            router_id: Router identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/services/ntp"
        return RouterNTPConfig.from_api(self._request("GET", path))

    def update_router_ntp_config(
        self,
        router_id: int,
        enabled: Optional[bool] = None,
        interface_id: Optional[int] = None,
        upstreams: Optional[Sequence[str]] = None,
    ) -> int:
        """Update the NTP service configuration of a cloud router.

        Mirrors gona's UpdateRouterNTPConfigRequest, whose enabled,
        interfaceId and upstreams fields carry no omitempty tag and so are
        always sent, as null here when left unset.

        Parameters:
            router_id: Router identifier.
            enabled: Whether the NTP service is enabled, or None to send null.
            interface_id: Interface to bind the NTP service to, or None to
                send null.
            upstreams: Complete set of upstream NTP domains, or None to send
                null.
        """
        body: Dict[str, Any] = {
            "enabled": enabled,
            "interfaceId": interface_id,
            "upstreams": [{"domain": domain} for domain in upstreams] if upstreams is not None else None,
        }
        path = f"/cloud-routing/routers/{router_id}/config/services/ntp"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router NTP config response must be an object")
        return _response_int(data, "routerId")

    def get_router_routing_views(self, router_id: int, vrf_id: int, views: Sequence[Mapping[str, Any]]) -> Any:
        """Return requested live routing views for a router VRF, as raw JSON.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            views: Routing view selectors to request, each a mapping in API
                shape with ipVersion and name required, and id and filter
                optional.
        """
        body = {"views": [dict(view) for view in views]}
        path = f"/cloud-routing/routers/{router_id}/view/routing/{vrf_id}"
        return self._post_json(path, body)

    def get_router_routing_overview(self, router_id: int, vrf_id: int) -> Any:
        """Return the live routing overview for a router VRF, as raw JSON.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/view/routing/{vrf_id}/overview"
        return self._request("GET", path)

    def get_router_ipsec_config(self, router_id: int) -> RouterIPSecConfig:
        """Return the IPsec service configuration of a cloud router.

        Parameters:
            router_id: Router identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/ipSec"
        return RouterIPSecConfig.from_api(self._request("GET", path))

    def update_router_ipsec_config(
        self,
        router_id: int,
        ike_do_auto_renegotiation: bool,
        ike_key_exchange_version: int,
        ike_lifetime_seconds: int,
        ike_dh_group_number: int,
        ike_encryption: str,
        ike_hash: str,
        ike_prf: str,
        esp_lifetime_seconds: int,
        esp_encryption: str,
        esp_hash: str,
    ) -> None:
        """Replace the IPsec service configuration of a cloud router.

        Both the IKE and ESP negotiation groups are full replacements: every
        parameter is required and always sent, mirroring gona's
        RouterIPSecIKEGroup and RouterIPSecESPGroup, neither of which marks
        any field optional.

        Parameters:
            router_id: Router identifier.
            ike_do_auto_renegotiation: Whether IKE renegotiates automatically.
            ike_key_exchange_version: IKE key exchange version, 1 or 2.
            ike_lifetime_seconds: IKE security association lifetime.
            ike_dh_group_number: Diffie-Hellman group number for IKE.
            ike_encryption: IKE encryption algorithm.
            ike_hash: IKE hash algorithm.
            ike_prf: IKE pseudo-random function.
            esp_lifetime_seconds: ESP security association lifetime.
            esp_encryption: ESP encryption algorithm.
            esp_hash: ESP hash algorithm.
        """
        body = {
            "ikeGroup": {
                "doAutoRenegotiation": ike_do_auto_renegotiation,
                "keyExchangeVersion": ike_key_exchange_version,
                "lifetimeSeconds": ike_lifetime_seconds,
                "dhGroupNumber": ike_dh_group_number,
                "encryption": ike_encryption,
                "hash": ike_hash,
                "prf": ike_prf,
            },
            "espGroup": {
                "lifetimeSeconds": esp_lifetime_seconds,
                "encryption": esp_encryption,
                "hash": esp_hash,
            },
        }
        path = f"/cloud-routing/routers/{router_id}/config/ipSec"
        self._put_json(path, body)

    def list_router_vrf_ipsec_peers(self, router_id: int, vrf_id: int) -> List[RouterVRFIPSecPeer]:
        """Return the IPsec peers configured on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/ipSec/peers"
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise NetActuateError("router VRF IPsec peer list response must be a list")
        return [RouterVRFIPSecPeer.from_api(row) for row in data]

    def get_router_vrf_ipsec_peer(self, router_id: int, vrf_id: int, peer_id: int) -> RouterVRFIPSecPeer:
        """Return one IPsec peer on a router VRF.

        Lists the VRF's IPsec peers and filters by id, since there is no
        single-peer get endpoint, and raises NotFoundError when no peer
        matches so a caller can tell gone from failed.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            peer_id: IPsec peer identifier to look up.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/ipSec/peers"
        for peer in self.list_router_vrf_ipsec_peers(router_id, vrf_id):
            if peer.ip_sec_peer_id == peer_id:
                return peer
        raise NotFoundError(
            f"IPsec peer {peer_id} not found for VRF {vrf_id} on router {router_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def create_router_vrf_ipsec_peer(
        self,
        router_id: int,
        vrf_id: int,
        name: str,
        remote_id: str,
        psk_secret: str,
        do_initiate_connection: bool,
        description: Optional[str] = None,
        peer_address: str = "",
        overlay_ipv4: Optional[str] = None,
        overlay_ipv6: Optional[str] = None,
    ) -> int:
        """Create an IPsec peer on a router VRF and return its peer id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the peer on.
            name: Peer name.
            remote_id: Remote IKE identity.
            psk_secret: Pre-shared key secret.
            do_initiate_connection: Whether this side initiates the connection.
            description: Optional peer description.
            peer_address: Optional remote peer address.
            overlay_ipv4: Optional IPv4 overlay network for the peer.
            overlay_ipv6: Optional IPv6 overlay network for the peer.
        """
        body = _router_vrf_ipsec_peer_body(
            name, remote_id, psk_secret, do_initiate_connection, description, peer_address, overlay_ipv4, overlay_ipv6
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/ipSec/peers"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF IPsec peer response must be an object")
        return _response_int(data, "ipSecPeerId")

    def update_router_vrf_ipsec_peer(
        self,
        router_id: int,
        vrf_id: int,
        peer_id: int,
        name: str,
        remote_id: str,
        psk_secret: str,
        do_initiate_connection: bool,
        description: Optional[str] = None,
        peer_address: str = "",
        overlay_ipv4: Optional[str] = None,
        overlay_ipv6: Optional[str] = None,
    ) -> int:
        """Update an IPsec peer on a router VRF and return its peer id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            peer_id: IPsec peer identifier to update.
            name: Peer name.
            remote_id: Remote IKE identity.
            psk_secret: Pre-shared key secret.
            do_initiate_connection: Whether this side initiates the connection.
            description: Optional peer description.
            peer_address: Optional remote peer address.
            overlay_ipv4: Optional IPv4 overlay network for the peer.
            overlay_ipv6: Optional IPv6 overlay network for the peer.
        """
        body = _router_vrf_ipsec_peer_body(
            name, remote_id, psk_secret, do_initiate_connection, description, peer_address, overlay_ipv4, overlay_ipv6
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/ipSec/peers/{peer_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF IPsec peer response must be an object")
        return _response_int(data, "ipSecPeerId")

    def delete_router_vrf_ipsec_peer(self, router_id: int, vrf_id: int, peer_id: int) -> None:
        """Delete an IPsec peer from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            peer_id: IPsec peer identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/ipSec/peers/{peer_id}"
        self._delete(path)

    def list_router_vrf_interfaces(self, router_id: int, vrf_id: int) -> Dict[str, RouterVRFInterface]:
        """Return the interfaces configured on a router VRF, keyed by interface id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces"
        data = self._request("GET", path)
        if not isinstance(data, Mapping):
            raise NetActuateError("router VRF interface list response must be an object")
        return {key: RouterVRFInterface.from_api(row) for key, row in data.items()}

    def create_router_vrf_interface(
        self,
        router_id: int,
        vrf_id: int,
        interface_type: str,
        name: str,
        description: Optional[str] = None,
        ipv4_cidr: Optional[str] = None,
        ipv6_cidr: Optional[str] = None,
        ethernet_hardware_id: Optional[str] = None,
        wireguard_port: Optional[int] = None,
    ) -> int:
        """Create an interface on a router VRF and return its interface id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the interface on.
            interface_type: Interface type, such as ethernet or wireguard.
            name: Interface name.
            description: Optional interface description.
            ipv4_cidr: Optional IPv4 address in CIDR notation.
            ipv6_cidr: Optional IPv6 address in CIDR notation.
            ethernet_hardware_id: Optional backing ethernet hardware identifier.
            wireguard_port: Optional wireguard listen port.
        """
        body = _router_vrf_interface_body(
            interface_type, name, description, ipv4_cidr, ipv6_cidr, ethernet_hardware_id, wireguard_port
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF interface response must be an object")
        return _response_int(data, "interfaceId")

    def get_router_vrf_interface(self, router_id: int, vrf_id: int, interface_id: int) -> RouterVRFInterface:
        """Return one interface on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            interface_id: Interface identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces/{interface_id}"
        return RouterVRFInterface.from_api(self._request("GET", path))

    def update_router_vrf_interface(
        self,
        router_id: int,
        vrf_id: int,
        interface_id: int,
        interface_type: str,
        name: str,
        description: Optional[str] = None,
        ipv4_cidr: Optional[str] = None,
        ipv6_cidr: Optional[str] = None,
        ethernet_hardware_id: Optional[str] = None,
        wireguard_port: Optional[int] = None,
    ) -> int:
        """Update an interface on a router VRF and return its interface id.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            interface_id: Interface identifier to update.
            interface_type: Interface type, such as ethernet or wireguard.
            name: Interface name.
            description: Optional interface description.
            ipv4_cidr: Optional IPv4 address in CIDR notation.
            ipv6_cidr: Optional IPv6 address in CIDR notation.
            ethernet_hardware_id: Optional backing ethernet hardware identifier.
            wireguard_port: Optional wireguard listen port.
        """
        body = _router_vrf_interface_body(
            interface_type, name, description, ipv4_cidr, ipv6_cidr, ethernet_hardware_id, wireguard_port
        )
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces/{interface_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF interface response must be an object")
        return _response_int(data, "interfaceId")

    def delete_router_vrf_interface(self, router_id: int, vrf_id: int, interface_id: int) -> None:
        """Delete an interface from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            interface_id: Interface identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces/{interface_id}"
        self._delete(path)

    def create_router_vrf_interface_wireguard_peer(
        self,
        router_id: int,
        vrf_id: int,
        interface_id: int,
        allowed_ips: Optional[Sequence[str]] = None,
        public_key: Optional[str] = None,
        pre_shared_key: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        remote: Optional[str] = None,
    ) -> int:
        """Create a wireguard peer on a router VRF interface and return its peer id.

        Mirrors gona's CreateRouterVRFInterfaceWireguardPeerRequest, whose
        fields carry no omitempty tag and so are always sent, as null here
        when left unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            interface_id: Wireguard interface identifier to add the peer to.
            allowed_ips: Networks allowed through the peer, in CIDR notation,
                or None to send null.
            public_key: Optional peer public key, or None to send null.
            pre_shared_key: Optional pre-shared key, or None to send null.
            name: Optional peer name, or None to send null.
            description: Optional peer description, or None to send null.
            remote: Optional remote endpoint address, or None to send null.
        """
        body: Dict[str, Any] = {
            "allowedIps": [{"network": network} for network in allowed_ips] if allowed_ips is not None else None,
            "publicKey": public_key,
            "preSharedKey": pre_shared_key,
            "name": name,
            "description": description,
            "remote": remote,
        }
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces/{interface_id}/wireguard-peers"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF interface wireguard peer response must be an object")
        return _response_int(data, "wireguardPeerId")

    def get_router_vrf_interface_wireguard_peer(
        self, router_id: int, vrf_id: int, interface_id: int, wireguard_peer_id: int
    ) -> RouterVRFInterfaceWireguardPeer:
        """Return one wireguard peer on a router VRF interface.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            interface_id: Wireguard interface identifier.
            wireguard_peer_id: Wireguard peer identifier.
        """
        path = (
            f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces/"
            f"{interface_id}/wireguard-peers/{wireguard_peer_id}"
        )
        return RouterVRFInterfaceWireguardPeer.from_api(self._request("GET", path))

    def delete_router_vrf_interface_wireguard_peer(
        self, router_id: int, vrf_id: int, interface_id: int, wireguard_peer_id: int
    ) -> None:
        """Delete a wireguard peer from a router VRF interface.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            interface_id: Wireguard interface identifier.
            wireguard_peer_id: Wireguard peer identifier to delete.
        """
        path = (
            f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/interfaces/"
            f"{interface_id}/wireguard-peers/{wireguard_peer_id}"
        )
        self._delete(path)

    def create_router_vrf_snat_rule(
        self,
        router_id: int,
        vrf_id: int,
        ip_version: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Create a SNAT rule on a router VRF and return its rule id.

        Mirrors gona's CreateRouterVRFSNATRuleRequest: ipVersion, protocol,
        match and translation are always sent, the last two as null when not
        given, while description and priority are omitted when left unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the rule on.
            ip_version: IP version the rule applies to, 4 or 6.
            protocol: Protocol the rule matches.
            description: Optional rule description.
            match: Match block, passed through as the API expects it.
            translation: Translation block, passed through as the API expects it.
            priority: Optional priority block, passed through as the API expects it.
        """
        body = _router_vrf_nat_rule_create_body(ip_version, protocol, description, match, translation, priority)
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/snat-rules"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF SNAT rule response must be an object")
        return _response_int(data, "snatRuleId")

    def list_router_vrf_snat_rules(self, router_id: int, vrf_id: int) -> List[RouterVRFSNATRule]:
        """Return the SNAT rules configured on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/snat-rules"
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise NetActuateError("router VRF SNAT rule list response must be a list")
        return [RouterVRFSNATRule.from_api(row) for row in data]

    def get_router_vrf_snat_rule(self, router_id: int, vrf_id: int, snat_rule_id: int) -> RouterVRFSNATRule:
        """Return one SNAT rule on a router VRF.

        Lists the VRF's SNAT rules and filters by id, since there is no
        single-rule get endpoint, and raises NotFoundError when no rule
        matches so a caller can tell gone from failed.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            snat_rule_id: SNAT rule identifier to look up.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/snat-rules"
        for rule in self.list_router_vrf_snat_rules(router_id, vrf_id):
            if rule.snat_rule_id == snat_rule_id:
                return rule
        raise NotFoundError(
            f"SNAT rule {snat_rule_id} not found for VRF {vrf_id} on router {router_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_router_vrf_snat_rule(
        self,
        router_id: int,
        vrf_id: int,
        snat_rule_id: int,
        ip_version: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Update a SNAT rule on a router VRF and return its rule id.

        Mirrors gona's UpdateRouterVRFSNATRuleRequest: ipVersion, protocol
        and description are always sent, description included even when
        empty, while match, translation and priority are omitted when left
        unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            snat_rule_id: SNAT rule identifier to update.
            ip_version: IP version the rule applies to, 4 or 6.
            protocol: Protocol the rule matches.
            description: Rule description.
            match: Optional new match block, passed through as the API expects it.
            translation: Optional new translation block, passed through as the API expects it.
            priority: Optional new priority block, passed through as the API expects it.
        """
        body = _router_vrf_nat_rule_update_body(ip_version, protocol, description, match, translation, priority)
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/snat-rules/{snat_rule_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF SNAT rule response must be an object")
        return _response_int(data, "snatRuleId")

    def delete_router_vrf_snat_rule(self, router_id: int, vrf_id: int, snat_rule_id: int) -> None:
        """Delete a SNAT rule from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            snat_rule_id: SNAT rule identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/snat-rules/{snat_rule_id}"
        self._delete(path)

    def create_router_vrf_dnat_rule(
        self,
        router_id: int,
        vrf_id: int,
        ip_version: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Create a DNAT rule on a router VRF and return its rule id.

        Mirrors gona's CreateRouterVRFDNATRuleRequest: ipVersion, protocol,
        match and translation are always sent, the last two as null when not
        given, while description and priority are omitted when left unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the rule on.
            ip_version: IP version the rule applies to, 4 or 6.
            protocol: Protocol the rule matches.
            description: Optional rule description.
            match: Match block, passed through as the API expects it.
            translation: Translation block, passed through as the API expects it.
            priority: Optional priority block, passed through as the API expects it.
        """
        body = _router_vrf_nat_rule_create_body(ip_version, protocol, description, match, translation, priority)
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/dnat-rules"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF DNAT rule response must be an object")
        return _response_int(data, "dnatRuleId")

    def list_router_vrf_dnat_rules(self, router_id: int, vrf_id: int) -> List[RouterVRFDNATRule]:
        """Return the DNAT rules configured on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/dnat-rules"
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise NetActuateError("router VRF DNAT rule list response must be a list")
        return [RouterVRFDNATRule.from_api(row) for row in data]

    def get_router_vrf_dnat_rule(self, router_id: int, vrf_id: int, dnat_rule_id: int) -> RouterVRFDNATRule:
        """Return one DNAT rule on a router VRF.

        Lists the VRF's DNAT rules and filters by id, since there is no
        single-rule get endpoint, and raises NotFoundError when no rule
        matches so a caller can tell gone from failed.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            dnat_rule_id: DNAT rule identifier to look up.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/dnat-rules"
        for rule in self.list_router_vrf_dnat_rules(router_id, vrf_id):
            if rule.dnat_rule_id == dnat_rule_id:
                return rule
        raise NotFoundError(
            f"DNAT rule {dnat_rule_id} not found for VRF {vrf_id} on router {router_id}",
            method="GET",
            url=path,
            status_code=404,
            code=404,
        )

    def update_router_vrf_dnat_rule(
        self,
        router_id: int,
        vrf_id: int,
        dnat_rule_id: int,
        ip_version: int,
        protocol: str = "",
        description: str = "",
        match: Optional[Mapping[str, Any]] = None,
        translation: Optional[Mapping[str, Any]] = None,
        priority: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Update a DNAT rule on a router VRF and return its rule id.

        Mirrors gona's UpdateRouterVRFDNATRuleRequest: ipVersion, protocol
        and description are always sent, description included even when
        empty, while match, translation and priority are omitted when left
        unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            dnat_rule_id: DNAT rule identifier to update.
            ip_version: IP version the rule applies to, 4 or 6.
            protocol: Protocol the rule matches.
            description: Rule description.
            match: Optional new match block, passed through as the API expects it.
            translation: Optional new translation block, passed through as the API expects it.
            priority: Optional new priority block, passed through as the API expects it.
        """
        body = _router_vrf_nat_rule_update_body(ip_version, protocol, description, match, translation, priority)
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/dnat-rules/{dnat_rule_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF DNAT rule response must be an object")
        return _response_int(data, "dnatRuleId")

    def delete_router_vrf_dnat_rule(self, router_id: int, vrf_id: int, dnat_rule_id: int) -> None:
        """Delete a DNAT rule from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            dnat_rule_id: DNAT rule identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/dnat-rules/{dnat_rule_id}"
        self._delete(path)

    def list_router_vrf_tunnels(self, router_id: int, vrf_id: int) -> List[RouterVRFTunnel]:
        """Return the tunnels configured on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/tunnels"
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise NetActuateError("router VRF tunnel list response must be a list")
        return [RouterVRFTunnel.from_api(row) for row in data]

    def get_router_vrf_tunnel(self, router_id: int, vrf_id: int, tunnel_id: int) -> RouterVRFTunnel:
        """Return one tunnel on a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            tunnel_id: Tunnel identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/tunnels/{tunnel_id}"
        return RouterVRFTunnel.from_api(self._request("GET", path))

    def create_router_vrf_tunnel(
        self,
        router_id: int,
        vrf_id: int,
        ip_key: int,
        name: str,
        mtu: int,
        remote: str,
        description: Optional[str] = None,
        ipv4_cidr: Optional[str] = None,
        ipv6_cidr: Optional[str] = None,
    ) -> int:
        """Create a tunnel on a router VRF and return its tunnel id.

        Mirrors gona's CreateRouterVRFTunnelRequest, whose fields carry no
        omitempty tag and so are always sent, as null here when left unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier to create the tunnel on.
            ip_key: Tunnel IP key.
            name: Tunnel name.
            mtu: Tunnel MTU.
            remote: Remote endpoint address.
            description: Optional tunnel description, or None to send null.
            ipv4_cidr: Optional IPv4 address in CIDR notation, or None to send null.
            ipv6_cidr: Optional IPv6 address in CIDR notation, or None to send null.
        """
        body = {
            "ipKey": ip_key,
            "name": name,
            "description": description,
            "mtu": mtu,
            "ipv4Cidr": ipv4_cidr,
            "ipv6Cidr": ipv6_cidr,
            "endpointAddress": {"remote": remote},
        }
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/tunnels"
        data = self._post_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create router VRF tunnel response must be an object")
        return _response_int(data, "tunnelId")

    def update_router_vrf_tunnel(
        self,
        router_id: int,
        vrf_id: int,
        tunnel_id: int,
        ip_key: int,
        name: str,
        mtu: int,
        remote: str,
        description: Optional[str] = None,
        ipv4_cidr: Optional[str] = None,
        ipv6_cidr: Optional[str] = None,
    ) -> int:
        """Update a tunnel on a router VRF and return its tunnel id.

        Mirrors gona's UpdateRouterVRFTunnelRequest, whose fields carry no
        omitempty tag and so are always sent, as null here when left unset.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            tunnel_id: Tunnel identifier to update.
            ip_key: Tunnel IP key.
            name: Tunnel name.
            mtu: Tunnel MTU.
            remote: Remote endpoint address.
            description: Optional tunnel description, or None to send null.
            ipv4_cidr: Optional IPv4 address in CIDR notation, or None to send null.
            ipv6_cidr: Optional IPv6 address in CIDR notation, or None to send null.
        """
        body = {
            "ipKey": ip_key,
            "name": name,
            "description": description,
            "mtu": mtu,
            "ipv4Cidr": ipv4_cidr,
            "ipv6Cidr": ipv6_cidr,
            "endpointAddress": {"remote": remote},
        }
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/tunnels/{tunnel_id}"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF tunnel response must be an object")
        return _response_int(data, "tunnelId")

    def delete_router_vrf_tunnel(self, router_id: int, vrf_id: int, tunnel_id: int) -> None:
        """Delete a tunnel from a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            tunnel_id: Tunnel identifier to delete.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/tunnels/{tunnel_id}"
        self._delete(path)

    def get_router_vrf_dhcp(self, router_id: int, vrf_id: int) -> RouterVRFDHCPConfig:
        """Return the DHCP service configuration of a router VRF.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
        """
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/services/dhcp"
        return RouterVRFDHCPConfig.from_api(self._request("GET", path))

    def update_router_vrf_dhcp(
        self,
        router_id: int,
        vrf_id: int,
        enabled: bool,
        interface_id: int,
        subnet: str,
        lease_timeout: int,
        do_ping_check: bool,
        default_router_address: str = "",
        client_domain_name: str = "",
        dhcp_range: Optional[Mapping[str, str]] = None,
        domain_name_servers: Optional[Sequence[str]] = None,
        ntp_servers: Optional[Sequence[str]] = None,
        static_routes: Optional[Sequence[Mapping[str, str]]] = None,
    ) -> int:
        """Update the DHCP service configuration of a router VRF and return the router id.

        Mirrors gona's UpdateRouterVRFDHCPRequest: enabled, interfaceId,
        subnet, leaseTimeout and doPingCheck are always sent, along with
        range, domainNameServers, ntpServers and staticRoutes, sent as null
        or an empty list when left unset, while defaultRouterAddress and
        clientDomainName are omitted when left empty.

        Parameters:
            router_id: Router identifier.
            vrf_id: VRF identifier.
            enabled: Whether the DHCP service is enabled.
            interface_id: Interface to bind the DHCP service to.
            subnet: Subnet the DHCP service serves, in CIDR notation.
            lease_timeout: Lease timeout in seconds.
            do_ping_check: Whether to ping an address before leasing it.
            default_router_address: Optional default router address to hand out.
            client_domain_name: Optional client domain name to hand out.
            dhcp_range: Optional address range, a mapping with first_address
                and last_address keys, or None to send null.
            domain_name_servers: Optional DNS server addresses to hand out.
            ntp_servers: Optional NTP server addresses to hand out.
            static_routes: Optional static routes to hand out, each a mapping
                with network and next_hop keys.
        """
        body: Dict[str, Any] = {
            "enabled": enabled,
            "interfaceId": interface_id,
            "subnet": subnet,
            "leaseTimeout": lease_timeout,
            "doPingCheck": do_ping_check,
            "range": (
                {"firstAddress": dhcp_range["first_address"], "lastAddress": dhcp_range["last_address"]}
                if dhcp_range is not None
                else None
            ),
            "domainNameServers": (
                [{"address": address} for address in domain_name_servers]
                if domain_name_servers is not None
                else None
            ),
            "ntpServers": (
                [{"address": address} for address in ntp_servers] if ntp_servers is not None else None
            ),
            "staticRoutes": (
                [{"network": route["network"], "nextHop": route["next_hop"]} for route in static_routes]
                if static_routes is not None
                else None
            ),
        }
        if default_router_address:
            body["defaultRouterAddress"] = default_router_address
        if client_domain_name:
            body["clientDomainName"] = client_domain_name
        path = f"/cloud-routing/routers/{router_id}/config/vrfs/{vrf_id}/services/dhcp"
        data = self._put_json(path, body)
        if not isinstance(data, Mapping):
            raise NetActuateError("update router VRF DHCP response must be an object")
        return _response_int(data, "routerId")

    def create_ssl_certificate(
        self, name: str, certificate: str, private_key: str, description: str = ""
    ) -> int:
        """Create an SSL certificate and return its id.

        Parameters:
            name: Certificate name.
            certificate: PEM encoded certificate content.
            private_key: PEM encoded private key content.
            description: Optional certificate description.
        """
        body: Dict[str, Any] = {"name": name, "certificate": certificate, "privateKey": private_key}
        if description:
            body["description"] = description
        data = self._post_json("/ssl-certificates", body)
        if not isinstance(data, Mapping):
            raise NetActuateError("create SSL certificate response must be an object")
        return _response_int(data, "sslCertificateId")

    def list_ssl_certificates(self) -> List[SSLCertificate]:
        """Return the SSL certificates for the account."""
        return [SSLCertificate.from_api(row) for row in self._get_list("/ssl-certificates")]

    def get_ssl_certificate(self, ssl_certificate_id: int) -> SSLCertificate:
        """Return one SSL certificate.

        Parameters:
            ssl_certificate_id: SSL certificate identifier.
        """
        return SSLCertificate.from_api(self._request("GET", f"/ssl-certificates/{ssl_certificate_id}"))

    def update_ssl_certificate(
        self,
        ssl_certificate_id: int,
        name: str = "",
        description: str = "",
        certificate: str = "",
        private_key: str = "",
    ) -> None:
        """Update an SSL certificate.

        Parameters:
            ssl_certificate_id: SSL certificate identifier to update.
            name: Optional new certificate name.
            description: Optional new certificate description.
            certificate: Optional new PEM encoded certificate content.
            private_key: Optional new PEM encoded private key content.
        """
        body: Dict[str, Any] = {}
        if name:
            body["name"] = name
        if description:
            body["description"] = description
        if certificate:
            body["certificate"] = certificate
        if private_key:
            body["privateKey"] = private_key
        self._patch_json(f"/ssl-certificates/{ssl_certificate_id}", body)

    def delete_ssl_certificate(self, ssl_certificate_id: int) -> None:
        """Delete an SSL certificate.

        Parameters:
            ssl_certificate_id: SSL certificate identifier to delete.
        """
        self._delete(f"/ssl-certificates/{ssl_certificate_id}")

    def create_nlb_group(
        self,
        nlb_id: int,
        name: str,
        ip_version: int,
        algorithm: str,
        match: Mapping[str, Any],
        health_check: Mapping[str, Any],
        rules: Sequence[Mapping[str, Any]],
        backends: Sequence[Mapping[str, Any]],
        description: str = "",
    ) -> NLBGroup:
        """Create a group on a network load balancer.

        Parameters:
            nlb_id: Network load balancer identifier to create the group on.
            name: Group name.
            ip_version: IP version the group matches, 4 or 6.
            algorithm: Load balancing algorithm to use.
            match: Match criteria, passed through as the API expects it.
            health_check: Health check settings, passed through as the API expects it.
            rules: Protocol and port mapping rules, each passed through as the API expects it.
            backends: Backend hosts to bind, each passed through as the API expects it.
            description: Optional group description.
        """
        body = _nlb_group_body(name, ip_version, algorithm, match, health_check, rules, backends, description)
        return NLBGroup.from_api(self._post_json(f"/network-loadbalancers/{nlb_id}/groups", body))

    def get_nlb_group(self, nlb_id: int, group_id: int) -> NLBGroup:
        """Return one network load balancer group.

        Parameters:
            nlb_id: Network load balancer identifier.
            group_id: Group identifier.
        """
        return NLBGroup.from_api(self._request("GET", f"/network-loadbalancers/{nlb_id}/groups/{group_id}"))

    def list_nlb_groups(self, nlb_id: int) -> List[NLBGroup]:
        """Return the groups on a network load balancer.

        Parameters:
            nlb_id: Network load balancer identifier.
        """
        return [NLBGroup.from_api(row) for row in self._get_list(f"/network-loadbalancers/{nlb_id}/groups")]

    def replace_nlb_group(
        self,
        nlb_id: int,
        group_id: int,
        name: str,
        ip_version: int,
        algorithm: str,
        match: Mapping[str, Any],
        health_check: Mapping[str, Any],
        rules: Sequence[Mapping[str, Any]],
        backends: Sequence[Mapping[str, Any]],
        description: str = "",
    ) -> NLBGroup:
        """Replace a network load balancer group's full configuration.

        Parameters:
            nlb_id: Network load balancer identifier the group belongs to.
            group_id: Group identifier to replace.
            name: Group name.
            ip_version: IP version the group matches, 4 or 6.
            algorithm: Load balancing algorithm to use.
            match: Match criteria, passed through as the API expects it.
            health_check: Health check settings, passed through as the API expects it.
            rules: Protocol and port mapping rules, each passed through as the API expects it.
            backends: Backend hosts to bind, each passed through as the API expects it.
            description: Optional group description.
        """
        body = _nlb_group_body(name, ip_version, algorithm, match, health_check, rules, backends, description)
        path = f"/network-loadbalancers/{nlb_id}/groups/{group_id}"
        return NLBGroup.from_api(self._put_json(path, body))

    def delete_nlb_group(self, nlb_id: int, group_id: int) -> None:
        """Delete a network load balancer group.

        Parameters:
            nlb_id: Network load balancer identifier the group belongs to.
            group_id: Group identifier to delete.
        """
        self._delete(f"/network-loadbalancers/{nlb_id}/groups/{group_id}")

    def query_statistics(self, metrics: Sequence[str]) -> List[StatisticResult]:
        """Query cloud usage statistics for one or more metrics.

        Parameters:
            metrics: Metric names to query.
        """
        return self._query_statistics("/cloud/statistics", metrics)

    def query_networking_statistics(self, metrics: Sequence[str]) -> List[StatisticResult]:
        """Query cloud networking statistics for one or more metrics.

        Parameters:
            metrics: Metric names to query.
        """
        return self._query_statistics("/cloud/networking/statistics", metrics)

    def query_anycast_statistics(self, metrics: Sequence[str]) -> List[StatisticResult]:
        """Query anycast networking statistics for one or more metrics.

        Parameters:
            metrics: Metric names to query.
        """
        return self._query_statistics("/cloud/networking/anycast/statistics", metrics)

    def _query_statistics(self, path: str, metrics: Sequence[str]) -> List[StatisticResult]:
        body = {"metrics": [{"metric": {metric: {}}} for metric in metrics]}
        data = self._post_json(path, body)
        if not isinstance(data, list):
            raise NetActuateError(f"query statistics {path} response must be a list")
        return [StatisticResult.from_api(row) for row in data]

    def get_metric_names(self) -> MetricNames:
        """Return every metric name known to the statistics views, with its time window."""
        data = self._post_json("/cloud/statistics/views/all-metrics", {})
        if not isinstance(data, Mapping):
            raise NetActuateError("get metric names response must be an object")
        return MetricNames.from_api(data)

    def create_http_lb_group(
        self,
        http_lb_id: int,
        name: str,
        algorithm: str,
        internal_port: int,
        match: Mapping[str, Any],
        health_check: Mapping[str, Any],
        rules: Sequence[Mapping[str, Any]],
        backends: Sequence[Mapping[str, Any]],
        description: str = "",
        sticky_sessions_enabled: bool = False,
        ssl_to_backend_enabled: bool = False,
    ) -> HTTPLBGroup:
        """Create a group on an HTTP load balancer.

        Parameters:
            http_lb_id: HTTP load balancer identifier to create the group on.
            name: Group name.
            algorithm: Load balancing algorithm to use.
            internal_port: Backend port the group forwards traffic to.
            match: Match criteria, passed through as the API expects it.
            health_check: Health check settings, passed through as the API expects it.
            rules: Domain and path routing rules, each passed through as the API expects it.
            backends: Backend hosts to bind, each passed through as the API expects it.
            description: Optional group description.
            sticky_sessions_enabled: Whether to enable sticky sessions.
            ssl_to_backend_enabled: Whether to use SSL when forwarding to backends.
        """
        body = _http_lb_group_body(
            name,
            algorithm,
            internal_port,
            match,
            health_check,
            rules,
            backends,
            description,
            sticky_sessions_enabled,
            ssl_to_backend_enabled,
        )
        return HTTPLBGroup.from_api(self._post_json(f"/http-loadbalancers/{http_lb_id}/groups", body))

    def list_http_lb_groups(self, http_lb_id: int) -> List[HTTPLBGroup]:
        """Return the groups on an HTTP load balancer.

        Parameters:
            http_lb_id: HTTP load balancer identifier.
        """
        return [HTTPLBGroup.from_api(row) for row in self._get_list(f"/http-loadbalancers/{http_lb_id}/groups")]

    def get_http_lb_group(self, http_lb_id: int, group_id: int) -> HTTPLBGroup:
        """Return one HTTP load balancer group.

        Parameters:
            http_lb_id: HTTP load balancer identifier.
            group_id: Group identifier.
        """
        return HTTPLBGroup.from_api(self._request("GET", f"/http-loadbalancers/{http_lb_id}/groups/{group_id}"))

    def replace_http_lb_group(
        self,
        http_lb_id: int,
        group_id: int,
        name: str,
        algorithm: str,
        internal_port: int,
        match: Mapping[str, Any],
        health_check: Mapping[str, Any],
        rules: Sequence[Mapping[str, Any]],
        backends: Sequence[Mapping[str, Any]],
        description: str = "",
        sticky_sessions_enabled: bool = False,
        ssl_to_backend_enabled: bool = False,
    ) -> HTTPLBGroup:
        """Replace an HTTP load balancer group's full configuration.

        Parameters:
            http_lb_id: HTTP load balancer identifier the group belongs to.
            group_id: Group identifier to replace.
            name: Group name.
            algorithm: Load balancing algorithm to use.
            internal_port: Backend port the group forwards traffic to.
            match: Match criteria, passed through as the API expects it.
            health_check: Health check settings, passed through as the API expects it.
            rules: Domain and path routing rules, each passed through as the API expects it.
            backends: Backend hosts to bind, each passed through as the API expects it.
            description: Optional group description.
            sticky_sessions_enabled: Whether to enable sticky sessions.
            ssl_to_backend_enabled: Whether to use SSL when forwarding to backends.
        """
        body = _http_lb_group_body(
            name,
            algorithm,
            internal_port,
            match,
            health_check,
            rules,
            backends,
            description,
            sticky_sessions_enabled,
            ssl_to_backend_enabled,
        )
        path = f"/http-loadbalancers/{http_lb_id}/groups/{group_id}"
        return HTTPLBGroup.from_api(self._put_json(path, body))

    def delete_http_lb_group(self, http_lb_id: int, group_id: int) -> None:
        """Delete an HTTP load balancer group.

        Parameters:
            http_lb_id: HTTP load balancer identifier the group belongs to.
            group_id: Group identifier to delete.
        """
        self._delete(f"/http-loadbalancers/{http_lb_id}/groups/{group_id}")

    def get_vpc_nameservers(self, vpc_id: int) -> VPCNameservers:
        """Return the DHCP nameservers currently announced by a VPC.

        The `/vpcs/{id}/dhcp/nameservers` path only accepts PUT, so the
        current nameservers are read from the VPC object instead, mirroring
        gona's GetVPCNameservers.

        Parameters:
            vpc_id: VPC identifier.
        """
        vpc = self.get_vpc(vpc_id)
        dhcp = vpc.raw.get("dhcp")
        nameservers = dhcp.get("nameservers") if isinstance(dhcp, Mapping) else None
        if not isinstance(nameservers, Mapping):
            return VPCNameservers(ipv4=[], ipv6=[], raw={})
        ipv4 = [VPCNameserver(server=str(s), raw={"server": s}) for s in nameservers.get("ipv4") or []]
        ipv6 = [VPCNameserver(server=str(s), raw={"server": s}) for s in nameservers.get("ipv6") or []]
        return VPCNameservers(ipv4=ipv4, ipv6=ipv6, raw=dict(nameservers))

    def replace_vpc_nameservers(self, vpc_id: int, servers: Sequence[str]) -> List[VPCNameserver]:
        """Replace the complete set of DHCP nameservers announced by a VPC.

        Unlike `update_vpc_nameservers`, this takes a single flat list of
        servers rather than separate IPv4 and IPv6 lists, mirroring gona's
        ReplaceVPCNameserversRequest.

        Parameters:
            vpc_id: VPC identifier.
            servers: Complete set of nameserver addresses to announce.
        """
        body = {"nameservers": [{"server": server} for server in servers]}
        data = self._put_json(f"/vpcs/{vpc_id}/dhcp/nameservers", body)
        if not isinstance(data, Mapping):
            return []
        rows = data.get("nameservers")
        if not isinstance(rows, list):
            return []
        return [VPCNameserver.from_api(row) for row in rows]

    def update_vpc_nameservers(
        self, vpc_id: int, ipv4: Optional[Sequence[str]] = None, ipv6: Optional[Sequence[str]] = None
    ) -> VPCNameservers:
        """Update the DHCP nameservers announced by a VPC, by IP version.

        Parameters:
            vpc_id: VPC identifier.
            ipv4: Optional complete set of IPv4 nameserver addresses.
            ipv6: Optional complete set of IPv6 nameserver addresses.
        """
        body: Dict[str, Any] = {}
        if ipv4 is not None:
            body["ipv4"] = [{"server": server} for server in ipv4]
        if ipv6 is not None:
            body["ipv6"] = [{"server": server} for server in ipv6]
        data = self._patch_json(f"/vpcs/{vpc_id}/dhcp/nameservers", body)
        if not isinstance(data, Mapping):
            return VPCNameservers(ipv4=[], ipv6=[], raw={})
        return VPCNameservers.from_api(data)

    def get_account_limits(self) -> Dict[str, AccountLimit]:
        """Return every account-wide resource limit, keyed by resource name."""
        data = self._request("GET", "/account-limits")
        if not isinstance(data, Mapping):
            raise NetActuateError("get account limits response must be an object")
        return {key: AccountLimit.from_api(value) for key, value in data.items()}

    def _post_json(self, path: str, body: Any = None) -> Any:
        return self._request("POST", path, json_body=body)

    def _put_json(self, path: str, body: Any = None) -> Any:
        return self._request("PUT", path, json_body=body)

    def _patch_json(self, path: str, body: Any = None) -> Any:
        return self._request("PATCH", path, json_body=body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    def _request(self, method: str, path: str, json_body: Any = None) -> Any:
        url = _with_key(urljoin(self.base_url, path), self._api_key)
        response = self.session.request(method, url, json=json_body, timeout=self.timeout)
        if response.status_code == 204:
            return None
        payload = _json(response)
        code = int(payload.get("code") or 0)
        data = payload.get("data")
        message = ""
        if isinstance(data, Mapping):
            message = str(data.get("message") or data.get("error") or "")
        if not message:
            message = str(payload.get("message") or "")
        if response.status_code == 404 or code == 404 or "not found" in message.lower():
            raise NotFoundError(message or "resource not found", method=method, url=url, status_code=response.status_code, code=code, body=data)
        if _looks_contract_gated(response.status_code, code, message):
            raise ContractError(message or "contract gated capability refused", method=method, url=url, status_code=response.status_code, code=code, body=data)
        if response.status_code < 200 or response.status_code >= 300 or (code and (code < 200 or code >= 300)):
            raise NetActuateError(message or "API request failed", method=method, url=url, status_code=response.status_code, code=code, body=data)
        return data

    def _get_list(self, path: str) -> List[Any]:
        rows, meta, paginator = self._read_list_page(path)
        all_rows = list(rows)
        while meta and meta.get("total", 0) and meta.get("limit", 0) and meta.get("offset", 0) + meta.get("limit", 0) < meta.get("total", 0):
            path = _page_path(path, offset=int(meta["offset"]) + int(meta["limit"]), limit=int(meta["limit"]))
            rows, meta, paginator = self._read_list_page(path)
            if not rows:
                break
            all_rows.extend(rows)
        while paginator and paginator.get("current_page", 0) < paginator.get("last_page", 0):
            path = _page_path(path, page=int(paginator["current_page"]) + 1)
            rows, meta, paginator = self._read_list_page(path)
            if not rows:
                break
            all_rows.extend(rows)
        return all_rows

    def _read_list_page(self, path: str) -> Tuple[List[Any], Dict[str, int], Dict[str, int]]:
        data = self._request("GET", path)
        return _unwrap_v3_list(data)


def _router_vrf_bgp_neighbor_body(
    address: str,
    remote_asn: int,
    is_shutdown: bool,
    do_as_override: bool,
    do_next_help_self: bool,
    enabled_ipv4: bool,
    enabled_ipv6: bool,
    source_address: Optional[str],
    ebgp_multihop: Optional[int],
    md5_secret: str,
    import_route_map: Optional[Mapping[str, Any]],
    export_route_map: Optional[Mapping[str, Any]],
    name: str,
    description: str,
) -> Dict[str, Any]:
    """Build the JSON body shared by router VRF BGP neighbor create and update calls.

    Mirrors gona's CreateRouterVRFBGPNeighborRequest and
    UpdateRouterVRFBGPNeighborRequest, which share an identical shape:
    address, isShutdown, doAsOverride, doNextHelpSelf, enabledIpVersion and
    asn are always sent, while source, ebgpMultihop, md5Secret, import,
    export, name and description are omitted when left unset.

    Parameters:
        address: Neighbor IP address.
        remote_asn: Neighbor's remote ASN.
        is_shutdown: Whether the neighbor is administratively shut down.
        do_as_override: Whether AS override is enabled.
        do_next_help_self: Whether next-hop-self is enabled.
        enabled_ipv4: Whether IPv4 is enabled for the neighbor.
        enabled_ipv6: Whether IPv6 is enabled for the neighbor.
        source_address: Optional source address override.
        ebgp_multihop: Optional eBGP multihop count.
        md5_secret: Optional MD5 authentication secret.
        import_route_map: Optional import route map, in API shape (doDefaultDrop and rules).
        export_route_map: Optional export route map, in API shape.
        name: Optional neighbor name.
        description: Optional neighbor description.
    """
    body: Dict[str, Any] = {
        "address": address,
        "isShutdown": is_shutdown,
        "doAsOverride": do_as_override,
        "doNextHelpSelf": do_next_help_self,
        "enabledIpVersion": {"ipv4": enabled_ipv4, "ipv6": enabled_ipv6},
        "asn": {"remote": remote_asn},
    }
    if source_address:
        body["source"] = {"address": source_address}
    if ebgp_multihop is not None:
        body["ebgpMultihop"] = ebgp_multihop
    if md5_secret:
        body["md5Secret"] = md5_secret
    if import_route_map is not None:
        body["import"] = dict(import_route_map)
    if export_route_map is not None:
        body["export"] = dict(export_route_map)
    if name:
        body["name"] = name
    if description:
        body["description"] = description
    return body


def _router_static_route_body(
    network: str,
    via_next_hop: str,
    via_interface_id: Optional[int],
    via_tunnel_id: Optional[int],
    via_ip_sec_peer_id: Optional[int],
    description: str,
    distance: Optional[int],
) -> Dict[str, Any]:
    """Build the JSON body shared by router static route create and update calls.

    Mirrors gona's CreateRouterStaticRouteRequest and
    UpdateRouterStaticRouteRequest: network and via are always sent, with
    via's own fields omitted when unset, and description and distance
    omitted when left unset.

    Parameters:
        network: Destination network in CIDR notation.
        via_next_hop: Optional next-hop IP address.
        via_interface_id: Optional next-hop interface identifier.
        via_tunnel_id: Optional next-hop tunnel identifier.
        via_ip_sec_peer_id: Optional next-hop IPsec peer identifier.
        description: Optional route description.
        distance: Optional administrative distance.
    """
    via: Dict[str, Any] = {}
    if via_next_hop:
        via["nextHop"] = via_next_hop
    if via_interface_id is not None:
        via["interfaceId"] = via_interface_id
    if via_tunnel_id is not None:
        via["tunnelId"] = via_tunnel_id
    if via_ip_sec_peer_id is not None:
        via["ipSecPeerId"] = via_ip_sec_peer_id
    body: Dict[str, Any] = {"network": network, "via": via}
    if description:
        body["description"] = description
    if distance is not None:
        body["distance"] = distance
    return body


def _router_prefix_list_body(
    name: str,
    ip_version: int,
    description: str,
    rules: Optional[Sequence[Mapping[str, Any]]],
) -> Dict[str, Any]:
    """Build the JSON body shared by router prefix list create and update calls.

    Mirrors gona's CreateRouterPrefixListRequest and
    UpdateRouterPrefixListRequest: name, ipVersion and rules carry no
    omitempty tag and so are always sent, with rules defaulting to an empty
    list, while description is omitted when left unset.

    Parameters:
        name: Prefix list name.
        ip_version: IP version the prefix list matches.
        description: Optional prefix list description.
        rules: Rules to send, each a mapping with action and prefix keys, or
            None to send an empty list.
    """
    body: Dict[str, Any] = {
        "name": name,
        "ipVersion": ip_version,
        "rules": [{"action": rule["action"], "prefix": rule["prefix"]} for rule in rules] if rules else [],
    }
    if description:
        body["description"] = description
    return body


def _router_vrf_ipsec_peer_body(
    name: str,
    remote_id: str,
    psk_secret: str,
    do_initiate_connection: bool,
    description: Optional[str],
    peer_address: str,
    overlay_ipv4: Optional[str],
    overlay_ipv6: Optional[str],
) -> Dict[str, Any]:
    """Build the JSON body shared by router VRF IPsec peer create and update calls.

    Mirrors gona's CreateRouterVRFIPSecPeerRequest, which
    UpdateRouterVRFIPSecPeerRequest aliases: name, remoteId, pskSecret,
    doInitiateConnection and overlayNetwork are always sent, while
    description, peerAddress and the overlay network's own ipv4 and ipv6
    are omitted when left unset.

    Parameters:
        name: Peer name.
        remote_id: Remote IKE identity.
        psk_secret: Pre-shared key secret.
        do_initiate_connection: Whether this side initiates the connection.
        description: Optional peer description.
        peer_address: Optional remote peer address.
        overlay_ipv4: Optional IPv4 overlay network for the peer.
        overlay_ipv6: Optional IPv6 overlay network for the peer.
    """
    overlay_network: Dict[str, Any] = {}
    if overlay_ipv4:
        overlay_network["ipv4"] = overlay_ipv4
    if overlay_ipv6:
        overlay_network["ipv6"] = overlay_ipv6
    body: Dict[str, Any] = {
        "name": name,
        "remoteId": remote_id,
        "pskSecret": psk_secret,
        "doInitiateConnection": do_initiate_connection,
        "overlayNetwork": overlay_network,
    }
    if description is not None:
        body["description"] = description
    if peer_address:
        body["peerAddress"] = peer_address
    return body


def _router_vrf_interface_body(
    interface_type: str,
    name: str,
    description: Optional[str],
    ipv4_cidr: Optional[str],
    ipv6_cidr: Optional[str],
    ethernet_hardware_id: Optional[str],
    wireguard_port: Optional[int],
) -> Dict[str, Any]:
    """Build the JSON body shared by router VRF interface create and update calls.

    Mirrors gona's CreateRouterVRFInterfaceRequest and
    UpdateRouterVRFInterfaceRequest: type and name are always sent, while
    description, ipv4Cidr, ipv6Cidr, ethernetHardwareId and wireguardPort
    are omitted when left unset.

    Parameters:
        interface_type: Interface type, such as ethernet or wireguard.
        name: Interface name.
        description: Optional interface description.
        ipv4_cidr: Optional IPv4 address in CIDR notation.
        ipv6_cidr: Optional IPv6 address in CIDR notation.
        ethernet_hardware_id: Optional backing ethernet hardware identifier.
        wireguard_port: Optional wireguard listen port.
    """
    body: Dict[str, Any] = {"type": interface_type, "name": name}
    if description is not None:
        body["description"] = description
    if ipv4_cidr is not None:
        body["ipv4Cidr"] = ipv4_cidr
    if ipv6_cidr is not None:
        body["ipv6Cidr"] = ipv6_cidr
    if ethernet_hardware_id is not None:
        body["ethernetHardwareId"] = ethernet_hardware_id
    if wireguard_port is not None:
        body["wireguardPort"] = wireguard_port
    return body


def _router_vrf_nat_rule_create_body(
    ip_version: int,
    protocol: str,
    description: str,
    match: Optional[Mapping[str, Any]],
    translation: Optional[Mapping[str, Any]],
    priority: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build the JSON body for a router VRF SNAT or DNAT rule create call.

    Mirrors gona's CreateRouterVRFSNATRuleRequest and
    CreateRouterVRFDNATRuleRequest, which share an identical shape:
    ipVersion, protocol, match and translation carry no omitempty tag and
    so are always sent, the latter two as null when not given, while
    description and priority are omitted when left unset.

    Parameters:
        ip_version: IP version the rule applies to, 4 or 6.
        protocol: Protocol the rule matches.
        description: Optional rule description.
        match: Match block, passed through as the API expects it.
        translation: Translation block, passed through as the API expects it.
        priority: Optional priority block, passed through as the API expects it.
    """
    body: Dict[str, Any] = {
        "ipVersion": ip_version,
        "protocol": protocol,
        "match": dict(match) if match is not None else None,
        "translation": dict(translation) if translation is not None else None,
    }
    if description:
        body["description"] = description
    if priority is not None:
        body["priority"] = dict(priority)
    return body


def _router_vrf_nat_rule_update_body(
    ip_version: int,
    protocol: str,
    description: str,
    match: Optional[Mapping[str, Any]],
    translation: Optional[Mapping[str, Any]],
    priority: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Build the JSON body for a router VRF SNAT or DNAT rule update call.

    Mirrors gona's UpdateRouterVRFSNATRuleRequest and
    UpdateRouterVRFDNATRuleRequest, which share an identical shape:
    ipVersion, protocol and description carry no omitempty tag and so are
    always sent, description included even when empty, while match,
    translation and priority are omitted when left unset.

    Parameters:
        ip_version: IP version the rule applies to, 4 or 6.
        protocol: Protocol the rule matches.
        description: Rule description.
        match: Optional match block, passed through as the API expects it.
        translation: Optional translation block, passed through as the API expects it.
        priority: Optional priority block, passed through as the API expects it.
    """
    body: Dict[str, Any] = {"ipVersion": ip_version, "protocol": protocol, "description": description}
    if match is not None:
        body["match"] = dict(match)
    if translation is not None:
        body["translation"] = dict(translation)
    if priority is not None:
        body["priority"] = dict(priority)
    return body


def _encode_backend_host(host: Mapping[str, Any]) -> Dict[str, Any]:
    body: Dict[str, Any] = {}
    name = host.get("name")
    if name:
        body["name"] = name
    address = host.get("address")
    if address:
        body["address"] = address
    internal_address = host.get("internal_address", host.get("internalAddress"))
    if internal_address:
        body["internalAddress"] = internal_address
    backend_host_id = host.get("backend_host_id", host.get("backendHostId"))
    if backend_host_id:
        body["backendHostId"] = backend_host_id
    return body


def _http_lb_group_body(
    name: str,
    algorithm: str,
    internal_port: int,
    match: Mapping[str, Any],
    health_check: Mapping[str, Any],
    rules: Sequence[Mapping[str, Any]],
    backends: Sequence[Mapping[str, Any]],
    description: str,
    sticky_sessions_enabled: bool,
    ssl_to_backend_enabled: bool,
) -> Dict[str, Any]:
    """Build the JSON body shared by HTTP LB group create and replace calls.

    Mirrors gona's CreateHTTPLBGroupRequest and ReplaceHTTPLBGroupRequest,
    which share an identical shape: every field except description is
    always sent, with description omitted when unset.

    Parameters:
        name: Group name.
        algorithm: Load balancing algorithm to use.
        internal_port: Backend port the group forwards traffic to.
        match: Match criteria, passed through as the API expects it.
        health_check: Health check settings, passed through as the API expects it.
        rules: Domain and path routing rules, each passed through as the API expects it.
        backends: Backend hosts to bind, each passed through as the API expects it.
        description: Optional group description.
        sticky_sessions_enabled: Whether to enable sticky sessions.
        ssl_to_backend_enabled: Whether to use SSL when forwarding to backends.
    """
    body: Dict[str, Any] = {
        "name": name,
        "algorithm": algorithm,
        "stickySessionsEnabled": sticky_sessions_enabled,
        "sslToBackendEnabled": ssl_to_backend_enabled,
        "internalPort": internal_port,
        "match": dict(match),
        "healthCheck": dict(health_check),
        "rules": [dict(rule) for rule in rules],
        "backends": [dict(backend) for backend in backends],
    }
    if description:
        body["description"] = description
    return body


def _nlb_group_body(
    name: str,
    ip_version: int,
    algorithm: str,
    match: Mapping[str, Any],
    health_check: Mapping[str, Any],
    rules: Sequence[Mapping[str, Any]],
    backends: Sequence[Mapping[str, Any]],
    description: str,
) -> Dict[str, Any]:
    """Build the JSON body shared by NLB group create and replace calls.

    Mirrors gona's CreateNLBGroupRequest and ReplaceNLBGroupRequest, which
    share an identical shape: name, ipVersion, algorithm, match, healthCheck,
    rules and backends are always sent, with description omitted when unset.

    Parameters:
        name: Group name.
        ip_version: IP version the group matches, 4 or 6.
        algorithm: Load balancing algorithm to use.
        match: Match criteria, passed through as the API expects it.
        health_check: Health check settings, passed through as the API expects it.
        rules: Protocol and port mapping rules, each passed through as the API expects it.
        backends: Backend hosts to bind, each passed through as the API expects it.
        description: Optional group description.
    """
    body: Dict[str, Any] = {
        "name": name,
        "ipVersion": ip_version,
        "algorithm": algorithm,
        "match": dict(match),
        "healthCheck": dict(health_check),
        "rules": [dict(rule) for rule in rules],
        "backends": [dict(backend) for backend in backends],
    }
    if description:
        body["description"] = description
    return body


def _unwrap_backend_hosts(data: Any) -> List[Any]:
    """Return the backendHosts list from a VPC backends response.

    This endpoint answers with an object carrying the backend hosts, not a
    bare array, for both the list and replace operations.
    """
    if isinstance(data, Mapping):
        hosts = data.get("backendHosts")
        if isinstance(hosts, list):
            return hosts
        raise NetActuateError("VPC backends response is missing backendHosts")
    raise NetActuateError("VPC backends response must be an object with backendHosts")


def _unwrap_v3_list(data: Any) -> Tuple[List[Any], Dict[str, int], Dict[str, int]]:
    if isinstance(data, list):
        return data, {}, {}
    if not isinstance(data, Mapping):
        raise NetActuateError("vAPI3 list response has no list data")
    paginator = data.get("paginator")
    if isinstance(paginator, Mapping) and isinstance(paginator.get("data"), list):
        return list(paginator["data"]), _meta(data.get("meta")), _paginator(paginator)
    rows = data.get("data")
    if isinstance(rows, list):
        return list(rows), _meta(data.get("meta")), {}
    if isinstance(rows, Mapping) and isinstance(rows.get("paginator"), Mapping):
        nested_paginator = rows["paginator"]
        if isinstance(nested_paginator.get("data"), list):
            return list(nested_paginator["data"]), _meta(rows.get("meta")), _paginator(nested_paginator)
    for key, value in data.items():
        if key == "meta":
            continue
        if isinstance(value, Mapping) and isinstance(value.get("data"), list):
            return list(value["data"]), _meta(value.get("meta")), {}
    raise NetActuateError("vAPI3 list response has no list data")


def _meta(value: Any) -> Dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {key: int(value.get(key) or 0) for key in ("limit", "offset", "total")}


def _paginator(value: Mapping[str, Any]) -> Dict[str, int]:
    return {key: int(value.get(key) or 0) for key in ("current_page", "last_page")}


def _nested_list_data(value: Any) -> Optional[List[Any]]:
    """Return the `data` list nested under a vAPI3 sub-resource wrapper.

    Returns None when the wrapper or its `data` member is absent, so a caller
    can distinguish "not present" from "present and empty", and raises when
    `data` is present but not a list.

    Parameters:
        value: Decoded JSON value for the wrapper, or None.
    """
    if not isinstance(value, Mapping):
        return None
    data = value.get("data")
    if data is None:
        return None
    if not isinstance(data, list):
        raise NetActuateError("vAPI3 nested list wrapper has a non-list data member")
    return data
