"""HTTP clients for NetActuate vAPI2 and vAPI3."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from netactuate.errors import ContractError, NetActuateError, NotFoundError
from netactuate.models import DNSRecord, DNSZone, NKECluster, Server, StorageBucket, VPC

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


def _looks_contract_gated(status_code: int, code: int, message: str) -> bool:
    text = message.lower()
    return (
        status_code == 412
        or code == 412
        or "contract" in text
        or "not entitled" in text
        or "not enabled" in text
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

    def _get(self, path: str) -> Any:
        response = self._request("GET", path)
        return response

    def _request(self, method: str, path: str, json_body: Any = None) -> Any:
        url = _with_key(urljoin(self.base_url, path), self._api_key)
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

    def list_storage_buckets(self) -> List[StorageBucket]:
        """Return all storage buckets visible to the account."""
        return [StorageBucket.from_api(row) for row in self._get_list("/storage/buckets?limit=1000")]

    def get_storage_bucket(self, bucket_id: int) -> StorageBucket:
        """Return one storage bucket.

        Parameters:
            bucket_id: Storage bucket identifier.
        """
        return StorageBucket.from_api(self._request("GET", f"/storage/buckets/{bucket_id}"))

    def list_nke_clusters(self) -> List[NKECluster]:
        """Return all NKE clusters visible to the account."""
        return [NKECluster.from_api(row) for row in self._get_list("/nke/clusters")]

    def get_nke_cluster(self, cluster_id: int) -> NKECluster:
        """Return one NKE cluster.

        Parameters:
            cluster_id: NKE cluster identifier.
        """
        return NKECluster.from_api(self._request("GET", f"/nke/clusters/{cluster_id}"))

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
