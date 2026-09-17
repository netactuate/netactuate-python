from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from netactuate import Client, ContractError, NetActuateError, NotFoundError, V3Client


class RecordedResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.url = ""
        self.request = requests.Request("GET", "https://example.test").prepare()

    def json(self) -> Any:
        return self._payload


class RecordedSession:
    def __init__(self, responses: List[RecordedResponse]) -> None:
        self.responses = responses
        self.calls: List[Dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> RecordedResponse:
        if not self.responses:
            raise AssertionError("no recorded response left")
        response = self.responses.pop(0)
        prepared = requests.Request(method, url).prepare()
        response.request = prepared
        response.url = url
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return response


def response(data: Any, code: int = 200, status: int = 200) -> RecordedResponse:
    return RecordedResponse({"code": code, "data": data}, status)


def test_clients_read_key_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETACTUATE_API_KEY", "env-secret")
    session = RecordedSession([RecordedResponse({"result": "success", "data": []})])

    Client(session=session).list_servers()

    parsed = urlsplit(session.calls[0]["url"])
    assert parse_qs(parsed.query)["key"] == ["env-secret"]


def test_vapi3_follows_meta_pagination() -> None:
    session = RecordedSession(
        [
            response({"data": [{"vpcId": 1, "label": "one"}], "meta": {"limit": 1, "offset": 0, "total": 2}}),
            response({"data": [{"vpcId": 2, "label": "two"}], "meta": {"limit": 1, "offset": 1, "total": 2}}),
        ]
    )

    vpcs = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpcs()

    assert [vpc.vpc_id for vpc in vpcs] == [1, 2]
    assert "offset=1" in session.calls[1]["url"]
    assert "limit=1" in session.calls[1]["url"]


@pytest.mark.parametrize(
    "payload",
    [
        [{"vpcId": 7, "label": "bare"}],
        {"data": [{"vpcId": 7, "label": "data"}]},
        {"vpcs": {"data": [{"vpcId": 7, "label": "named"}], "meta": {"limit": 10, "offset": 0, "total": 1}}},
        {"paginator": {"current_page": 1, "last_page": 1, "data": [{"vpcId": 7, "label": "pager"}]}},
    ],
)
def test_vapi3_accepts_all_list_envelopes(payload: Any) -> None:
    session = RecordedSession([response(payload)])

    vpcs = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpcs()

    assert len(vpcs) == 1
    assert vpcs[0].vpc_id == 7


def test_vapi3_follows_laravel_pagination() -> None:
    session = RecordedSession(
        [
            response({"paginator": {"current_page": 1, "last_page": 2, "data": [{"vpcId": 1, "label": "one"}]}}),
            response({"paginator": {"current_page": 2, "last_page": 2, "data": [{"vpcId": 2, "label": "two"}]}}),
        ]
    )

    vpcs = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpcs()

    assert [vpc.vpc_id for vpc in vpcs] == [1, 2]
    assert "page=2" in session.calls[1]["url"]


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (Client(api_key="secret", base_url="https://api.test/", session=RecordedSession([RecordedResponse({"code": 404, "message": "gone", "data": {}})])), NotFoundError),
        (V3Client(api_key="secret", base_url="https://api.test", session=RecordedSession([response({"message": "not found"}, code=404)])), NotFoundError),
    ],
)
def test_not_found_is_distinguishable(client: Any, expected: Any) -> None:
    with pytest.raises(expected):
        if isinstance(client, Client):
            client.get_zone(99)
        else:
            client.get_vpc(99)


@pytest.mark.parametrize(
    "client",
    [
        Client(api_key="secret", base_url="https://api.test/", session=RecordedSession([RecordedResponse({"code": 412, "message": "contract required", "data": {}})])),
        V3Client(api_key="secret", base_url="https://api.test", session=RecordedSession([response({"message": "contract required"}, code=412)])),
    ],
)
def test_contract_error_is_distinguishable(client: Any) -> None:
    with pytest.raises(ContractError):
        if isinstance(client, Client):
            client.get_zone(99)
        else:
            client.get_vpc(99)


def test_error_text_redacts_key_from_url() -> None:
    key = "secret-in-url"
    session = RecordedSession([response({"message": "boom"}, code=500, status=500)])

    with pytest.raises(NetActuateError) as caught:
        V3Client(api_key=key, base_url="https://api.test", session=session).get_vpc(1)

    assert key not in str(caught.value)
    assert "key=REDACTED" in str(caught.value)


def test_client_repr_does_not_include_key() -> None:
    client = V3Client(api_key="repr-secret", base_url="https://api.test", session=RecordedSession([]))

    assert "repr-secret" not in repr(client)
