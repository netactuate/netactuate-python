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


def test_create_zone_sends_form_encoded_body() -> None:
    session = RecordedSession([response({"id": 1, "name": "example.com", "type": "master"})])

    zone = Client(api_key="secret", base_url="https://api.test/", session=session).create_zone(
        "example.com", "master", ip="192.0.2.1"
    )

    assert zone.id == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "dns/zone" in call["url"]
    assert call["kwargs"]["data"] == {"name": "example.com", "type": "master", "ip": "192.0.2.1"}
    assert "json" not in call["kwargs"] or call["kwargs"]["json"] is None


def test_delete_zone_calls_delete() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_zone(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "dns/zone/1" in session.calls[0]["url"]


def test_create_record_omits_zero_ttl_and_priority() -> None:
    session = RecordedSession(
        [response({"id": 2, "domain_id": 1, "name": "www", "type": "A", "content": "192.0.2.1"})]
    )

    record = Client(api_key="secret", base_url="https://api.test/", session=session).create_record(
        1, "A", "192.0.2.1", name="www"
    )

    assert record.id == 2
    values = session.calls[0]["kwargs"]["data"]
    assert values == {"domain_id": 1, "name": "www", "type": "A", "record_content": "192.0.2.1"}


def test_create_record_includes_ttl_and_priority_when_set() -> None:
    session = RecordedSession(
        [response({"id": 3, "domain_id": 1, "name": "mx", "type": "MX", "content": "mail.example.com"})]
    )

    Client(api_key="secret", base_url="https://api.test/", session=session).create_record(
        1, "MX", "mail.example.com", name="mx", ttl=3600, priority=10
    )

    values = session.calls[0]["kwargs"]["data"]
    assert values["ttl"] == 3600
    assert values["prio"] == 10


def test_update_record_puts_to_dns_record() -> None:
    session = RecordedSession(
        [response({"id": 2, "domain_id": 1, "name": "www", "type": "A", "content": "192.0.2.2"})]
    )

    record = Client(api_key="secret", base_url="https://api.test/", session=session).update_record(
        2, 1, "A", "192.0.2.2", name="www"
    )

    assert record.content == "192.0.2.2"
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["url"].split("?")[0].endswith("dns/record")
    assert call["kwargs"]["data"]["id"] == 2


def test_delete_record_calls_delete() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_record(2)

    assert session.calls[0]["method"] == "DELETE"
    assert "dns/record/2" in session.calls[0]["url"]


def _tag_payload(tag_id: int = 1, **overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "id": tag_id,
        "name": "prod",
        "description": "",
        "icon": "",
        "color": "",
        "is_default": 0,
        "is_favorite": 0,
        "is_locked": 0,
        "show_dashboard": 0,
        "created_at": "2026-01-01T00:00:00Z",
        "mb_id": 0,
        "resources_count": 0,
        "resources": [],
    }
    payload.update(overrides)
    return payload


def test_list_tags_decodes_embedded_resources() -> None:
    resource_row = {
        "id": 5,
        "resource_tag_id": 1,
        "resource_name": "server",
        "identifier": 99,
        "created_at": "2026-01-01T00:00:00Z",
    }
    session = RecordedSession([response([_tag_payload(resources=[resource_row])])])

    tags = Client(api_key="secret", base_url="https://api.test/", session=session).list_tags()

    assert len(tags) == 1
    assert tags[0].resources[0].resource_name == "server"


def test_get_tag_returns_matching_tag() -> None:
    session = RecordedSession([response([_tag_payload(1), _tag_payload(2)])])

    tag = Client(api_key="secret", base_url="https://api.test/", session=session).get_tag(2)

    assert tag.id == 2


def test_get_tag_raises_not_found_when_absent() -> None:
    session = RecordedSession([response([_tag_payload(1)])])

    with pytest.raises(NotFoundError):
        Client(api_key="secret", base_url="https://api.test/", session=session).get_tag(99)


def test_create_tag_sends_json_body() -> None:
    session = RecordedSession([response(_tag_payload(1))])

    tag = Client(api_key="secret", base_url="https://api.test/", session=session).create_tag(
        "prod", description="production hosts"
    )

    assert tag.id == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {"name": "prod", "description": "production hosts"}


def test_update_tag_sends_flags_as_integers() -> None:
    session = RecordedSession([response(_tag_payload(1, is_locked=1))])

    Client(api_key="secret", base_url="https://api.test/", session=session).update_tag(
        1, "prod", is_locked=True
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["is_locked"] == 1
    assert body["is_default"] == 0


def test_delete_tag_calls_delete() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_tag(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "tags/1" in session.calls[0]["url"]


def test_assign_tag_resource_sends_string_identifier() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).assign_tag_resource(
        1, "server", 42
    )

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "tags/1/assign-resource" in call["url"]
    assert call["kwargs"]["json"] == {"resource_name": "server", "identifier": "42"}


def test_remove_tag_resource_sends_string_identifier() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).remove_tag_resource(
        1, "server", 42
    )

    assert "tags/1/remove-resource" in session.calls[0]["url"]


def test_get_resource_tags_builds_path() -> None:
    session = RecordedSession([response([_tag_payload(1)])])

    tags = Client(api_key="secret", base_url="https://api.test/", session=session).get_resource_tags(
        "server", 42
    )

    assert len(tags) == 1
    assert "tags/resource/server/id/42" in session.calls[0]["url"]


def test_get_tag_resources_decodes_rows() -> None:
    resource_row = {
        "id": 5,
        "resource_tag_id": 1,
        "resource_name": "server",
        "identifier": 99,
        "created_at": "2026-01-01T00:00:00Z",
    }
    session = RecordedSession([response([resource_row])])

    resources = Client(api_key="secret", base_url="https://api.test/", session=session).get_tag_resources(1)

    assert resources[0].identifier == 99


def test_get_tag_logs_decodes_rows_without_requiring_id() -> None:
    session = RecordedSession([response([{"action": "created", "message": "tag created"}])])

    logs = Client(api_key="secret", base_url="https://api.test/", session=session).get_tag_logs(1)

    assert logs[0].action == "created"


def test_list_ssh_keys_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"id": 1, "name": "laptop", "ssh_key": "ssh-ed25519 AAAA", "fingerprint": "aa:bb"}])]
    )

    keys = Client(api_key="secret", base_url="https://api.test/", session=session).list_ssh_keys()

    assert keys[0].name == "laptop"


def test_get_ssh_key_returns_key() -> None:
    session = RecordedSession(
        [response({"id": 1, "name": "laptop", "ssh_key": "ssh-ed25519 AAAA", "fingerprint": "aa:bb"})]
    )

    key = Client(api_key="secret", base_url="https://api.test/", session=session).get_ssh_key(1)

    assert key.fingerprint == "aa:bb"


def test_get_ssh_key_raises_not_found_on_null_body() -> None:
    session = RecordedSession([response(None)])

    with pytest.raises(NotFoundError):
        Client(api_key="secret", base_url="https://api.test/", session=session).get_ssh_key(1)


def test_create_ssh_key_sends_form_encoded_body() -> None:
    session = RecordedSession([response({"id": 1, "name": "laptop", "ssh_key": "ssh-ed25519 AAAA"})])

    key = Client(api_key="secret", base_url="https://api.test/", session=session).create_ssh_key(
        "laptop", "ssh-ed25519 AAAA"
    )

    assert key.id == 1
    assert session.calls[0]["kwargs"]["data"] == {"ssh_key": "ssh-ed25519 AAAA", "name": "laptop"}


def test_update_ssh_key_sends_json_patch() -> None:
    session = RecordedSession([response({"id": 1, "name": "renamed", "ssh_key": "ssh-ed25519 AAAA"})])

    key = Client(api_key="secret", base_url="https://api.test/", session=session).update_ssh_key(
        1, "renamed", "ssh-ed25519 AAAA"
    )

    assert key.name == "renamed"
    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"name": "renamed", "ssh_key": "ssh-ed25519 AAAA"}


def test_delete_ssh_key_calls_delete() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_ssh_key(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "account/ssh_key/1" in session.calls[0]["url"]


def test_list_vpc_locations_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "NYC"}])])

    locations = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_locations()

    assert locations[0].id == 1
    assert locations[0].name == "NYC"


def test_create_vpc_sends_required_and_optional_fields() -> None:
    session = RecordedSession([response({"vpcId": 1, "label": "prod"})])

    vpc = V3Client(api_key="secret", base_url="https://api.test", session=session).create_vpc(
        "prod", location_id=5, network={"ipv4": "10.0.0.0/24"}
    )

    assert vpc.vpc_id == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {
        "label": "prod",
        "description": "",
        "location_id": 5,
        "network": {"ipv4": "10.0.0.0/24"},
    }


def test_update_vpc_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"vpcId": 1, "label": "renamed"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc(1, label="renamed")

    assert session.calls[0]["kwargs"]["json"] == {"label": "renamed"}


def test_delete_vpc_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/vpcs/1" in session.calls[0]["url"]


def test_add_vpc_standby_gateway_posts_without_body() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).add_vpc_standby_gateway(1)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/1/gateway/standby" in call["url"]
    assert call["kwargs"]["json"] is None


def test_delete_vpc_standby_gateway_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_standby_gateway(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/vpcs/1/gateway/standby" in session.calls[0]["url"]


def test_get_vpc_ip_reservations_decodes_raw_sections() -> None:
    session = RecordedSession(
        [response({"gateways": [{"ip": "192.0.2.1"}], "interfaces": [], "vms": []})]
    )

    reservations = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).get_vpc_ip_reservations(1)

    assert reservations.gateways == [{"ip": "192.0.2.1"}]


def test_get_vpc_ssh_settings_decodes_plain_port_and_keys() -> None:
    session = RecordedSession(
        [response({"port": 2222, "enabled": True, "keys": {"5": {"id": 5, "name": "laptop"}}})]
    )

    settings = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).get_vpc_ssh_settings(1)

    assert settings.port == 2222
    assert settings.enabled is True
    assert settings.keys["5"]["name"] == "laptop"


def test_get_vpc_ssh_settings_decodes_object_port_and_wrapped_keys() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "port": {"value": 22},
                    "enabled": False,
                    "keys": {"data": [{"id": 9, "name": "office"}]},
                    "bastion": {"ipv4": "192.0.2.1"},
                }
            )
        ]
    )

    settings = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).get_vpc_ssh_settings(1)

    assert settings.port == 22
    assert settings.keys["9"]["name"] == "office"
    assert settings.bastion == {"ipv4": "192.0.2.1"}


def test_wait_for_vpc_ready_returns_once_running() -> None:
    session = RecordedSession([response({"vpcId": 1, "label": "x", "status": "Running"})])

    vpc = V3Client(api_key="secret", base_url="https://api.test", session=session).wait_for_vpc_ready(1)

    assert vpc.metadata["status"] == "Running"
    assert len(session.calls) == 1


def test_wait_for_vpc_ready_times_out() -> None:
    session = RecordedSession([response({"vpcId": 1, "label": "x", "status": "Building"})])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).wait_for_vpc_ready(
            1, timeout=0
        )


def test_create_vpc_backend_template_sends_json_body() -> None:
    session = RecordedSession(
        [response({"backendTemplateId": 1, "name": "web", "description": "", "backendHosts": []})]
    )

    template = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_vpc_backend_template(7, name="web", backend_hosts=[{"name": "h1", "address": "192.0.2.10"}])

    assert template.backend_template_id == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/backend-templates" in call["url"]
    assert call["kwargs"]["json"] == {
        "name": "web",
        "backendHosts": [{"name": "h1", "address": "192.0.2.10"}],
    }


def test_get_vpc_backend_template_builds_path() -> None:
    session = RecordedSession([response({"backendTemplateId": 2, "name": "web"})])

    template = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).get_vpc_backend_template(7, 2)

    assert template.backend_template_id == 2
    assert "/vpcs/7/backend-templates/2" in session.calls[0]["url"]


def test_list_vpc_backend_templates_decodes_rows() -> None:
    session = RecordedSession([response([{"backendTemplateId": 3, "name": "web"}])])

    templates = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_vpc_backend_templates(7)

    assert templates[0].backend_template_id == 3


def test_update_vpc_backend_template_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"backendTemplateId": 3, "name": "renamed"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc_backend_template(
        7, 3, name="renamed"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"name": "renamed"}


def test_replace_vpc_backend_template_always_sends_backend_hosts() -> None:
    session = RecordedSession([response({"backendTemplateId": 3, "name": "web", "backendHosts": []})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).replace_vpc_backend_template(
        7, 3, []
    )

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {"backendHosts": []}


def test_delete_vpc_backend_template_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_backend_template(7, 3)

    assert session.calls[0]["method"] == "DELETE"
    assert "/vpcs/7/backend-templates/3" in session.calls[0]["url"]


def test_create_vpc_backend_sends_json_body() -> None:
    session = RecordedSession([response({"backendHostId": 1, "address": "192.0.2.10"})])

    backend = V3Client(api_key="secret", base_url="https://api.test", session=session).create_vpc_backend(
        7, 3, "192.0.2.10", name="h1"
    )

    assert backend.backend_host_id == 1
    assert session.calls[0]["kwargs"]["json"] == {"address": "192.0.2.10", "name": "h1"}


def test_list_vpc_backends_decodes_wrapper_not_bare_array() -> None:
    session = RecordedSession(
        [response({"backendHosts": [{"backendHostId": 1, "address": "192.0.2.10"}]})]
    )

    backends = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_backends(
        7, 3
    )

    assert [b.backend_host_id for b in backends] == [1]


def test_list_vpc_backends_rejects_bare_array() -> None:
    session = RecordedSession([response([{"backendHostId": 1}])])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_backends(7, 3)


def test_replace_vpc_backends_decodes_wrapper() -> None:
    session = RecordedSession(
        [response({"backendHosts": [{"backendHostId": 2, "address": "192.0.2.11"}]})]
    )

    backends = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).replace_vpc_backends(7, 3, [{"address": "192.0.2.11"}])

    assert [b.backend_host_id for b in backends] == [2]
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {"backendHosts": [{"address": "192.0.2.11"}]}


def test_get_vpc_backend_returns_matching_backend() -> None:
    session = RecordedSession(
        [response({"backendHosts": [{"backendHostId": 1}, {"backendHostId": 2}]})]
    )

    backend = V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_backend(
        7, 3, 2
    )

    assert backend.backend_host_id == 2


def test_get_vpc_backend_raises_not_found_when_absent() -> None:
    session = RecordedSession([response({"backendHosts": [{"backendHostId": 1}]})])

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_backend(7, 3, 99)


def test_update_vpc_backend_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"backendHostId": 1, "name": "renamed"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc_backend(
        7, 3, 1, name="renamed"
    )

    assert session.calls[0]["kwargs"]["json"] == {"name": "renamed"}


def test_delete_vpc_backend_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_backend(7, 3, 1)

    assert session.calls[0]["method"] == "DELETE"


def test_update_vpc_ssh_settings_sends_port() -> None:
    session = RecordedSession([response({"port": 2222, "enabled": True})])

    settings = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).update_vpc_ssh_settings(7, port=2222)

    assert settings.port == 2222
    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/vpcs/7/ssh" in call["url"]
    assert call["kwargs"]["json"] == {"port": 2222}


def test_list_vpc_ssh_keys_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "laptop"}])])

    keys = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_ssh_keys(7)

    assert [key.id for key in keys] == [1]
    assert "/vpcs/7/ssh/keys" in session.calls[0]["url"]


def test_get_vpc_ssh_key_matches_id_or_ssh_key_id() -> None:
    session = RecordedSession([response([{"id": 0, "sshKeyId": 5, "name": "fallback"}])])

    key = V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_ssh_key(7, 5)

    assert key.ssh_key_id == 5


def test_get_vpc_ssh_key_raises_not_found_when_absent() -> None:
    session = RecordedSession([response([{"id": 1}])])

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_ssh_key(7, 99)


def test_enable_vpc_ssh_key_sends_enabled_flag() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).enable_vpc_ssh_key(7, 5, True)

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/vpcs/7/ssh/keys/5" in call["url"]
    assert call["kwargs"]["json"] == {"enabled": True}


def test_delete_vpc_ssh_key_disables_key() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_ssh_key(7, 5)

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"enabled": False}


def test_create_vpc_floating_ip_returns_id() -> None:
    session = RecordedSession([response({"floatingIpId": 9})])

    floating_ip_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_vpc_floating_ip(7, ip_version=4, ptr="host.example.com")

    assert floating_ip_id == 9
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/floating-ips" in call["url"]
    assert call["kwargs"]["json"] == {"ipVersion": 4, "ptr": "host.example.com"}


def test_list_vpc_floating_ips_decodes_rows() -> None:
    session = RecordedSession([response([{"floatingIpId": 9, "address": "203.0.113.5"}])])

    fips = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_vpc_floating_ips(7)

    assert [fip.floating_ip_id for fip in fips] == [9]


def test_get_vpc_floating_ip_raises_not_found_when_absent() -> None:
    session = RecordedSession([response([{"floatingIpId": 1}])])

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_floating_ip(7, 99)


def test_update_vpc_floating_ip_sends_ptr() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc_floating_ip(
        7, 9, "new.example.com"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/vpcs/7/floating-ips/9" in call["url"]
    assert call["kwargs"]["json"] == {"ptr": "new.example.com"}


def test_delete_vpc_floating_ip_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_floating_ip(7, 9)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/vpcs/7/floating-ips/9" in call["url"]


def test_create_vpc_firewall_rule_returns_id() -> None:
    session = RecordedSession([response({"firewallRuleId": 4})])

    rule_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_vpc_firewall_rule(7, ip_version=4, direction="inbound", protocol="tcp")

    assert rule_id == 4
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/gateway/rules/firewall" in call["url"]
    assert call["kwargs"]["json"] == {"ipVersion": 4, "direction": "inbound", "protocol": "tcp"}


def test_list_vpc_firewall_rules_all_builds_path() -> None:
    session = RecordedSession([response([{"firewallRuleId": 4}])])

    rules = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_vpc_firewall_rules_all(7)

    assert [rule.firewall_rule_id for rule in rules] == [4]
    assert "/vpcs/7/gateway/rules/firewall" in session.calls[0]["url"]
    assert "ipv" not in session.calls[0]["url"].split("firewall", 1)[1].split("?")[0]


def test_list_vpc_firewall_rules_builds_ip_version_path() -> None:
    session = RecordedSession([response([{"firewallRuleId": 4}])])

    V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_firewall_rules(7, 6)

    assert "/vpcs/7/gateway/rules/firewall/ipv6" in session.calls[0]["url"]


def test_get_vpc_firewall_rule_raises_not_found_when_absent() -> None:
    session = RecordedSession([response([{"firewallRuleId": 1}])])

    with pytest.raises(NotFoundError):
        V3Client(
            api_key="secret", base_url="https://api.test", session=session
        ).get_vpc_firewall_rule(7, 99, 4)


def test_update_vpc_firewall_rule_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"firewallRuleId": 4, "direction": "outbound"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc_firewall_rule(
        7, 4, direction="outbound"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"direction": "outbound"}


def test_delete_vpc_firewall_rule_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_firewall_rule(7, 4)

    assert session.calls[0]["method"] == "DELETE"
    assert "/vpcs/7/gateway/rules/firewall/4" in session.calls[0]["url"]


def test_apply_vpc_firewall_changes_posts_apply_changes() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).apply_vpc_firewall_changes(7)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/gateway/rules/firewall/apply-changes" in call["url"]


def test_create_vpc_snat_rule_sends_json_body() -> None:
    session = RecordedSession([response({"snatRuleId": 5, "ipVersion": 4})])

    rule = V3Client(api_key="secret", base_url="https://api.test", session=session).create_vpc_snat_rule(
        7, ip_version=4, match={"internalCidr": "10.0.0.0/24"}
    )

    assert rule.snat_rule_id == 5
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/gateway/rules/snat" in call["url"]
    assert call["kwargs"]["json"] == {"ipVersion": 4, "match": {"internalCidr": "10.0.0.0/24"}}


def test_list_vpc_snat_rules_builds_ip_version_path() -> None:
    session = RecordedSession([response([{"snatRuleId": 5}])])

    rules = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_snat_rules(
        7, 4
    )

    assert [rule.snat_rule_id for rule in rules] == [5]
    assert "/vpcs/7/gateway/rules/snat/ipv4" in session.calls[0]["url"]


def test_get_vpc_snat_rule_raises_not_found_when_absent() -> None:
    session = RecordedSession([response([{"snatRuleId": 1}])])

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_snat_rule(
            7, 99, 4
        )


def test_update_vpc_snat_rule_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"snatRuleId": 5, "description": "updated"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc_snat_rule(
        7, 5, description="updated"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"description": "updated"}


def test_delete_vpc_snat_rule_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_snat_rule(7, 5)

    assert session.calls[0]["method"] == "DELETE"
    assert "/vpcs/7/gateway/rules/snat/5" in session.calls[0]["url"]


def test_apply_vpc_snat_changes_posts_apply_changes() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).apply_vpc_snat_changes(7)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/gateway/rules/snat/apply-changes" in call["url"]


def test_create_vpc_dnat_rule_requires_translation() -> None:
    session = RecordedSession([response({"dnatRuleId": 6, "ipVersion": 4})])

    rule = V3Client(api_key="secret", base_url="https://api.test", session=session).create_vpc_dnat_rule(
        7, ip_version=4, translation={"address": "192.0.2.20"}
    )

    assert rule.dnat_rule_id == 6
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/gateway/rules/dnat" in call["url"]
    assert call["kwargs"]["json"] == {"ipVersion": 4, "translation": {"address": "192.0.2.20"}}


def test_list_vpc_dnat_rules_builds_ip_version_path() -> None:
    session = RecordedSession([response([{"dnatRuleId": 6}])])

    rules = V3Client(api_key="secret", base_url="https://api.test", session=session).list_vpc_dnat_rules(
        7, 4
    )

    assert [rule.dnat_rule_id for rule in rules] == [6]
    assert "/vpcs/7/gateway/rules/dnat/ipv4" in session.calls[0]["url"]


def test_get_vpc_dnat_rule_raises_not_found_when_absent() -> None:
    session = RecordedSession([response([{"dnatRuleId": 1}])])

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_vpc_dnat_rule(
            7, 99, 4
        )


def test_update_vpc_dnat_rule_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"dnatRuleId": 6, "description": "updated"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_vpc_dnat_rule(
        7, 6, description="updated"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"description": "updated"}


def test_delete_vpc_dnat_rule_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_vpc_dnat_rule(7, 6)

    assert session.calls[0]["method"] == "DELETE"
    assert "/vpcs/7/gateway/rules/dnat/6" in session.calls[0]["url"]


def test_apply_vpc_dnat_changes_posts_apply_changes() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).apply_vpc_dnat_changes(7)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/vpcs/7/gateway/rules/dnat/apply-changes" in call["url"]


def test_list_storage_types_decodes_bare_array() -> None:
    session = RecordedSession([response([{"type": "block", "name": "Block"}])])

    types = V3Client(api_key="secret", base_url="https://api.test", session=session).list_storage_types()

    assert [t.type for t in types] == ["block"]


def test_list_storage_types_decodes_data_envelope() -> None:
    session = RecordedSession([response({"data": [{"type": "object", "name": "Object"}]})])

    types = V3Client(api_key="secret", base_url="https://api.test", session=session).list_storage_types()

    assert [t.type for t in types] == ["object"]


def test_list_storage_types_falls_back_to_type_code_keys() -> None:
    session = RecordedSession(
        [response({"block": {"name": "Block"}, "object": {"name": "Object"}, "meta": {"total": 2}})]
    )

    types = V3Client(api_key="secret", base_url="https://api.test", session=session).list_storage_types()

    assert [t.type for t in types] == ["block", "object"]
    assert [t.name for t in types] == ["Block", "Object"]


def test_create_storage_bucket_returns_bucket_id() -> None:
    session = RecordedSession([response({"bucketId": 10, "details": {"queued": True}})])

    bucket_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_storage_bucket(1, "assets", capacity=100, private=True)

    assert bucket_id == 10
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/storage/buckets" in call["url"]
    assert call["kwargs"]["json"] == {
        "locationId": 1,
        "label": "assets",
        "capacity": 100,
        "private": True,
    }


def test_list_storage_buckets_decodes_rows() -> None:
    session = RecordedSession([response([{"bucketId": 10, "label": "assets"}])])

    buckets = V3Client(api_key="secret", base_url="https://api.test", session=session).list_storage_buckets()

    assert [b.bucket_id for b in buckets] == [10]


def test_get_storage_bucket_raises_not_found() -> None:
    session = RecordedSession([response({"message": "not found"}, code=404)])

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_storage_bucket(99)


def test_update_storage_bucket_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"bucketId": 10, "label": "renamed"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_storage_bucket(
        10, label="renamed"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/storage/buckets/10" in call["url"]
    assert call["kwargs"]["json"] == {"label": "renamed"}


def test_delete_storage_bucket_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_storage_bucket(10)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/storage/buckets/10" in call["url"]


def test_convert_storage_bucket_to_store_returns_object_store_id() -> None:
    session = RecordedSession([response({"objectStoreId": 22})])

    object_store_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).convert_storage_bucket_to_store(10)

    assert object_store_id == 22
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/storage/buckets/10/convert-to-store" in call["url"]


def test_wait_for_storage_bucket_ready_returns_once_ready() -> None:
    session = RecordedSession([response({"bucketId": 10, "label": "assets", "ready": True})])

    bucket = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).wait_for_storage_bucket_ready(10)

    assert bucket.metadata["ready"] is True
    assert len(session.calls) == 1


def test_wait_for_storage_bucket_ready_times_out() -> None:
    session = RecordedSession([response({"bucketId": 10, "label": "assets", "ready": False})])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).wait_for_storage_bucket_ready(
            10, timeout=0
        )


def test_create_storage_object_store_returns_object_store_id() -> None:
    session = RecordedSession([response({"objectStoreId": 5})])

    object_store_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_storage_object_store(1, "media")

    assert object_store_id == 5
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/storage/object-stores" in call["url"]
    assert call["kwargs"]["json"] == {"locationId": 1, "label": "media"}


def test_list_storage_object_stores_decodes_rows() -> None:
    session = RecordedSession([response([{"objectStoreId": 5, "label": "media"}])])

    stores = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_storage_object_stores()

    assert [s.object_store_id for s in stores] == [5]


def test_get_storage_object_store_builds_path() -> None:
    session = RecordedSession([response({"objectStoreId": 5, "label": "media"})])

    store = V3Client(api_key="secret", base_url="https://api.test", session=session).get_storage_object_store(5)

    assert store.object_store_id == 5
    assert "/storage/object-stores/5" in session.calls[0]["url"]


def test_update_storage_object_store_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"objectStoreId": 5, "capacity": 200})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_storage_object_store(
        5, capacity=200
    )

    assert session.calls[0]["kwargs"]["json"] == {"capacity": 200}


def test_delete_storage_object_store_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_storage_object_store(5)

    assert session.calls[0]["method"] == "DELETE"
    assert "/storage/object-stores/5" in session.calls[0]["url"]


def test_wait_for_storage_object_store_ready_returns_once_ready() -> None:
    session = RecordedSession([response({"objectStoreId": 5, "ready": True})])

    store = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).wait_for_storage_object_store_ready(5)

    assert store.metadata["ready"] is True


def test_create_storage_block_namespace_returns_namespace_id() -> None:
    session = RecordedSession([response({"blockNamespaceId": 3})])

    namespace_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_storage_block_namespace(1, "team")

    assert namespace_id == 3
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/storage/block-namespaces" in call["url"]


def test_list_storage_block_namespaces_decodes_rows() -> None:
    session = RecordedSession([response([{"blockNamespaceId": 3, "label": "team"}])])

    namespaces = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_storage_block_namespaces()

    assert [n.block_namespace_id for n in namespaces] == [3]


def test_get_storage_block_namespace_builds_path() -> None:
    session = RecordedSession([response({"blockNamespaceId": 3, "label": "team"})])

    namespace = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).get_storage_block_namespace(3)

    assert namespace.block_namespace_id == 3
    assert "/storage/block-namespaces/3" in session.calls[0]["url"]


def test_update_storage_block_namespace_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"blockNamespaceId": 3, "label": "renamed"})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_storage_block_namespace(
        3, label="renamed"
    )

    assert session.calls[0]["kwargs"]["json"] == {"label": "renamed"}


def test_delete_storage_block_namespace_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_storage_block_namespace(3)

    assert session.calls[0]["method"] == "DELETE"
    assert "/storage/block-namespaces/3" in session.calls[0]["url"]


def test_wait_for_storage_block_namespace_ready_returns_once_ready() -> None:
    session = RecordedSession([response({"blockNamespaceId": 3, "ready": True})])

    namespace = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).wait_for_storage_block_namespace_ready(3)

    assert namespace.metadata["ready"] is True


def test_create_storage_block_volume_returns_volume_id() -> None:
    session = RecordedSession([response({"blockVolumeId": 7})])

    volume_id = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_storage_block_volume(1, "data", capacity=50)

    assert volume_id == 7
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/storage/block-volumes" in call["url"]
    assert call["kwargs"]["json"] == {"locationId": 1, "label": "data", "capacity": 50}


def test_list_storage_block_volumes_decodes_rows() -> None:
    session = RecordedSession([response([{"blockVolumeId": 7, "label": "data"}])])

    volumes = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_storage_block_volumes()

    assert [v.block_volume_id for v in volumes] == [7]
    assert session.calls[0]["url"].split("?")[0].endswith("/storage/block-volumes")


def test_get_storage_block_volume_fills_in_missing_id() -> None:
    """PLATFORM DEFECT: the single-volume get answers with object-store shaped
    metadata that carries no blockVolumeId. The id requested is filled back
    in rather than surfacing a volume with id zero."""
    session = RecordedSession([response({"label": "data", "ready": True})])

    volume = V3Client(api_key="secret", base_url="https://api.test", session=session).get_storage_block_volume(7)

    assert volume.block_volume_id == 7


def test_get_storage_block_volume_keeps_decoded_id_when_present() -> None:
    session = RecordedSession([response({"blockVolumeId": 7, "label": "data"})])

    volume = V3Client(api_key="secret", base_url="https://api.test", session=session).get_storage_block_volume(7)

    assert volume.block_volume_id == 7


def test_update_storage_block_volume_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"blockVolumeId": 7, "capacity": 100})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_storage_block_volume(
        7, capacity=100
    )

    assert session.calls[0]["kwargs"]["json"] == {"capacity": 100}


def test_delete_storage_block_volume_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_storage_block_volume(7)

    assert session.calls[0]["method"] == "DELETE"
    assert "/storage/block-volumes/7" in session.calls[0]["url"]


def test_wait_for_storage_block_volume_ready_returns_once_ready() -> None:
    session = RecordedSession([response({"blockVolumeId": 7, "ready": True})])

    volume = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).wait_for_storage_block_volume_ready(7)

    assert volume.metadata["ready"] is True


def test_list_storage_locations_decodes_bare_array() -> None:
    session = RecordedSession(
        [response([{"location": {"id": 1, "name": "atl"}, "hardware": {"id": 2, "name": "nvme"}}])]
    )

    locations = V3Client(api_key="secret", base_url="https://api.test", session=session).list_storage_locations()

    assert locations[0].location["name"] == "atl"
    assert locations[0].hardware["name"] == "nvme"


def test_list_firewall_external_ip_sets_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "office", "description": "office net"}])])

    sets = Client(api_key="secret", base_url="https://api.test/", session=session).list_firewall_external_ip_sets()

    assert [s.id for s in sets] == [1]
    assert sets[0].name == "office"


def test_get_firewall_external_ip_set_builds_path() -> None:
    session = RecordedSession([response({"id": 3, "name": "vpn"})])

    ip_set = Client(
        api_key="secret", base_url="https://api.test/", session=session
    ).get_firewall_external_ip_set(3)

    assert ip_set.id == 3
    assert "firewall/external-ipsets/3" in session.calls[0]["url"]


def test_get_firewall_manage_enabled_decodes_flag() -> None:
    session = RecordedSession([response({"enabled": "1"})])

    result = Client(api_key="secret", base_url="https://api.test/", session=session).get_firewall_manage_enabled()

    assert result.enabled is True
    assert "firewall/manage/enabled" in session.calls[0]["url"]


def test_list_firewall_sets_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"id": 1, "name": "default", "description": "", "enabled": 1, "is_draft": 0}])]
    )

    sets = Client(api_key="secret", base_url="https://api.test/", session=session).list_firewall_sets()

    assert [s.id for s in sets] == [1]
    assert sets[0].enabled is True
    assert sets[0].is_draft is False


def test_get_firewall_set_builds_path() -> None:
    session = RecordedSession([response({"id": 5, "name": "default", "enabled": True, "is_draft": False})])

    firewall_set = Client(api_key="secret", base_url="https://api.test/", session=session).get_firewall_set(5)

    assert firewall_set.id == 5
    assert "firewall/sets/5" in session.calls[0]["url"]


def test_create_firewall_set_sends_form_encoded_body() -> None:
    session = RecordedSession([response({"id": 1, "name": "default", "enabled": True, "is_draft": False})])

    Client(api_key="secret", base_url="https://api.test/", session=session).create_firewall_set(
        "default", "a set", enabled=True
    )

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets" in call["url"]
    assert call["kwargs"]["data"] == {"name": "default", "description": "a set", "enabled": "1"}


def test_update_firewall_set_sends_form_encoded_body() -> None:
    session = RecordedSession([response({"id": 1, "name": "renamed", "enabled": False, "is_draft": False})])

    Client(api_key="secret", base_url="https://api.test/", session=session).update_firewall_set(
        1, "renamed", "still a set", enabled=False
    )

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "firewall/sets/1" in call["url"]
    assert call["kwargs"]["data"] == {"name": "renamed", "description": "still a set", "enabled": "0"}


def test_delete_firewall_set_calls_delete() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_firewall_set(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "firewall/sets/1" in session.calls[0]["url"]


def test_enable_firewall_set_puts_without_meaningful_body() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).enable_firewall_set(1)

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "firewall/sets/1/enable" in call["url"]
    assert call["kwargs"]["data"] == {}


def test_disable_firewall_set_puts_without_meaningful_body() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).disable_firewall_set(1)

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "firewall/sets/1/disable" in call["url"]


def test_create_draft_firewall_set_posts_without_meaningful_body() -> None:
    session = RecordedSession([response({"id": 2, "draft_firewall_set_id": None})])

    draft = Client(api_key="secret", base_url="https://api.test/", session=session).create_draft_firewall_set(1)

    assert draft.id == 2
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/create-draft" in call["url"]
    assert call["kwargs"]["data"] == {}


def test_publish_draft_firewall_set_builds_path() -> None:
    session = RecordedSession([response({"id": 1, "draft_firewall_set_id": None})])

    published = Client(
        api_key="secret", base_url="https://api.test/", session=session
    ).publish_draft_firewall_set(2)

    assert published.id == 1
    assert "firewall/sets/publish-draft/2" in session.calls[0]["url"]


def test_delete_draft_firewall_set_calls_delete() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_draft_firewall_set(2)

    assert session.calls[0]["method"] == "DELETE"
    assert "firewall/sets/delete-draft/2" in session.calls[0]["url"]


def test_sync_firewall_set_rules_posts_without_meaningful_body() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).sync_firewall_set_rules(1)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/vm/sync-all" in call["url"]


def _firewall_rule_payload(rule_id: int = 1, **overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "id": rule_id,
        "firewall_set_id": 1,
        "ip_version": "ipv4",
        "direction": "inbound",
        "action": "accept",
        "enabled": True,
        "match_criteria": None,
        "admin_comment": "",
        "rule_priority": 10,
    }
    payload.update(overrides)
    return payload


def test_list_firewall_rules_builds_path() -> None:
    session = RecordedSession([response([_firewall_rule_payload(1)])])

    rules = Client(api_key="secret", base_url="https://api.test/", session=session).list_firewall_rules(1)

    assert [rule.id for rule in rules] == [1]
    assert "firewall/sets/1/rules" in session.calls[0]["url"]


def test_reorder_firewall_rules_sends_only_provided_ids() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).reorder_firewall_rules(
        1, move_id=5, after_id=3
    )

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/rules/re-order" in call["url"]
    assert call["kwargs"]["json"] == {"move_id": 5, "after_id": 3}


def test_get_firewall_rule_builds_path() -> None:
    session = RecordedSession([response(_firewall_rule_payload(4))])

    rule = Client(api_key="secret", base_url="https://api.test/", session=session).get_firewall_rule(1, 4)

    assert rule.id == 4
    assert "firewall/sets/1/rules/4" in session.calls[0]["url"]


def test_create_firewall_rule_sends_json_body_with_null_match_criteria() -> None:
    session = RecordedSession([response(_firewall_rule_payload(1))])

    Client(api_key="secret", base_url="https://api.test/", session=session).create_firewall_rule(
        1, ip_version="ipv4", action="accept", enabled=True
    )

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/rules" in call["url"]
    assert call["kwargs"]["json"] == {
        "ip_version": "ipv4",
        "action": "accept",
        "enabled": True,
        "match_criteria": None,
    }


def test_create_firewall_rule_includes_all_optional_fields_when_given() -> None:
    session = RecordedSession([response(_firewall_rule_payload(1))])

    Client(api_key="secret", base_url="https://api.test/", session=session).create_firewall_rule(
        1,
        ip_version="ipv4",
        action="accept",
        enabled=False,
        direction="outbound",
        rule_priority=7,
        admin_comment="allow office",
        match_criteria={"protocol": "tcp"},
    )

    call = session.calls[0]
    assert call["kwargs"]["json"] == {
        "ip_version": "ipv4",
        "action": "accept",
        "enabled": False,
        "match_criteria": {"protocol": "tcp"},
        "direction": "outbound",
        "rule_priority": 7,
        "admin_comment": "allow office",
    }


def test_update_firewall_rule_puts_to_flat_path() -> None:
    session = RecordedSession([response(_firewall_rule_payload(4))])

    rule = Client(api_key="secret", base_url="https://api.test/", session=session).update_firewall_rule(
        1, 4, ip_version="ipv4", action="drop", enabled=True
    )

    assert rule.id == 4
    call = session.calls[0]
    assert call["method"] == "PUT"
    # gona's UpdateFirewallRule targets "firewall/{setID}/{ruleID}", not the
    # "firewall/sets/{setID}/rules/{ruleID}" shape used by get and create.
    assert "firewall/1/4" in call["url"]
    assert "firewall/sets" not in call["url"]


def test_delete_firewall_rule_calls_delete_on_flat_path() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).delete_firewall_rule(1, 4)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    # gona's DeleteFirewallRule targets "firewall/{setID}/rules/{ruleID}",
    # not the "firewall/sets/{setID}/rules/{ruleID}" shape used by get.
    assert "firewall/1/rules/4" in call["url"]
    assert "firewall/sets" not in call["url"]


def _firewall_set_vm_payload(vm_id: int = 1, **overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "id": vm_id,
        "mbpkgid": 100,
        "interface_id": 1,
        "firewall_set_id": 1,
        "set_priority": 0,
        "iata_code": "nyc",
        "location": "New York",
        "hostname": "host.example.com",
    }
    payload.update(overrides)
    return payload


def test_list_firewall_set_vms_builds_path() -> None:
    session = RecordedSession([response([_firewall_set_vm_payload(1)])])

    vms = Client(api_key="secret", base_url="https://api.test/", session=session).list_firewall_set_vms(1)

    assert [vm.id for vm in vms] == [1]
    assert "firewall/sets/1/vm-list" in session.calls[0]["url"]


def test_list_firewall_set_available_vms_builds_query_string() -> None:
    session = RecordedSession([response([_firewall_set_vm_payload(1)])])

    Client(api_key="secret", base_url="https://api.test/", session=session).list_firewall_set_available_vms(
        1,
        extref_account_id=42,
        vpc_id=9,
        include_bandwidth=True,
        include_ul=False,
        check_vpc=True,
        disable_interface_id_filter=False,
    )

    parsed = urlsplit(session.calls[0]["url"])
    query = parse_qs(parsed.query)
    assert query["extref_acct_id"] == ["42"]
    assert query["vpc_id"] == ["9"]
    assert query["bw"] == ["1"]
    assert query["ul"] == ["0"]
    assert query["check_vpc"] == ["1"]
    assert query["disable_interface_id_filter"] == ["0"]


def test_list_firewall_set_related_vms_omits_query_when_no_flags() -> None:
    session = RecordedSession([response([_firewall_set_vm_payload(1)])])

    vms = Client(api_key="secret", base_url="https://api.test/", session=session).list_firewall_set_related_vms(100)

    assert [vm.id for vm in vms] == [1]
    call_path = session.calls[0]["url"]
    assert "firewall/sets/vm/100/related" in call_path
    assert set(parse_qs(urlsplit(call_path).query).keys()) == {"key"}


def test_attach_firewall_set_vm_sends_vm_list_body() -> None:
    session = RecordedSession([response([_firewall_set_vm_payload(1)])])

    vms = Client(api_key="secret", base_url="https://api.test/", session=session).attach_firewall_set_vm(
        1, 100, 2, 3
    )

    assert [vm.id for vm in vms] == [1]
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/vm/attach" in call["url"]
    assert call["kwargs"]["json"] == {
        "vm_list": [{"mbpkgid": 100, "interface_id": 2, "set_priority": 3}]
    }


def test_detach_firewall_set_vm_posts_without_meaningful_body() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).detach_firewall_set_vm(1, 100)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/vm/detach/100" in call["url"]


def test_detach_firewall_set_vm_relation_posts_without_meaningful_body() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).detach_firewall_set_vm_relation(55)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/vm/detach/55" in call["url"]


def test_detach_all_firewall_set_vms_posts_without_meaningful_body() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).detach_all_firewall_set_vms(1)

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "firewall/sets/1/vm/detach-all" in call["url"]


def _vlan_payload(vlan_id: int) -> Dict[str, Any]:
    return {
        "id": vlan_id,
        "mbid": 100,
        "private": 1,
        "allow_sriov": 0,
        "display_name": "vlan-a",
        "description": "test vlan",
        "last_updated": "2026-01-01",
        "created": "2026-01-01",
        "provisioned_locations": [
            {"provisioned": True, "name": "loc-a", "location_id": 5, "flag": "us", "iata_code": "IAD"}
        ],
    }


def test_list_vlans_decodes_rows() -> None:
    session = RecordedSession([response([_vlan_payload(1)])])

    vlans = Client(api_key="secret", base_url="https://api.test/", session=session).list_vlans()

    assert [vlan.id for vlan in vlans] == [1]
    assert vlans[0].provisioned_locations[0].location_id == 5
    assert "cloud/networking/vlans" in session.calls[0]["url"]


def test_get_customer_vlan_calls_expected_path() -> None:
    session = RecordedSession([response(_vlan_payload(9))])

    vlan = Client(api_key="secret", base_url="https://api.test/", session=session).get_customer_vlan(9)

    assert vlan.id == 9
    assert "cloud/networking/vlans/9" in session.calls[0]["url"]


def test_list_customer_vlans_at_location_calls_expected_path() -> None:
    session = RecordedSession([response([_vlan_payload(3)])])

    vlans = Client(
        api_key="secret", base_url="https://api.test/", session=session
    ).list_customer_vlans_at_location(5)

    assert [vlan.id for vlan in vlans] == [3]
    assert "cloud/networking/locations/5/vlans" in session.calls[0]["url"]


def _server_nic_payload(nic_id: int) -> Dict[str, Any]:
    return {"nic_id": nic_id, "mbpkgid": 100, "customer_vlan_id": 9, "attach_order": 1}


def test_list_server_nics_decodes_rows() -> None:
    session = RecordedSession([response([_server_nic_payload(1)])])

    nics = Client(api_key="secret", base_url="https://api.test/", session=session).list_server_nics(100)

    assert [nic.nic_id for nic in nics] == [1]
    assert "cloud/networking/nics/100" in session.calls[0]["url"]


def test_attach_server_nic_decodes_object_response() -> None:
    session = RecordedSession([response(_server_nic_payload(2))])

    nic = Client(api_key="secret", base_url="https://api.test/", session=session).attach_server_nic(100, 9)

    assert nic.nic_id == 2
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {"customer_vlan_id": 9}


def test_attach_server_nic_decodes_single_element_list_response() -> None:
    session = RecordedSession([response([_server_nic_payload(3)])])

    nic = Client(api_key="secret", base_url="https://api.test/", session=session).attach_server_nic(100, 9)

    assert nic.nic_id == 3


def test_update_server_nic_sends_expected_body() -> None:
    session = RecordedSession([response(_server_nic_payload(2))])

    nic = Client(api_key="secret", base_url="https://api.test/", session=session).update_server_nic(
        2, 100, 9, 1
    )

    assert nic.nic_id == 2
    call = session.calls[0]
    assert call["method"] == "PUT"
    assert call["kwargs"]["json"] == {"mbpkgid": 100, "customer_vlan_id": 9, "attach_order": 1}


def test_detach_server_nic_sends_mbpkgid_query_param() -> None:
    session = RecordedSession([response(None)])

    Client(api_key="secret", base_url="https://api.test/", session=session).detach_server_nic(100, 2)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    parsed = urlsplit(call["url"])
    assert parsed.path.endswith("cloud/networking/nics/2")
    assert parse_qs(parsed.query)["mbpkgid"] == ["100"]


def test_list_cloud_floating_ipv4_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"floatingIpv4Id": 1, "address": "203.0.113.1", "AssignedOn": "2026-01-01"}])]
    )

    fips = V3Client(api_key="secret", base_url="https://api.test", session=session).list_cloud_floating_ipv4()

    assert [fip.floating_ipv4_id for fip in fips] == [1]
    assert fips[0].assigned_on == "2026-01-01"


def test_create_cloud_floating_ipv4_sends_optional_fields() -> None:
    session = RecordedSession([response({"floatingIpv4Id": 4, "address": "203.0.113.4"})])

    fip = V3Client(api_key="secret", base_url="https://api.test", session=session).create_cloud_floating_ipv4(
        ptr_domain="host.example.com", vlan_id=9
    )

    assert fip.floating_ipv4_id == 4
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {"ptrDomain": "host.example.com", "vlanId": 9}


def test_create_cloud_floating_ipv4_omits_unset_fields() -> None:
    session = RecordedSession([response({"floatingIpv4Id": 4})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).create_cloud_floating_ipv4()

    assert session.calls[0]["kwargs"]["json"] == {}


def test_delete_cloud_floating_ipv4_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_cloud_floating_ipv4(4)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/cloud/networking/floating-ips/ipv4/4" in call["url"]


def test_list_cloud_floating_ipv4_vms_decodes_rows() -> None:
    session = RecordedSession([response([{"mbpkgid": 100, "fqdn": "vm.example", "ip": "10.0.0.1"}])])

    vms = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_cloud_floating_ipv4_vms(4)

    assert [vm.mbpkgid for vm in vms] == [100]


def test_grant_cloud_floating_ipv4_vms_sends_body() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).grant_cloud_floating_ipv4_vms(
        4, [100, 200], revoke_existing=True
    )

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/cloud/networking/floating-ips/ipv4/4/vms/mass-grant" in call["url"]
    assert call["kwargs"]["json"] == {
        "vms": [{"mbpkgid": 100}, {"mbpkgid": 200}],
        "revokeExisting": True,
    }


def test_revoke_cloud_floating_ipv4_vms_sends_body() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).revoke_cloud_floating_ipv4_vms(
        4, [100]
    )

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/cloud/networking/floating-ips/ipv4/4/vms/mass-revoke" in call["url"]
    assert call["kwargs"]["json"] == {"vms": [{"mbpkgid": 100}]}


def test_list_cloud_networking_locations_decodes_bare_list() -> None:
    session = RecordedSession([response([{"locationId": 1, "datacenterId": 2}])])

    locations = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_cloud_networking_locations()

    assert [(loc.location_id, loc.datacenter_id) for loc in locations] == [(1, 2)]


def _oidc_client_row(client_id: int, **overrides: Any) -> Dict[str, Any]:
    row = {
        "clientId": client_id,
        "createdOn": "2026-01-01",
        "lastUsedOn": None,
        "label": "list-label",
        "description": "list-description",
        "jwksUri": "https://list.example/jwks",
        "accountDefault": False,
        "defaultAudience": "aud",
        "ttl": 300,
        "enforceAllowList": True,
    }
    row.update(overrides)
    return row


def test_create_oidc_client_returns_id() -> None:
    session = RecordedSession([response({"clientId": 7})])

    client_id = V3Client(api_key="secret", base_url="https://api.test", session=session).create_oidc_client(
        label="my client", account_default=True, enforce_allow_list=True
    )

    assert client_id == 7
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {
        "accountDefault": True,
        "enforceAllowList": True,
        "label": "my client",
    }


def test_list_oidc_clients_attaches_tenant_and_paginates() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "tenant": "42",
                    "clients": {
                        "data": [_oidc_client_row(1)],
                        "meta": {"limit": 1, "offset": 0, "total": 2},
                    },
                }
            ),
            response(
                {
                    "tenant": "42",
                    "clients": {
                        "data": [_oidc_client_row(2)],
                        "meta": {"limit": 1, "offset": 1, "total": 2},
                    },
                }
            ),
        ]
    )

    clients = V3Client(api_key="secret", base_url="https://api.test", session=session).list_oidc_clients()

    assert [client.client_id for client in clients] == [1, 2]
    assert all(client.tenant == "42" for client in clients)
    assert "offset=1" in session.calls[1]["url"]


def test_get_oidc_client_merges_detail_keys_and_logs() -> None:
    detail = {
        "metadata": {
            "createdOn": "2026-02-01",
            "lastUsedOn": "2026-02-02",
            "label": "detail-label",
            "description": "detail-description",
            "jwksUri": "https://detail.example/jwks",
        },
        "keys": {"data": [{"keyId": 1, "label": "k1", "publicKey": "PK"}], "meta": {}},
        "logs": {
            "auth": {"data": [{"id": 5, "issuedOn": "t1", "expiresOn": "t2", "jti": "abc"}], "meta": {}},
            "changes": {"data": [{"keyId": 1, "recordedOn": "t3", "type": "created"}], "meta": {}},
        },
    }
    session = RecordedSession(
        [
            response(detail),
            response({"tenant": "42", "clients": {"data": [_oidc_client_row(7)], "meta": {}}}),
        ]
    )

    client = V3Client(api_key="secret", base_url="https://api.test", session=session).get_oidc_client(7)

    assert client.client_id == 7
    assert client.label == "detail-label"
    assert client.description == "detail-description"
    assert client.jwks_uri == "https://detail.example/jwks"
    assert [key.key_id for key in client.keys] == [1]
    assert [log.log_id for log in client.auth_logs] == [5]
    assert [log.key_id for log in client.change_logs] == [1]


def test_get_oidc_client_raises_not_found_when_absent_from_list() -> None:
    session = RecordedSession(
        [
            response({}),
            response({"tenant": "42", "clients": {"data": [_oidc_client_row(1)], "meta": {}}}),
        ]
    )

    with pytest.raises(NotFoundError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).get_oidc_client(99)


def test_update_oidc_client_sends_only_set_fields() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_oidc_client(
        7, label="new label", account_default=False
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"label": "new label", "accountDefault": False}


def test_delete_oidc_client_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_oidc_client(7)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/oidc/clients/7" in call["url"]


def test_create_oidc_client_keys_sends_key_list_and_decodes_response() -> None:
    session = RecordedSession([response({"keys": [{"keyId": 1, "publicKey": "PK"}]})])

    keys = V3Client(api_key="secret", base_url="https://api.test", session=session).create_oidc_client_keys(
        7, [{"public_key": "PK", "label": "k1"}]
    )

    assert [key.key_id for key in keys] == [1]
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["kwargs"]["json"] == {"keys": [{"publicKey": "PK", "label": "k1"}]}


def test_list_oidc_client_keys_decodes_rows() -> None:
    session = RecordedSession([response({"keys": {"data": [{"keyId": 1, "publicKey": "PK"}], "meta": {}}})])

    keys = V3Client(api_key="secret", base_url="https://api.test", session=session).list_oidc_client_keys(7)

    assert [key.key_id for key in keys] == [1]


def test_update_oidc_client_key_sends_body() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_oidc_client_key(
        7, 1, label="new label"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/oidc/clients/7/keys/1" in call["url"]
    assert call["kwargs"]["json"] == {"label": "new label"}


def test_delete_oidc_client_key_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_oidc_client_key(7, 1)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/oidc/clients/7/keys/1" in call["url"]


def test_delete_oidc_client_key_treats_already_revoked_as_idempotent_success() -> None:
    session = RecordedSession([response({"message": "The key is revoked"}, code=400, status=400)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_oidc_client_key(7, 1)


def test_delete_oidc_client_key_raises_on_other_errors() -> None:
    session = RecordedSession([response({"message": "internal error"}, code=500, status=500)])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).delete_oidc_client_key(7, 1)


def test_add_oidc_client_vms_sends_body() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).add_oidc_client_vms(7, [100, 200])

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/oidc/clients/7/allow-list/vms" in call["url"]
    assert call["kwargs"]["json"] == {"vms": [{"mbpkgid": 100}, {"mbpkgid": 200}]}


def test_add_oidc_client_bare_metal_servers_sends_body() -> None:
    session = RecordedSession([response(None)])

    V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).add_oidc_client_bare_metal_servers(7, [300])

    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/oidc/clients/7/allow-list/bare-metal" in call["url"]
    assert call["kwargs"]["json"] == {"servers": [{"mbpkgid": 300}]}


def test_remove_oidc_client_vm_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).remove_oidc_client_vm(7, 100)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/oidc/clients/7/allow-list/vms/100" in call["url"]


def test_remove_oidc_client_bare_metal_server_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).remove_oidc_client_bare_metal_server(7, 300)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/oidc/clients/7/allow-list/bare-metal/300" in call["url"]


def test_list_oidc_client_vms_decodes_object_and_bare_int_rows() -> None:
    session = RecordedSession([response({"vms": [{"mbpkgid": 100}, 200]})])

    vms = V3Client(api_key="secret", base_url="https://api.test", session=session).list_oidc_client_vms(7)

    assert [vm.mbpkgid for vm in vms] == [100, 200]


def test_list_oidc_client_bare_metal_servers_decodes_rows() -> None:
    session = RecordedSession([response({"servers": [{"mbpkgid": 300}]})])

    servers = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_oidc_client_bare_metal_servers(7)

    assert [server.mbpkgid for server in servers] == [300]


def test_list_oidc_client_auth_logs_decodes_rows() -> None:
    session = RecordedSession(
        [response({"logs": {"data": [{"id": 5, "issuedOn": "t1", "expiresOn": "t2", "jti": "abc"}], "meta": {}}})]
    )

    logs = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_oidc_client_auth_logs(7)

    assert [log.log_id for log in logs] == [5]


def test_list_oidc_client_change_logs_decodes_rows() -> None:
    session = RecordedSession(
        [response({"logs": {"data": [{"keyId": 1, "recordedOn": "t3", "type": "created"}], "meta": {}}})]
    )

    logs = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).list_oidc_client_change_logs(7)

    assert [log.key_id for log in logs] == [1]


def test_list_nke_versions_decodes_bare_array() -> None:
    session = RecordedSession([response(["1.29.0", "1.30.0"])])

    versions = V3Client(api_key="secret", base_url="https://api.test", session=session).list_nke_versions()

    assert versions == ["1.29.0", "1.30.0"]
    assert "/nke/versions" in session.calls[0]["url"]


def test_create_nke_cluster_sends_billing_and_optional_fields() -> None:
    session = RecordedSession([response({"clusterId": 50})])

    cluster_id = V3Client(api_key="secret", base_url="https://api.test", session=session).create_nke_cluster(
        "prod",
        "1.30.0",
        replicas=3,
        minimum_nodes=3,
        maximum_nodes=6,
        package_id=10,
        location_id=1,
        contract_id=99,
        do_autoscaling=True,
        kubernetes_dashboard=True,
        tag_ids=[1, 2],
    )

    assert cluster_id == 50
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/nke/clusters" in call["url"]
    assert call["kwargs"]["json"] == {
        "name": "prod",
        "version": "1.30.0",
        "replicas": 3,
        "minimumNodes": 3,
        "maximumNodes": 6,
        "doAutoscaling": True,
        "doDualStack": False,
        "billing": {"packageId": 10, "locationId": 1, "contractId": 99},
        "addonsToInstall": {"kubernetesDashboard": True},
        "tags": [{"tagId": 1}, {"tagId": 2}],
    }


def test_create_nke_cluster_omits_unset_optional_fields() -> None:
    session = RecordedSession([response({"clusterId": 51})])

    V3Client(api_key="secret", base_url="https://api.test", session=session).create_nke_cluster(
        "prod", "1.30.0", replicas=1, minimum_nodes=1, maximum_nodes=1, package_id=10, location_id=1
    )

    body = session.calls[0]["kwargs"]["json"]
    assert "contractId" not in body["billing"]
    assert "addonsToInstall" not in body
    assert "tags" not in body
    assert "networking" not in body


def test_update_nke_cluster_sends_only_provided_fields() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_nke_cluster(
        7, name="renamed"
    )

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/nke/clusters/7" in call["url"]
    assert call["kwargs"]["json"] == {"name": "renamed"}


def test_update_nke_cluster_nodes_sends_explicit_null_maximum() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).update_nke_cluster(
        7, minimum_nodes=2
    )

    assert session.calls[0]["kwargs"]["json"] == {"nodes": {"minimum": 2, "maximum": None}}


def test_delete_nke_cluster_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_nke_cluster(7)

    assert session.calls[0]["method"] == "DELETE"
    assert "/nke/clusters/7" in session.calls[0]["url"]


def test_generate_nke_kubeconfig_returns_decoded_string() -> None:
    session = RecordedSession([response("apiVersion: v1")])

    kubeconfig = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).generate_nke_kubeconfig(7, expiration_seconds=7200)

    assert kubeconfig == "apiVersion: v1"
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/nke/clusters/7/kubeconfig" in call["url"]
    assert call["kwargs"]["json"] == {"expirationSeconds": 7200}


def test_generate_nke_kubeconfig_falls_back_to_raw_data() -> None:
    session = RecordedSession([response({"unexpected": "shape"})])

    kubeconfig = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).generate_nke_kubeconfig(7)

    assert kubeconfig == "{'unexpected': 'shape'}"


def test_create_nke_access_urls_decodes_response() -> None:
    session = RecordedSession(
        [response({"api": "https://api.example", "prometheus": "https://prom.example"})]
    )

    urls = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).create_nke_access_urls(7)

    assert urls.api == "https://api.example"
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/nke/clusters/7/create-access-urls" in call["url"]
    assert call["kwargs"]["json"] is None


def test_list_nke_cluster_logs_decodes_rows() -> None:
    session = RecordedSession([response([{"recordedOn": "t1", "message": "cluster created"}])])

    logs = V3Client(api_key="secret", base_url="https://api.test", session=session).list_nke_cluster_logs(7)

    assert [log.message for log in logs] == ["cluster created"]
    assert "/nke/clusters/7/logs" in session.calls[0]["url"]


def test_list_nke_worker_nodes_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"workerNodeId": 1, "clusterId": 7, "name": "worker-1", "status": {"ready": True}}])]
    )

    nodes = V3Client(api_key="secret", base_url="https://api.test", session=session).list_nke_worker_nodes(7)

    assert [n.worker_node_id for n in nodes] == [1]
    assert nodes[0].ready is True
    assert "/nke/clusters/7/worker-nodes" in session.calls[0]["url"]


def test_get_nke_worker_node_builds_path() -> None:
    session = RecordedSession([response({"workerNodeId": 1, "name": "worker-1"})])

    node = V3Client(api_key="secret", base_url="https://api.test", session=session).get_nke_worker_node(7, 1)

    assert node.worker_node_id == 1
    assert "/nke/clusters/7/worker-nodes/1" in session.calls[0]["url"]


def test_update_nke_worker_node_sends_label_and_tags() -> None:
    session = RecordedSession([response({"workerNodeId": 1, "name": "renamed"})])

    node = V3Client(api_key="secret", base_url="https://api.test", session=session).update_nke_worker_node(
        7, 1, label="renamed", tag_ids=[5]
    )

    assert node.name == "renamed"
    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["kwargs"]["json"] == {"label": "renamed", "tags": [{"tagId": 5}]}


def test_delete_nke_worker_node_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_nke_worker_node(7, 1)

    assert session.calls[0]["method"] == "DELETE"
    assert "/nke/clusters/7/worker-nodes/1" in session.calls[0]["url"]


def test_wait_for_nke_worker_nodes_returns_once_minimum_reached() -> None:
    session = RecordedSession([response([{"workerNodeId": 1}, {"workerNodeId": 2}])])

    nodes = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).wait_for_nke_worker_nodes(7, 2)

    assert len(nodes) == 2
    assert len(session.calls) == 1


def test_wait_for_nke_worker_nodes_times_out() -> None:
    session = RecordedSession([response([{"workerNodeId": 1}])])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).wait_for_nke_worker_nodes(
            7, 2, timeout=0
        )


def test_wait_for_nke_cluster_healthy_returns_once_healthy() -> None:
    session = RecordedSession([response({"clusterId": 7, "status": {"cluster": "Healthy"}})])

    cluster = V3Client(
        api_key="secret", base_url="https://api.test", session=session
    ).wait_for_nke_cluster_healthy(7)

    assert cluster.status["cluster"] == "Healthy"
    assert len(session.calls) == 1


def test_wait_for_nke_cluster_healthy_raises_on_failed_state() -> None:
    session = RecordedSession([response({"clusterId": 7, "status": {"cluster": "Failed"}})])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).wait_for_nke_cluster_healthy(7)


def test_wait_for_nke_cluster_healthy_times_out() -> None:
    session = RecordedSession([response({"clusterId": 7, "status": {"cluster": "Building"}})])

    with pytest.raises(NetActuateError):
        V3Client(api_key="secret", base_url="https://api.test", session=session).wait_for_nke_cluster_healthy(
            7, timeout=0
        )


def test_list_addon_catalog_decodes_rows() -> None:
    session = RecordedSession([response([{"addonId": 1, "addonType": "storage", "isDefault": True}])])

    catalog = V3Client(api_key="secret", base_url="https://api.test", session=session).list_addon_catalog()

    assert [entry.addon_type for entry in catalog] == ["storage"]
    assert "/nke/addons" in session.calls[0]["url"]


def test_list_cluster_addons_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "addonType": "storage", "state": "Installed"}])])

    addons = V3Client(api_key="secret", base_url="https://api.test", session=session).list_cluster_addons(7)

    assert [addon.addon_type for addon in addons] == ["storage"]
    assert "/nke/clusters/7/addons" in session.calls[0]["url"]


def test_get_cluster_addon_builds_path() -> None:
    session = RecordedSession([response({"id": 1, "addonType": "storage"})])

    addon = V3Client(api_key="secret", base_url="https://api.test", session=session).get_cluster_addon(
        7, "storage"
    )

    assert addon.addon_type == "storage"
    assert "/nke/clusters/7/addons/storage" in session.calls[0]["url"]


def test_create_cluster_addon_sends_json_body() -> None:
    session = RecordedSession([response({"id": 1, "addonType": "netactuate-dns"})])

    addon = V3Client(api_key="secret", base_url="https://api.test", session=session).create_cluster_addon(
        7, "netactuate-dns", config={"zone": "example.com", "mode": "primary"}
    )

    assert addon.addon_type == "netactuate-dns"
    call = session.calls[0]
    assert call["method"] == "POST"
    assert "/nke/clusters/7/addons" in call["url"]
    assert call["kwargs"]["json"] == {
        "addonType": "netactuate-dns",
        "config": {"zone": "example.com", "mode": "primary"},
    }


def test_update_cluster_addon_sends_only_provided_fields() -> None:
    session = RecordedSession([response({"id": 1, "addonType": "storage", "version": "2.0"})])

    addon = V3Client(api_key="secret", base_url="https://api.test", session=session).update_cluster_addon(
        7, "storage", version="2.0"
    )

    assert addon.version == "2.0"
    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/nke/clusters/7/addons/storage" in call["url"]
    assert call["kwargs"]["json"] == {"version": "2.0"}


def test_delete_cluster_addon_calls_delete() -> None:
    session = RecordedSession([response(None)])

    V3Client(api_key="secret", base_url="https://api.test", session=session).delete_cluster_addon(7, "storage")

    assert session.calls[0]["method"] == "DELETE"
    assert "/nke/clusters/7/addons/storage" in session.calls[0]["url"]


def test_list_cluster_dns_zones_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"dnsZoneId": 1, "clusterId": 7, "zone": "example.com", "mode": "primary"}])]
    )

    zones = V3Client(api_key="secret", base_url="https://api.test", session=session).list_cluster_dns_zones(7)

    assert [zone.zone for zone in zones] == ["example.com"]
    assert "/nke/clusters/7/dns-zones" in session.calls[0]["url"]
