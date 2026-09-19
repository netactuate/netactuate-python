"""Tests for the vAPI2 compute domain gona-parity methods (gona's compute.go)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from netactuate import Client, NotFoundError
from test_client import RecordedResponse, RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def _query(url: str) -> dict:
    return parse_qs(urlsplit(url).query)


# --- server delete, power actions --------------------------------------------


def test_delete_server_sends_force_password_and_password() -> None:
    session = RecordedSession([response({"id": 42})])

    _client(session).delete_server(42, force_password="fp", password="pw")

    assert session.calls[0]["kwargs"]["json"] == {"force_password": "fp", "password": "pw"}


def test_start_server_omits_force_by_default() -> None:
    session = RecordedSession([response(None)])

    _client(session).start_server(3)

    assert session.calls[0]["kwargs"]["json"] == {}


def test_start_server_sends_force_when_given() -> None:
    session = RecordedSession([response(None)])

    _client(session).start_server(3, force=True)

    assert session.calls[0]["kwargs"]["json"] == {"force": True}


def test_stop_server_sends_force_when_given() -> None:
    session = RecordedSession([response(None)])

    _client(session).stop_server(3, force=False)

    assert session.calls[0]["kwargs"]["json"] == {"force": False}


def test_reboot_server_posts_to_reboot_path() -> None:
    session = RecordedSession([response(None)])

    _client(session).reboot_server(3, force=True)

    assert "cloud/server/3/reboot" in session.calls[0]["url"]
    assert session.calls[0]["kwargs"]["json"] == {"force": True}


def test_run_server_fsck_posts_empty_form() -> None:
    session = RecordedSession([response(None)])

    _client(session).run_server_fsck(3)

    call = session.calls[0]
    assert "cloud/server/3/fsck" in call["url"]
    assert call["kwargs"]["data"] == {}


def test_reconfigure_server_network_posts_empty_form() -> None:
    session = RecordedSession([response(None)])

    _client(session).reconfigure_server_network(3)

    call = session.calls[0]
    assert "cloud/server/3/netconfig" in call["url"]
    assert call["kwargs"]["data"] == {}


def test_stop_server_rescue_posts_empty_form() -> None:
    session = RecordedSession([response(None)])

    _client(session).stop_server_rescue(3)

    call = session.calls[0]
    assert "cloud/server/3/rescue_stop" in call["url"]
    assert call["kwargs"]["data"] == {}


def test_start_server_rescue_sends_rescue_pass_and_optional_password() -> None:
    session = RecordedSession([response({"status": "ok"})])

    _client(session).start_server_rescue(3, rescue_pass="rp", password="pw")

    call = session.calls[0]
    assert "cloud/server/3/rescue_start" in call["url"]
    assert call["kwargs"]["json"] == {"rescue_pass": "rp", "password": "pw"}


def test_reset_server_root_password_omits_password_when_not_given() -> None:
    session = RecordedSession([response({"status": "ok"})])

    _client(session).reset_server_root_password(3, root_pass="rp")

    call = session.calls[0]
    assert "cloud/server/3/password" in call["url"]
    assert call["kwargs"]["json"] == {"rootpass": "rp"}


def test_start_server_vnc_posts_to_vnc_path() -> None:
    session = RecordedSession([response({"port": 5901})])

    data = _client(session).start_server_vnc(3)

    assert data == {"port": 5901}
    assert "cloud/server/3/vnc" in session.calls[0]["url"]


# --- server detail getters ---------------------------------------------------


def test_list_server_ipv4_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "ip": "1.2.3.4", "reverse": "host.example"}])])

    addresses = _client(session).list_server_ipv4(3)

    assert addresses[0].ip == "1.2.3.4"
    assert addresses[0].reverse == "host.example"
    assert "cloud/server/3/ipv4" in session.calls[0]["url"]


def test_list_server_ipv6_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 2, "ip": "::1", "reverse": None}])])

    addresses = _client(session).list_server_ipv6(3)

    assert addresses[0].ip == "::1"
    assert addresses[0].reverse is None
    assert "cloud/server/3/ipv6" in session.calls[0]["url"]


def test_list_server_jobs_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 9, "command": "reboot", "status": 1}])])

    jobs = _client(session).list_server_jobs(3)

    assert jobs[0].id == 9
    assert "cloud/server/3/jobs" in session.calls[0]["url"]


def test_get_server_job_scoped_to_server() -> None:
    session = RecordedSession([response({"id": 9, "command": "reboot", "status": 1})])

    job = _client(session).get_server_job(3, 9)

    assert job.id == 9
    assert "cloud/server/3/jobs/9" in session.calls[0]["url"]


def test_get_server_network_ips_returns_raw_payload() -> None:
    session = RecordedSession([response([{"ip": "1.2.3.4"}])])

    data = _client(session).get_server_network_ips(3)

    assert data == [{"ip": "1.2.3.4"}]


def test_get_server_bgp_sessions_adds_group_type_query() -> None:
    session = RecordedSession([response([])])

    _client(session).get_server_bgp_sessions(3, group_type="anycast")

    assert _query(session.calls[0]["url"])["group_type"] == ["anycast"]


def test_get_server_status_decodes_payload() -> None:
    session = RecordedSession([response({"status": "on", "state": "running"})])

    status = _client(session).get_server_status(3)

    assert status.status == "on"
    assert status.state == "running"


def test_get_server_vnc_status_returns_raw_payload() -> None:
    session = RecordedSession([response({"active": False})])

    data = _client(session).get_server_vnc_status(3)

    assert data == {"active": False}
    assert "cloud/server/vnc-status/3" in session.calls[0]["url"]


def test_get_server_build_status_decodes_payload() -> None:
    session = RecordedSession([response({"id": 5, "status": "building", "percent": 40, "response": ""})])

    status = _client(session).get_server_build_status(5)

    assert status.percent == 40
    assert "cloud/server/build_status/5" in session.calls[0]["url"]


def test_get_server_deployment_info_adds_contract_type_query() -> None:
    session = RecordedSession([response({})])

    _client(session).get_server_deployment_info(contract_type="hourly")

    assert _query(session.calls[0]["url"])["contract_type"] == ["hourly"]


def test_update_server_options_sends_only_given_fields() -> None:
    session = RecordedSession([response({})])

    _client(session).update_server_options(3, fqdn="host.example", vcpus=4)

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "cloud/options/3" in call["url"]
    assert call["kwargs"]["json"] == {"fqdn": "host.example", "vcpus": 4}


def test_get_scaling_options_encodes_bool_as_true_false() -> None:
    session = RecordedSession([response({})])

    _client(session).get_scaling_options(3, include_current_plan=True, min_ram=1024)

    query = _query(session.calls[0]["url"])
    assert query["include_current_plan"] == ["true"]
    assert query["min_ram"] == ["1024"]


def test_get_server_monthly_bandwidth_returns_raw_payload() -> None:
    session = RecordedSession([response({"bytes": 100})])

    data = _client(session).get_server_monthly_bandwidth(3)

    assert data == {"bytes": 100}


def test_get_bandwidth_stats_adds_date_query() -> None:
    session = RecordedSession([response({})])

    _client(session).get_bandwidth_stats(3, date="2026-01-01")

    assert _query(session.calls[0]["url"])["date"] == ["2026-01-01"]


def test_get_bandwidth_stats_range_returns_raw_payload() -> None:
    session = RecordedSession([response({"days": []})])

    data = _client(session).get_bandwidth_stats_range(3)

    assert data == {"days": []}
    assert "cloud/bw_stats_range/3" in session.calls[0]["url"]


def test_get_ip_limits_returns_raw_payload() -> None:
    session = RecordedSession([response({"max": 5})])

    data = _client(session).get_ip_limits(3)

    assert data == {"max": 5}


def test_get_cloud_extras_returns_raw_payload() -> None:
    session = RecordedSession([response({"extras": []})])

    data = _client(session).get_cloud_extras(3)

    assert data == {"extras": []}


def test_update_cloud_ipv4_reverse_dns_puts_reverse() -> None:
    session = RecordedSession([response(None)])

    _client(session).update_cloud_ipv4_reverse_dns(7, "host.example")

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "cloud/ipv4/7" in call["url"]
    assert call["kwargs"]["json"] == {"reverse": "host.example"}


def test_update_cloud_ipv6_reverse_dns_puts_reverse() -> None:
    session = RecordedSession([response(None)])

    _client(session).update_cloud_ipv6_reverse_dns(7, "host.example")

    call = session.calls[0]
    assert call["method"] == "PUT"
    assert "cloud/ipv6/7" in call["url"]
    assert call["kwargs"]["json"] == {"reverse": "host.example"}


# --- images -------------------------------------------------------------------


def test_list_base_images_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "os": "Debian 12"}])])

    images = _client(session).list_base_images()

    assert images[0].name == "Debian 12"
    assert "cloud/images/base" in session.calls[0]["url"]


def test_list_private_images_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 2, "os": "custom"}])])

    images = _client(session).list_private_images()

    assert images[0].id == 2
    assert "cloud/images/private" in session.calls[0]["url"]


def test_replace_image_posts_replace_id() -> None:
    session = RecordedSession([response({"status": "ok"})])

    _client(session).replace_image(1, 2)

    call = session.calls[0]
    assert "cloud/images/1/replace_image" in call["url"]
    assert call["kwargs"]["json"] == {"replace_id": 2}


def test_get_images_provisioning_jobs_count_returns_raw_payload() -> None:
    session = RecordedSession([response(3)])

    assert _client(session).get_images_provisioning_jobs_count() == 3


# --- kernels, locations, pools ------------------------------------------------


def test_list_kernels_decodes_rows() -> None:
    session = RecordedSession([response([{"id": 1, "name": "stock"}])])

    kernels = _client(session).list_kernels()

    assert kernels[0].name == "stock"


def test_get_cloud_location_decodes_payload() -> None:
    session = RecordedSession([response({"id": 4, "name": "US-East", "city": "Ashburn"})])

    location = _client(session).get_cloud_location(4)

    assert location.city == "Ashburn"


def test_get_cloud_pool_decodes_payload() -> None:
    session = RecordedSession(
        [response({"id": 1, "name": "default", "hard_capabilities": ["nvme"], "required_vcpu": "EPYC-Milan"})]
    )

    pool = _client(session).get_cloud_pool(1)

    assert pool.hard_capabilities == ["nvme"]
    assert pool.required_vcpu == "EPYC-Milan"


def test_get_current_server_decodes_payload() -> None:
    session = RecordedSession([response({"mbpkgid": 9, "fqdn": "current.example"})])

    server = _client(session).get_current_server()

    assert server.id == 9
    assert "cloud/servers/current" in session.calls[0]["url"]


def test_get_unprovisioned_packages_returns_raw_payload() -> None:
    session = RecordedSession([response([{"id": 1}])])

    assert _client(session).get_unprovisioned_packages() == [{"id": 1}]


def test_get_cloud_servers_usage_info_returns_raw_payload() -> None:
    session = RecordedSession([response({"used": 1})])

    assert _client(session).get_cloud_servers_usage_info() == {"used": 1}


def test_get_virtual_server_contract_decodes_payload() -> None:
    session = RecordedSession([response({"id": 1, "mb_id": 2, "max_cpus": 4})])

    contract = _client(session).get_virtual_server_contract(3)

    assert contract.max_cpus == 4
    assert "cloud/servers/3/contract" in session.calls[0]["url"]


def test_get_server_summary_returns_raw_payload() -> None:
    session = RecordedSession([response({"summary": True})])

    assert _client(session).get_server_summary(3) == {"summary": True}


def test_attempt_ssh_connection_posts_credentials() -> None:
    session = RecordedSession([response({"ok": True})])

    _client(session).attempt_ssh_connection(3, "root", "hunter2")

    call = session.calls[0]
    assert "cloud/servers/attempt-ssh" in call["url"]
    assert call["kwargs"]["json"] == {"mbpkgid": 3, "username": "root", "password": "hunter2"}


def test_get_plan_id_escapes_plan_name() -> None:
    session = RecordedSession([response(42)])

    assert _client(session).get_plan_id("value vc1") == 42
    assert "cloud/sizes/plan-id/value%20vc1" in session.calls[0]["url"]


def test_list_deploy_sizes_adds_filters() -> None:
    session = RecordedSession([response([{"plan_id": 1, "plan": "value.vc1", "cpu": 1}])])

    sizes = _client(session).list_deploy_sizes("us-east", min_cpu=2, min_ram=1024)

    assert sizes[0].plan == "value.vc1"
    query = _query(session.calls[0]["url"])
    assert query["min_cpu"] == ["2"]
    assert query["min_ram"] == ["1024"]


def test_get_cloud_storage_locations_adds_cloud_pool_id_query() -> None:
    session = RecordedSession([response([])])

    _client(session).get_cloud_storage_locations(cloud_pool_id=5)

    assert _query(session.calls[0]["url"])["cloud_pool_id"] == ["5"]


def test_bind_cloud_firewall_set_posts_body() -> None:
    session = RecordedSession([response({"status": "ok"})])

    _client(session).bind_cloud_firewall_set(3, firewall_set_id=1, interface_id=2, set_priority=10)

    call = session.calls[0]
    assert "cloud/3/firewall-sets" in call["url"]
    assert call["kwargs"]["json"] == {"firewall_set_id": 1, "interface_id": 2, "set_priority": 10}


def test_unbind_cloud_firewall_set_deletes_by_name() -> None:
    session = RecordedSession([response(None)])

    _client(session).unbind_cloud_firewall_set(3, "prod set")

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "cloud/3/firewall-sets/prod%20set" in call["url"]


def test_create_usage_contract_posts_mb_id() -> None:
    session = RecordedSession([response({"id": 1, "mb_id": 9})])

    contract = _client(session).create_usage_contract(9)

    assert contract.mb_id == 9
    call = session.calls[0]
    assert "cloud/contract/usage" in call["url"]
    assert call["kwargs"]["json"] == {"mb_id": 9}


def test_parse_cloud_init_uploads_multipart_file() -> None:
    session = RecordedSession([response({"parsed": True})])

    data = _client(session).parse_cloud_init("init.yaml", b"#cloud-config\n")

    assert data == {"parsed": True}
    call = session.calls[0]
    assert "cloud/parse-cloud-init" in call["url"]
    assert call["kwargs"]["files"] == {"file": ("init.yaml", b"#cloud-config\n")}


# --- shared NotFoundError behavior --------------------------------------------


def test_compute_getter_raises_not_found_on_404() -> None:
    session = RecordedSession([RecordedResponse({"code": 404, "message": "gone", "data": {}})])

    with pytest.raises(NotFoundError):
        _client(session).get_cloud_location(999)
