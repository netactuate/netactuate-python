"""Tests for the dedicated server and image vAPI2 gona-parity methods."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from netactuate import Client, NetActuateError, NotFoundError
from test_client import RecordedResponse, RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


def _query(url: str) -> dict:
    return parse_qs(urlsplit(url).query)


# --- dedicated devices, locations, OS profiles, plans -----------------------


def test_list_dedicated_devices_accepts_bare_list() -> None:
    session = RecordedSession([response([{"cpu_type": "epyc"}])])

    devices = _client(session).list_dedicated_devices(cpu_type="epyc")

    assert devices == [{"cpu_type": "epyc"}]
    assert _query(session.calls[0]["url"])["cpu_type"] == ["epyc"]


def test_list_dedicated_devices_accepts_paginator_envelope() -> None:
    session = RecordedSession(
        [response({"devices": {"paginator": {"data": [{"cpu_type": "xeon"}]}}})]
    )

    devices = _client(session).list_dedicated_devices()

    assert devices == [{"cpu_type": "xeon"}]


def test_list_dedicated_devices_rejects_unrecognized_shape() -> None:
    session = RecordedSession([response({"unexpected": True})])

    with pytest.raises(NetActuateError):
        _client(session).list_dedicated_devices()


def test_list_dedicated_locations_decodes_rows() -> None:
    session = RecordedSession(
        [response([{"location_id": 5, "short_name": "AMS", "pub_description": "Amsterdam"}])]
    )

    locations = _client(session).list_dedicated_locations()

    assert locations[0].location_id == 5
    assert locations[0].short_name == "AMS"


def test_list_dedicated_device_os_profiles_reads_pascal_case_keys() -> None:
    payload = [
        {
            "OSID": 5,
            "Name": "Ubuntu 22.04",
            "GroupName": "Ubuntu",
            "Tags": ["lts"],
            "DiskLayouts": [{"ID": 1, "Name": "Layout"}],
            "Scripts": [{"ID": 2, "Name": "Script"}],
            "DefaultDiskLayout": 1,
            "DefaultScripts": [2],
            "AllowSSHKeys": 1,
            "SetRootPassword": 1,
            "RescueImage": 0,
            "Public": 1,
            "Enabled": 1,
            "Created": "2020-01-01",
            "LastUpdated": "2021-01-01",
            "ProfileID": 9,
            "Arch": "x86_64",
            "Flavor": "linux",
            "LocationID": 3,
        }
    ]
    session = RecordedSession([response(payload)])

    profiles = _client(session).list_dedicated_device_os_profiles(42, is_buyable=True)

    profile = profiles[0]
    assert profile.os_id == 5
    assert profile.disk_layouts[0].id == 1
    assert profile.disk_layouts[0].name == "Layout"
    assert profile.scripts[0].name == "Script"
    assert profile.location_id == 3
    assert "dedicated/os/device/42" in session.calls[0]["url"]
    assert _query(session.calls[0]["url"])["is_buyable"] == ["1"]


def test_list_dedicated_plans_returns_raw_rows() -> None:
    session = RecordedSession([response([{"plan": "value.m1"}])])

    plans = _client(session).list_dedicated_plans(location_id=7)

    assert plans == [{"plan": "value.m1"}]
    assert "dedicated/plans/7" in session.calls[0]["url"]


# --- deploy, buy, ipv4 reverse -----------------------------------------------


def test_deploy_dedicated_server_always_sends_fqdn_and_profile() -> None:
    session = RecordedSession([response({"mbpkgid": 11, "status": "queued", "build": 1})])

    build = _client(session).deploy_dedicated_server(11, fqdn="host.example.com", profile=3)

    assert build.server_id == 11
    assert session.calls[0]["kwargs"]["json"] == {"fqdn": "host.example.com", "profile": 3}
    assert "dedicated/server/build/11" in session.calls[0]["url"]


def test_deploy_dedicated_server_includes_optional_fields_when_set() -> None:
    session = RecordedSession([response({"mbpkgid": 11, "status": "queued", "build": 1})])

    _client(session).deploy_dedicated_server(
        11,
        fqdn="host.example.com",
        profile=3,
        disk_layout=2,
        root_password="secret",
        ssh_key_id=9,
        build_script="#!/bin/sh",
    )

    assert session.calls[0]["kwargs"]["json"] == {
        "fqdn": "host.example.com",
        "profile": 3,
        "disklayout": 2,
        "root_password": "secret",
        "ssh_key_id": 9,
        "build_script": "#!/bin/sh",
    }


def test_buy_dedicated_server_posts_empty_form_body() -> None:
    session = RecordedSession([response({"mbpkgid": 12, "status": "queued", "build": 1})])

    build = _client(session).buy_dedicated_server(device_id=4)

    assert build.server_id == 12
    assert session.calls[0]["kwargs"]["data"] == {}
    assert "dedicated/server/buy/4" in session.calls[0]["url"]


def test_buy_and_deploy_dedicated_server_posts_json_body() -> None:
    session = RecordedSession([response({"mbpkgid": 13, "status": "queued", "build": 1})])

    _client(session).buy_and_deploy_dedicated_server(device_id=4, fqdn="a.example.com")

    assert session.calls[0]["kwargs"]["json"] == {"fqdn": "a.example.com", "profile": 0}
    assert "dedicated/server/buy_build/4" in session.calls[0]["url"]


def test_update_dedicated_server_ipv4_reverse_sends_full_body() -> None:
    session = RecordedSession([response(None)])

    _client(session).update_dedicated_server_ipv4_reverse(mbpkgid=5, address_id=9, reverse="host.example.com")

    assert session.calls[0]["kwargs"]["json"] == {"mbpkgid": 5, "id": 9, "reverse": "host.example.com"}
    assert session.calls[0]["method"] == "PUT"


# --- power and lifecycle actions ---------------------------------------------


def test_soft_reset_dedicated_server_sends_no_body() -> None:
    session = RecordedSession([response(None)])

    _client(session).soft_reset_dedicated_server(21)

    assert session.calls[0]["kwargs"]["json"] is None
    assert "dedicated/server/soft-reset/21" in session.calls[0]["url"]


@pytest.mark.parametrize(
    ("method_name", "action"),
    [
        ("delete_dedicated_server", "delete"),
        ("reboot_dedicated_server", "reboot"),
        ("shutdown_dedicated_server", "shutdown"),
        ("start_dedicated_server", "start"),
    ],
)
def test_dedicated_server_actions_omit_body_when_unset(method_name: str, action: str) -> None:
    session = RecordedSession([response(None)])

    getattr(_client(session), method_name)(22)

    assert session.calls[0]["kwargs"]["json"] is None
    assert f"dedicated/server/22/{action}" in session.calls[0]["url"]


def test_delete_dedicated_server_includes_force_and_password_when_given() -> None:
    session = RecordedSession([response(None)])

    _client(session).delete_dedicated_server(22, force=True, password="hunter2")

    assert session.calls[0]["kwargs"]["json"] == {"force": True, "password": "hunter2"}


def test_get_dedicated_server_power_status_returns_raw_mapping() -> None:
    session = RecordedSession([response({"power_status": "running"})])

    status = _client(session).get_dedicated_server_power_status(22)

    assert status == {"power_status": "running"}
    assert session.calls[0]["kwargs"]["json"] is None


def test_get_dedicated_server_power_status_rejects_non_object_response() -> None:
    session = RecordedSession([response(["running"])])

    with pytest.raises(NetActuateError):
        _client(session).get_dedicated_server_power_status(22)


def test_list_dedicated_servers_decodes_rows_with_flexible_fields() -> None:
    payload = [
        {
            "id": 1,
            "mbpkgid": 100,
            "hostname": "server1.example.com",
            "primary_ip": "203.0.113.5",
            "primary_ipv6": None,
            "location": "AMS",
            "package_status": "Active",
            "locked": 0,
            "total_ram": 32768,
            "ipmi_pubip": "203.0.113.6",
            "ob_id": 555,
            "building": None,
        },
        {
            "id": 2,
            "mbpkgid": 101,
            "hostname": "server2.example.com",
            "primary_ip": "203.0.113.7",
            "location": "NYC",
            "package_status": "Building",
            "locked": 1,
            "total_ram": 65536,
            "ipmi_pubip": "203.0.113.8",
            "ob_id": "556",
            "building": {"percent": 40},
        },
    ]
    session = RecordedSession([response(payload)])

    servers = _client(session).list_dedicated_servers()

    assert servers[0].ob_id == "555"
    assert servers[0].locked is False
    assert servers[0].primary_ipv6 is None
    assert servers[1].ob_id == "556"
    assert servers[1].locked is True
    assert servers[1].building == {"percent": 40}


def test_list_dedicated_servers_not_found() -> None:
    session = RecordedSession([RecordedResponse({"code": 404, "message": "gone", "data": {}})])

    with pytest.raises(NotFoundError):
        _client(session).list_dedicated_servers()


# --- images -------------------------------------------------------------------


def test_list_images_decodes_name_from_os_field() -> None:
    session = RecordedSession([response([{"id": 1, "os": "Ubuntu 22.04", "type": "linux"}])])

    images = _client(session).list_images()

    assert images[0].id == 1
    assert images[0].name == "Ubuntu 22.04"


def test_get_image_decodes_nested_active_build() -> None:
    payload = {
        "id": 2,
        "os": "Debian 12",
        "active_build": {"id": 9, "status": 1, "command": "clone", "mb_pkgid": 4},
    }
    session = RecordedSession([response(payload)])

    image = _client(session).get_image(2)

    assert image.active_build is not None
    assert image.active_build.id == 9
    assert image.active_build.mb_pkgid == 4


def test_create_image_sends_form_body_and_returns_queue_id() -> None:
    session = RecordedSession([response({"queue_id": 55})])

    queue_id = _client(session).create_image(
        mbpkgid=10, image_name="golden", image_description="base image", keep_ssh_userdirs=True
    )

    assert queue_id == 55
    assert session.calls[0]["kwargs"]["data"] == {
        "mbpkgid": 10,
        "image_name": "golden",
        "image_description": "base image",
        "keep_ssh_userdirs": "1",
    }


def test_create_image_omits_optional_fields_when_unset() -> None:
    session = RecordedSession([response({"queue_id": 56})])

    _client(session).create_image(mbpkgid=10, image_name="golden")

    assert session.calls[0]["kwargs"]["data"] == {"mbpkgid": 10, "image_name": "golden"}


def test_create_image_raises_when_queue_id_missing() -> None:
    session = RecordedSession([response({})])

    with pytest.raises(NetActuateError):
        _client(session).create_image(mbpkgid=10, image_name="golden")


def test_edit_image_sends_patch_body() -> None:
    session = RecordedSession([response(None)])

    _client(session).edit_image(2, name="new name", description="new description")

    assert session.calls[0]["method"] == "PATCH"
    assert session.calls[0]["kwargs"]["json"] == {"os": "new name", "description": "new description"}


def test_delete_image_returns_queue_id() -> None:
    session = RecordedSession([response({"queue_id": 77})])

    queue_id = _client(session).delete_image(2)

    assert queue_id == 77
    assert session.calls[0]["method"] == "DELETE"


def test_get_image_queue_status_decodes_fields() -> None:
    session = RecordedSession(
        [response({"status": "Building", "percent": 40, "mbpkgid": 10, "fqdn": "host.example.com"})]
    )

    status = _client(session).get_image_queue_status(55)

    assert status.status == "Building"
    assert status.percent == 40
    assert status.mbpkgid == 10


def test_wait_for_image_queue_returns_on_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    session = RecordedSession(
        [
            response({"status": "Building", "percent": 10}),
            response({"status": "Complete", "percent": 100}),
        ]
    )
    monkeypatch.setattr("netactuate.client.time.sleep", lambda _seconds: None)

    status = _client(session).wait_for_image_queue(55)

    assert status.status == "Complete"
    assert len(session.calls) == 2


def test_wait_for_image_queue_raises_on_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    session = RecordedSession([response({"status": "Failed", "response": "disk full"})])
    monkeypatch.setattr("netactuate.client.time.sleep", lambda _seconds: None)

    with pytest.raises(NetActuateError, match="disk full"):
        _client(session).wait_for_image_queue(55)


def test_wait_for_image_queue_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    session = RecordedSession([response({"status": "Building", "percent": 5})])
    monkeypatch.setattr("netactuate.client.time.sleep", lambda _seconds: None)

    with pytest.raises(NetActuateError, match="timeout"):
        _client(session).wait_for_image_queue(55, max_tries=1)


def test_get_image_not_found() -> None:
    session = RecordedSession([RecordedResponse({"code": 404, "message": "gone", "data": {}})])

    with pytest.raises(NotFoundError):
        _client(session).get_image(999)
