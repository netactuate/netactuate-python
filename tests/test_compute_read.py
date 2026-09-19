"""Tests for the vAPI2 compute_read gona-parity methods (gona's compute_read.go)."""

from __future__ import annotations

import pytest

from netactuate import Client, DedicatedIDName, NetActuateError
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


# --- boot profiles ------------------------------------------------------------


def test_list_boot_profiles_decodes_int_image_template() -> None:
    payload = [
        {
            "id": 1,
            "name": "Ubuntu 22.04",
            "type": "linux",
            "description": "Ubuntu image",
            "builder": "kvm",
            "kernel": "default",
            "boot": "hd",
            "serial": "ttyS0",
            "disk_represent": "virtio",
            "image_template": 7,
            "last_updated": "2026-01-01",
            "extra": None,
            "vncdisplay": None,
            "disk_root": None,
            "bootloader": None,
            "ramdisk": None,
            "initrd": None,
            "created": None,
            "pae": 1,
            "acpi": 1,
            "apic": 1,
            "xlocaltime": 0,
            "sdl": 0,
            "vnc": 1,
            "vncconsole": 0,
            "vncunused": 1,
            "hide": 0,
            "kvm": 1,
        }
    ]
    session = RecordedSession([response(payload)])

    profiles = _client(session).list_boot_profiles()

    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.id == 1
    assert profile.image_template == 7
    assert profile.extra is None
    assert profile.kvm == 1
    assert "cloud/boot-profiles" in session.calls[0]["url"]


# --- server disks ---------------------------------------------------------------


def test_list_server_disks_returns_empty_list() -> None:
    session = RecordedSession([response([])])

    disks = _client(session).list_server_disks(555)

    assert disks == []
    assert "cloud/disks/555" in session.calls[0]["url"]


def test_list_server_disks_returns_raw_rows() -> None:
    session = RecordedSession([response([{"unspecified": "shape"}])])

    disks = _client(session).list_server_disks(555)

    assert disks == [{"unspecified": "shape"}]


def test_list_server_disks_raises_on_non_list_response() -> None:
    session = RecordedSession([response({"not": "a list"})])

    with pytest.raises(NetActuateError):
        _client(session).list_server_disks(555)


# --- dedicated OS profiles --------------------------------------------------------


def test_list_dedicated_os_profiles_decodes_snake_case_shape() -> None:
    payload = [
        {
            "id": 5,
            "name": "Ubuntu 22.04",
            "group_name": "Ubuntu",
            "tags": ["linux", "lts"],
            "disklayouts": {"1": "Layout A", "2": "Layout B"},
            "scripts": [{"id": 10, "name": "Script A"}],
            "default_disklayout": 1,
            "default_scripts": [10],
            "allow_ssh_keys": 1,
            "set_root_password": 1,
            "rescue_image": 0,
            "public": 1,
            "enabled": 1,
            "created": "2020-01-01",
            "last_updated": "2021-01-01",
            "profile_id": 9,
            "arch": "x86_64",
            "flavor": "linux",
            "location_id": 3,
        }
    ]
    session = RecordedSession([response(payload)])

    profiles = _client(session).list_dedicated_os_profiles()

    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.os_id == 5
    assert profile.disk_layouts == [
        DedicatedIDName(id=1, name="Layout A", raw={"id": 1, "name": "Layout A"}),
        DedicatedIDName(id=2, name="Layout B", raw={"id": 2, "name": "Layout B"}),
    ]
    assert profile.scripts[0].id == 10
    assert profile.scripts[0].name == "Script A"
    assert profile.default_disk_layout == 1
    assert profile.location_id == 3
    assert "dedicated/os" in session.calls[0]["url"]


def test_list_dedicated_os_profiles_handles_null_disklayouts_and_scripts() -> None:
    payload = [
        {
            "id": 6,
            "name": "Debian",
            "group_name": "Debian",
            "tags": [],
            "disklayouts": None,
            "scripts": None,
            "default_disklayout": None,
            "default_scripts": [],
            "allow_ssh_keys": 0,
            "set_root_password": 0,
            "rescue_image": 0,
            "public": 1,
            "enabled": 1,
            "created": "2020-01-01",
            "last_updated": "2020-01-02",
            "profile_id": 12,
            "arch": "x86_64",
            "flavor": "linux",
            "location_id": None,
        }
    ]
    session = RecordedSession([response(payload)])

    profiles = _client(session).list_dedicated_os_profiles()

    assert profiles[0].disk_layouts == []
    assert profiles[0].scripts == []
    assert profiles[0].default_disk_layout == 0
    assert profiles[0].location_id is None


def test_list_dedicated_rescue_os_decodes_snake_case_shape() -> None:
    payload = [
        {
            "id": 7,
            "name": "Rescue Linux",
            "group_name": "Rescue",
            "tags": ["rescue"],
            "disklayouts": [{"layout_id": 4, "name": "Rescue Layout"}],
            "scripts": ["plain-script-name"],
            "default_disklayout": 4,
            "default_scripts": [],
            "allow_ssh_keys": 1,
            "set_root_password": 1,
            "rescue_image": 1,
            "public": 1,
            "enabled": 1,
            "created": "2020-01-01",
            "last_updated": "2020-01-02",
            "profile_id": 20,
            "arch": "x86_64",
            "flavor": "linux",
            "location_id": None,
        }
    ]
    session = RecordedSession([response(payload)])

    profiles = _client(session).list_dedicated_rescue_os()

    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.os_id == 7
    assert profile.disk_layouts[0].id == 4
    assert profile.disk_layouts[0].name == "Rescue Layout"
    assert profile.scripts[0].name == "plain-script-name"
    assert "dedicated/os/rescue-system-list" in session.calls[0]["url"]


# --- dedicated disk layouts -------------------------------------------------------


def test_list_dedicated_disk_layouts_decodes_rows() -> None:
    payload = [{"id": 1, "name": "Layout A", "profile": "raid1", "min_disks": 2}]
    session = RecordedSession([response(payload)])

    layouts = _client(session).list_dedicated_disk_layouts(5)

    assert len(layouts) == 1
    assert layouts[0].layout_id == 1
    assert layouts[0].profile == "raid1"
    assert layouts[0].min_disks == 2
    assert "dedicated/disklayouts/5" in session.calls[0]["url"]
