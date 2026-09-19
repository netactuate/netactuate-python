"""Tests for the SSL certificate (vAPI3) gona-parity methods (gona's ssl_certificate.go)."""

from __future__ import annotations

import pytest

from netactuate import NotFoundError, V3Client
from test_client import RecordedSession, response


def _v3(session: RecordedSession) -> V3Client:
    return V3Client(api_key="secret", base_url="https://api.test", session=session)


def test_create_ssl_certificate_posts_body_and_returns_id() -> None:
    session = RecordedSession([response({"sslCertificateId": 5})])

    cert_id = _v3(session).create_ssl_certificate(
        "cert", "test-certificate", "test-private-key", description="site cert"
    )

    assert cert_id == 5
    call = session.calls[0]
    assert "/ssl-certificates" in call["url"]
    assert call["kwargs"]["json"] == {
        "name": "cert",
        "certificate": "test-certificate",
        "privateKey": "test-private-key",
        "description": "site cert",
    }


def test_create_ssl_certificate_omits_description_when_unset() -> None:
    session = RecordedSession([response({"sslCertificateId": 6})])

    _v3(session).create_ssl_certificate("cert", "cert-content", "key-content")

    assert "description" not in session.calls[0]["kwargs"]["json"]


def test_list_ssl_certificates_decodes_rows() -> None:
    payload = [
        {
            "sslCertificateId": 1,
            "name": "cert-1",
            "description": "primary",
            "fingerprint": "ab:cd",
            "domains": ["example.com", "www.example.com"],
            "isActive": True,
            "status": "active",
            "dates": {
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-02T00:00:00Z",
                "notBefore": "2026-01-01T00:00:00Z",
                "expiration": "2027-01-01T00:00:00Z",
            },
        }
    ]
    session = RecordedSession([response(payload)])

    certs = _v3(session).list_ssl_certificates()

    assert len(certs) == 1
    cert = certs[0]
    assert cert.ssl_certificate_id == 1
    assert cert.domains == ["example.com", "www.example.com"]
    assert cert.is_active is True
    assert cert.dates is not None
    assert cert.dates.expiration == "2027-01-01T00:00:00Z"
    assert "/ssl-certificates" in session.calls[0]["url"]


def test_get_ssl_certificate_decodes_single_row() -> None:
    session = RecordedSession(
        [
            response(
                {
                    "sslCertificateId": 2,
                    "name": "cert-2",
                    "description": "",
                    "fingerprint": "ef:12",
                    "domains": ["api.example.com"],
                    "isActive": False,
                    "status": "expired",
                }
            )
        ]
    )

    cert = _v3(session).get_ssl_certificate(2)

    assert cert.ssl_certificate_id == 2
    assert cert.is_active is False
    assert cert.dates is None
    assert "/ssl-certificates/2" in session.calls[0]["url"]


def test_get_ssl_certificate_raises_not_found() -> None:
    session = RecordedSession([response({"message": "not found"}, code=404)])

    with pytest.raises(NotFoundError):
        _v3(session).get_ssl_certificate(999)


def test_update_ssl_certificate_sends_only_set_fields() -> None:
    session = RecordedSession([response({})])

    _v3(session).update_ssl_certificate(3, name="renamed")

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert "/ssl-certificates/3" in call["url"]
    assert call["kwargs"]["json"] == {"name": "renamed"}


def test_delete_ssl_certificate_sends_delete() -> None:
    session = RecordedSession([response(None)])

    _v3(session).delete_ssl_certificate(4)

    call = session.calls[0]
    assert call["method"] == "DELETE"
    assert "/ssl-certificates/4" in call["url"]
