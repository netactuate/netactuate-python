"""Tests for the support and secrets vAPI2 gona-parity methods."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from netactuate import Client, NotFoundError
from test_client import RecordedSession, response


def _client(session: RecordedSession) -> Client:
    return Client(api_key="secret", base_url="https://api.test/", session=session)


class RawResponse:
    """A recorded response carrying a raw, non-enveloped body."""

    def __init__(self, content: bytes, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code
        self.text = content.decode("utf-8", "replace")
        self.url = ""
        self.request = None


def test_list_legacy_tickets() -> None:
    session = RecordedSession([response([{"id": "1", "subject": "old"}])])

    tickets = _client(session).list_legacy_tickets()

    assert [ticket.id for ticket in tickets] == ["1"]
    assert "support/legacy-tickets" in session.calls[0]["url"]


def test_list_tickets_applies_optional_filters() -> None:
    session = RecordedSession([response([{"id": "5", "subject": "hi"}])])

    tickets = _client(session).list_tickets(open_="1", include_stats="1")

    assert tickets[0].id == "5"
    query = parse_qs(urlsplit(session.calls[0]["url"]).query)
    assert query["open"] == ["1"]
    assert query["include_stats"] == ["1"]


def test_list_tickets_omits_filters_when_unset() -> None:
    session = RecordedSession([response([])])

    _client(session).list_tickets()

    query = parse_qs(urlsplit(session.calls[0]["url"]).query)
    assert "open" not in query
    assert "include_stats" not in query


def test_create_ticket_sends_required_fields_and_omits_optional() -> None:
    session = RecordedSession([response({"id": "9", "subject": "help"})])

    ticket = _client(session).create_ticket(subject="help", message="body", department=3)

    assert ticket.id == "9"
    body = session.calls[0]["kwargs"]["json"]
    assert body == {"subject": "help", "message": "body", "department": 3}


def test_create_ticket_includes_urgency_and_files() -> None:
    session = RecordedSession([response({"id": "9"})])

    _client(session).create_ticket(
        subject="help", message="body", department=3, urgency="high", files=["a.png"]
    )

    body = session.calls[0]["kwargs"]["json"]
    assert body["urgency"] == "high"
    assert body["files"] == ["a.png"]


def test_get_old_ticket_escapes_id() -> None:
    session = RecordedSession([response({"id": "old/1", "subject": "s"})])

    ticket = _client(session).get_old_ticket("old/1")

    assert ticket.id == "old/1"
    assert "support/tickets-old/old%2F1" in session.calls[0]["url"]


def test_get_old_ticket_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_old_ticket("missing")


def test_list_ticket_departments() -> None:
    session = RecordedSession([response([{"id": 1, "name": "Billing"}])])

    departments = _client(session).list_ticket_departments()

    assert departments[0].id == 1
    assert departments[0].name == "Billing"


def test_get_ticket() -> None:
    session = RecordedSession([response({"id": "42", "status": "open"})])

    ticket = _client(session).get_ticket("42")

    assert ticket.id == "42"
    assert ticket.status == "open"
    assert "support/tickets/42" in session.calls[0]["url"]


def test_get_ticket_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_ticket("missing")


def test_list_ticket_replies() -> None:
    session = RecordedSession([response([{"id": "r1", "message": "hi"}])])

    replies = _client(session).list_ticket_replies("42")

    assert replies[0].id == "r1"
    assert "support/tickets/42/replies" in session.calls[0]["url"]


def test_get_ticket_attachment_with_without_data() -> None:
    session = RecordedSession([response({"name": "a.png", "size": 10})])

    attachment = _client(session).get_ticket_attachment("42", "ticket", "42", 0, without_data=1)

    assert attachment.name == "a.png"
    assert attachment.size == 10
    query = parse_qs(urlsplit(session.calls[0]["url"]).query)
    assert query["without_data"] == ["1"]
    assert "support/tickets/42/attachment/ticket/42/0" in session.calls[0]["url"]


def test_get_ticket_attachment_without_flag_omits_query() -> None:
    session = RecordedSession([response({"name": "a.png"})])

    _client(session).get_ticket_attachment("42", "ticket", "42", 0)

    query = parse_qs(urlsplit(session.calls[0]["url"]).query)
    assert "without_data" not in query


def test_download_ticket_attachment_returns_raw_bytes() -> None:
    session = RecordedSession([])
    session.responses.append(RawResponse(b"\x89PNGDATA"))

    data = _client(session).download_ticket_attachment("42", "ticket", "42", 0)

    assert data == b"\x89PNGDATA"
    assert "support/tickets/42/attachment/ticket/42/0/download" in session.calls[0]["url"]


def test_preview_ticket_attachment_returns_raw_bytes() -> None:
    session = RecordedSession([])
    session.responses.append(RawResponse(b"preview-bytes"))

    data = _client(session).preview_ticket_attachment("42", "reply", "7", 1)

    assert data == b"preview-bytes"
    assert "support/tickets/42/attachment/reply/7/1/preview" in session.calls[0]["url"]


def test_close_ticket() -> None:
    session = RecordedSession([response(None)])

    _client(session).close_ticket("42")

    assert session.calls[0]["method"] == "POST"
    assert "support/tickets/42/close" in session.calls[0]["url"]


def test_close_ticket_alias() -> None:
    session = RecordedSession([response(None)])

    _client(session).close_ticket_alias("42")

    assert "support/tickets/close/42" in session.calls[0]["url"]


def test_reply_to_ticket() -> None:
    session = RecordedSession([response({"id": "r2", "message": "back"})])

    reply = _client(session).reply_to_ticket("42", "back", files=["log.txt"])

    assert reply.id == "r2"
    body = session.calls[0]["kwargs"]["json"]
    assert body == {"message": "back", "files": ["log.txt"]}
    assert "support/tickets/42/reply" in session.calls[0]["url"]


def test_reply_to_ticket_alias() -> None:
    session = RecordedSession([response({"id": "r3", "message": "back"})])

    reply = _client(session).reply_to_ticket_alias("42", "back")

    assert reply.id == "r3"
    assert "support/tickets/reply/42" in session.calls[0]["url"]


def test_list_secret_lists() -> None:
    session = RecordedSession([response([{"id": 1, "name": "prod"}])])

    lists = _client(session).list_secret_lists()

    assert lists[0].id == 1
    assert lists[0].name == "prod"


def test_get_secret_list() -> None:
    session = RecordedSession([response({"id": 4, "name": "prod"})])

    secret_list = _client(session).get_secret_list(4)

    assert secret_list.id == 4
    assert "secrets/lists/4" in session.calls[0]["url"]


def test_get_secret_list_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_secret_list(999)


def test_create_secret_list_sends_form_body() -> None:
    session = RecordedSession([response({"id": 1, "name": "prod"})])

    secret_list = _client(session).create_secret_list("prod")

    assert secret_list.id == 1
    assert session.calls[0]["kwargs"]["data"] == {"name": "prod"}
    assert session.calls[0]["method"] == "POST"


def test_update_secret_list() -> None:
    session = RecordedSession([response({"id": 1, "name": "renamed"})])

    secret_list = _client(session).update_secret_list(1, "renamed")

    assert secret_list.name == "renamed"
    assert "secrets/lists/1" in session.calls[0]["url"]
    assert session.calls[0]["kwargs"]["data"] == {"name": "renamed"}


def test_delete_secret_list() -> None:
    session = RecordedSession([response(None)])

    _client(session).delete_secret_list(1)

    assert session.calls[0]["method"] == "DELETE"
    assert "secrets/lists/1" in session.calls[0]["url"]


def test_list_secret_list_values() -> None:
    session = RecordedSession(
        [response([{"id": 1, "secret_list_id": "1", "secret_key": "k", "secret_value": "v"}])]
    )

    values = _client(session).list_secret_list_values(1)

    assert values[0].id == 1
    assert values[0].secret_list_id == 1
    assert values[0].secret_key == "k"
    assert "secrets/lists/1/values" in session.calls[0]["url"]


def test_list_all_secret_values() -> None:
    session = RecordedSession(
        [response([{"id": 2, "secret_list_id": 1, "secret_key": "k", "secret_value": "v"}])]
    )

    values = _client(session).list_all_secret_values()

    assert values[0].id == 2
    assert "secrets/all-values" in session.calls[0]["url"]


def test_get_secret_list_value() -> None:
    session = RecordedSession(
        [response({"id": 2, "secret_list_id": 1, "secret_key": "k", "secret_value": "v"})]
    )

    value = _client(session).get_secret_list_value(1, 2)

    assert value.id == 2
    assert value.secret_list_id == 1
    assert "secrets/lists/1/values/2" in session.calls[0]["url"]


def test_get_secret_list_value_not_found() -> None:
    session = RecordedSession([response(None, code=404, status=404)])

    with pytest.raises(NotFoundError):
        _client(session).get_secret_list_value(1, 999)


def test_create_secret_list_value_sends_form_body() -> None:
    session = RecordedSession(
        [response({"id": 3, "secret_list_id": 1, "secret_key": "k", "secret_value": "v"})]
    )

    value = _client(session).create_secret_list_value(1, "k", "v")

    assert value.id == 3
    assert session.calls[0]["kwargs"]["data"] == {"secret_key": "k", "secret_value": "v"}
    assert "secrets/lists/1/values" in session.calls[0]["url"]


def test_update_secret_list_value() -> None:
    session = RecordedSession(
        [response({"id": 3, "secret_list_id": 1, "secret_key": "k2", "secret_value": "v2"})]
    )

    value = _client(session).update_secret_list_value(1, 3, "k2", "v2")

    assert value.secret_key == "k2"
    assert "secrets/lists/1/values/3" in session.calls[0]["url"]
    assert session.calls[0]["kwargs"]["data"] == {"secret_key": "k2", "secret_value": "v2"}


def test_delete_secret_list_value() -> None:
    session = RecordedSession([response(None)])

    _client(session).delete_secret_list_value(1, 3)

    assert session.calls[0]["method"] == "DELETE"
    assert "secrets/lists/1/values/3" in session.calls[0]["url"]
