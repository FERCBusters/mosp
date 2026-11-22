"""Outbound mail: SMTP transport rules, attachments and calendar invites.

The SMTP classes are replaced at their owning module, so no network is used.
"""

import ssl
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from myf.services import mailer
from tests.testapp.config import settings


class FakeSMTP:
    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.calls: list[tuple] = []
        self.messages = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.calls.append(("quit",))
        return False

    def ehlo(self):
        self.calls.append(("ehlo",))

    def starttls(self, context=None):
        self.calls.append(("starttls", context))

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, message, from_addr=None, to_addrs=None):
        self.calls.append(("send",))
        self.messages.append(message)
        self.recipients = to_addrs


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", FakeSMTP)
    for name, value in {
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_from_email": "site@example.test",
        "smtp_from_name": "TestApp Alerts",
        "smtp_username": "",
        "smtp_password": "",
        "smtp_use_tls": True,
        "smtp_use_ssl": False,
        "smtp_timeout_seconds": 7,
    }.items():
        monkeypatch.setattr(settings, name, value)
    return FakeSMTP


def test_nothing_is_sent_without_configuration_or_a_recipient(smtp, monkeypatch):
    mailer.send_email(to_email="  ", subject="S", body="B")
    assert smtp.instances == []
    monkeypatch.setattr(settings, "smtp_host", " ")
    assert mailer.smtp_configured() is False
    mailer.send_email(to_email="a@example.test", subject="S", body="B")
    assert smtp.instances == []


def test_starttls_precedes_login_and_sending(smtp, monkeypatch):
    monkeypatch.setattr(settings, "smtp_username", "mailer")
    monkeypatch.setattr(settings, "smtp_password", "synthetic-secret")
    mailer.send_email(
        to_email=" auditor@example.test ",
        subject="Audit scheduled",
        body="Hello",
        attachments=[
            {
                "filename": "notes.txt",
                "content": "text",
                "maintype": "text",
                "subtype": "plain",
            },
            {"filename": "empty.bin", "content": b""},
            {"content": b"\x00\x01"},
        ],
    )
    (client,) = smtp.instances
    assert (client.host, client.port, client.timeout) == ("smtp.example.test", 587, 7)
    names = [call[0] for call in client.calls]
    assert names == ["ehlo", "starttls", "ehlo", "login", "send", "quit"]
    # The one address is the envelope recipient, never the parsed To header.
    assert client.recipients == ["auditor@example.test"]
    assert type(client.calls[1][1]) is ssl.SSLContext
    assert client.calls[1][1].verify_mode == ssl.CERT_REQUIRED
    assert client.calls[1][1].check_hostname is True
    (message,) = client.messages
    assert message["From"] == "TestApp Alerts <site@example.test>"
    assert message["To"] == "auditor@example.test"
    assert message["Subject"] == "Audit scheduled"
    attachments = list(message.iter_attachments())
    # Empty attachments are skipped; missing names and types get safe defaults.
    assert [(a.get_filename(), a.get_content_type()) for a in attachments] == [
        ("notes.txt", "text/plain"),
        ("attachment", "application/octet-stream"),
    ]


def test_a_subject_stays_on_one_line(smtp):
    # A stored title with a line break would otherwise fail every send.
    mailer.send_email(
        to_email="a@example.test", subject="Quiz ready -\r\nBcc: x@evil.test", body="B"
    )
    (client,) = smtp.instances
    (message,) = client.messages
    assert message["Subject"] == "Quiz ready - Bcc: x@evil.test"
    assert message["Bcc"] is None


def test_implicit_tls_uses_a_verifying_context(smtp, monkeypatch):
    monkeypatch.setattr(settings, "smtp_use_ssl", True)
    monkeypatch.setattr(settings, "smtp_port", 465)
    monkeypatch.setattr(settings, "smtp_username", "mailer")
    monkeypatch.setattr(settings, "smtp_password", "synthetic-secret")
    mailer.send_email(to_email="a@example.test", subject="S", body="B")
    (client,) = smtp.instances
    assert client.port == 465 and client.context.verify_mode == ssl.CERT_REQUIRED
    assert [call[0] for call in client.calls] == ["login", "send", "quit"]


def test_credentials_are_never_sent_without_tls(smtp, monkeypatch):
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    monkeypatch.setattr(settings, "smtp_username", "mailer")
    monkeypatch.setattr(settings, "smtp_password", "synthetic-secret")
    with pytest.raises(RuntimeError, match="require TESTAPP_SMTP_USE_TLS"):
        mailer.send_email(to_email="a@example.test", subject="S", body="B")
    assert smtp.instances == []

    # Without credentials, plain relays are still allowed.
    monkeypatch.setattr(settings, "smtp_username", "")
    mailer.send_email(to_email="a@example.test", subject="S", body="B")
    (client,) = smtp.instances
    assert [call[0] for call in client.calls] == ["ehlo", "send", "quit"]


def test_header_injection_reaches_no_mail_server(smtp):
    # A recipient holding a header break is not one address, so nothing is sent.
    mailer.send_email(
        to_email="a@example.test\r\nBcc: other@example.test", subject="S", body="B"
    )
    assert FakeSMTP.instances == []


def test_long_multibyte_lines_fold_on_character_boundaries():
    line = "SUMMARY:" + "é" * 80
    folded = mailer._ics_fold(line)
    parts = folded.split("\r\n")
    assert all(len(part.encode()) <= 75 for part in parts)
    assert "".join(part[1:] if i else part for i, part in enumerate(parts)) == line
    assert mailer._ics_escape("a\\b\r\nc\rd") == "a\\\\b\\nc\\nd"


def test_a_user_is_emailed_at_their_address_or_an_email_username():
    assert mailer.user_email(None) is None
    assert mailer.user_email(SimpleNamespace(email=" a@example.test ")) == (
        "a@example.test"
    )
    assert mailer.user_email(SimpleNamespace(email="", username="b@example.test")) == (
        "b@example.test"
    )
    assert mailer.user_email(SimpleNamespace(email=None, username="carol")) is None


def test_implicit_tls_without_credentials_sends_without_signing_in(smtp, monkeypatch):
    monkeypatch.setattr(settings, "smtp_use_ssl", True)
    mailer.send_email(to_email="a@example.test", subject="S", body="B")
    (client,) = smtp.instances
    assert [call[0] for call in client.calls] == ["send", "quit"]


def test_a_calendar_invite_describes_one_all_day_event(smtp, monkeypatch):
    invite = mailer.build_calendar_invite(
        summary="Review; part 1, of 2",
        description="Line one\nLine two",
        starts="2026-03-01T09:00:00",
        ends=date(2026, 3, 3),
        url="https://app.example/review",
        uid="review 7 / 2026",
    )
    lines = invite.split("\r\n")
    assert lines[:5] == [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//TestApp//Schedule//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    assert "UID:review-7-2026@testapp" in lines
    assert "DTSTART;VALUE=DATE:20260301" in lines
    # The end date is included: an all-day DTEND is exclusive.
    assert "DTEND;VALUE=DATE:20260304" in lines
    assert "SUMMARY:Review\\; part 1\\, of 2" in lines
    assert "DESCRIPTION:Line one\\nLine two" in lines
    assert invite.endswith("END:VCALENDAR\r\n")

    mailer.send_with_invite(
        to_email="a@example.test",
        subject="Review",
        body="See the invite.",
        invite=invite,
        filename="review.ics",
    )
    (message,) = smtp.instances[0].messages
    (attachment,) = list(message.iter_attachments())
    assert attachment.get_filename() == "review.ics"
    assert attachment.get_content_type() == "text/calendar"


def test_calendar_dates_fall_back_where_they_cannot_be_read():
    today = date.today()
    invite = mailer.build_calendar_invite(
        summary="S", description="", starts=None, ends="2000-01-01", url=""
    )
    assert f"DTSTART;VALUE=DATE:{today:%Y%m%d}" in invite
    assert f"DTEND;VALUE=DATE:{today + timedelta(days=1):%Y%m%d}" in invite
    unreadable = mailer.build_calendar_invite(
        summary="S", description="", starts="soon", url="", uid="!!!", uid_prefix="p"
    )
    assert f"DTSTART;VALUE=DATE:{today:%Y%m%d}" in unreadable
    assert "UID:p@testapp" in unreadable
    assert mailer._ics_fold("short") == "short"


def test_attachments_without_content_are_left_out_and_the_rest_named(smtp):
    mailer.send_email(
        to_email="a@example.test",
        subject="S",
        body="B",
        attachments=[
            {"content": "", "filename": "empty.txt"},
            {"content": b"data", "filename": " ", "maintype": " ", "subtype": ""},
        ],
    )
    (message,) = smtp.instances[0].messages
    (attachment,) = list(message.iter_attachments())
    assert attachment.get_filename() == "attachment"
    assert attachment.get_content_type() == "application/octet-stream"


def test_the_sender_is_named_after_the_application_by_default(monkeypatch):
    monkeypatch.setattr(settings, "smtp_from_name", " ")
    assert mailer.sender_name() == "TestApp"
    monkeypatch.setattr(settings, "smtp_from_name", "Alerts")
    assert mailer.sender_name() == "Alerts"
