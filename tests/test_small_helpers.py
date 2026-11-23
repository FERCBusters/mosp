"""The small shared helpers: links, uploads, spreadsheet cells, provider
logs, placeholders, identifiers, request text and JSON shape."""

import io
import json
import logging
import uuid
from types import SimpleNamespace

import pytest

from myf.api.uploads import upload_inputs
from myf.core.identifiers import try_uuid
from myf.security import json_shape
from myf.security.csv import spreadsheet_cell
from myf.security.placeholders import is_placeholder
from myf.security.provider_logging import suppress_provider_logs
from myf.security.urls import external_url, same_site_path
from myf.services import text
from myf.services.errors import DomainError
from myf.services.uploads import Upload, upload_size

# -- external links ---------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["https://example.org/a?b=c", "http://example.org:8080/"]
)
def test_an_http_link_is_kept_as_written(value):
    assert external_url(f"  {value} ") == value


@pytest.mark.parametrize("value", [None, "", "   "])
def test_a_blank_link_is_no_link(value):
    assert external_url(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "https://" + "a" * 2048,
        "https://example.org\\@evil.example/",
        "https://example.org/\x01",
        "https://example.org/\x7f",
        "javascript:alert(1)",
        "https:///path-only",
        "https://user@example.org/",
        "https://:secret@example.org/",
        "https://example.org:99999/",
    ],
)
def test_other_links_are_refused(value):
    with pytest.raises(ValueError, match="HTTP or HTTPS URL"):
        external_url(value)


@pytest.mark.parametrize(
    "value,stored",
    [
        ("/diagrams.html?x=1#y", "/diagrams.html?x=1#y"),
        ("https://example.org/", "https://example.org/"),
    ],
)
def test_a_link_may_be_a_path_on_this_site_where_the_caller_allows(value, stored):
    assert external_url(value, allow_relative=True) == stored


@pytest.mark.parametrize(
    "value", ["/a", "//elsewhere.example/", "/.//elsewhere.example", "/%2e%2e/x"]
)
def test_only_absolute_links_are_kept_by_default_or_where_a_path_is_unsafe(value):
    with pytest.raises(ValueError, match="HTTP or HTTPS URL"):
        external_url(value)
    if value != "/a":
        with pytest.raises(ValueError):
            external_url(value, allow_relative=True)


@pytest.mark.parametrize(
    "value,path",
    [
        ("/account.html?tab=1", "/account.html?tab=1"),
        (" /x ", "/x"),
        (None, None),
        ("", None),
        ("x", None),
        ("//elsewhere.example", None),
        ("/https://elsewhere.example", None),
        ("/a\\b", None),
        ("/a\x7fb", None),
        ("/a\tb", None),
        ("/%2F%2Felsewhere.example", None),
        ("/%5Celsewhere.example", None),
        ("/a/../b", None),
        ("/./b", None),
        ("/a?next=../b", "/a?next=../b"),
    ],
)
def test_same_site_paths_cannot_become_another_sites(value, path):
    assert same_site_path(value) == path


# -- uploads ----------------------------------------------------------------


def test_uploads_keep_their_reader_and_name_what_they_lack():
    named = SimpleNamespace(
        filename="report.pdf", content_type="application/pdf", file=io.BytesIO(b"x")
    )
    bare = SimpleNamespace(filename="", content_type=None, file=io.BytesIO(b"y"))
    unreadable = SimpleNamespace(filename="z", content_type="text/plain", file=None)

    first, second = upload_inputs([named, bare, unreadable])

    assert (first.filename, first.content_type, first.read()) == (
        "report.pdf",
        "application/pdf",
        b"x",
    )
    assert (second.filename, second.content_type, second.read()) == (
        "attachment",
        "application/octet-stream",
        b"y",
    )
    assert isinstance(first, Upload)


def test_an_upload_is_measured_and_left_at_its_start():
    content = io.BytesIO(b"12345")
    content.seek(3)
    assert upload_size(content) == 5
    assert content.read() == b"12345"


# -- spreadsheet cells ------------------------------------------------------


@pytest.mark.parametrize(
    "value,cell",
    [
        ("plain", "plain"),
        ("=SUM(A1)", "'=SUM(A1)"),
        (" +1", "' +1"),
        ("﻿@cmd", "'﻿@cmd"),
        ("\tvalue", "'\tvalue"),
        ("a;=b", "a;'=b"),
        ("a\n  -b", "a\n  '-b"),
        (42, 42),
        (None, None),
    ],
)
def test_spreadsheet_cells_never_begin_a_formula(value, cell):
    assert spreadsheet_cell(value) == cell


# -- provider logs ----------------------------------------------------------


def test_provider_diagnostics_are_suppressed_at_the_emitting_logger(caplog):
    suppress_provider_logs("tests.provider.quiet")
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("tests.provider.quiet").warning("https://secret")
        logging.getLogger("tests.provider.loud").warning("kept")
    assert [r.getMessage() for r in caplog.records] == ["kept"]


# -- placeholders -----------------------------------------------------------


@pytest.mark.parametrize(
    "value,placeholder",
    [("<GENERATE>", True), (" <x> ", True), ("<>", True), ("<", False), ("pw", False)],
)
def test_placeholders_are_text_in_angle_brackets(value, placeholder):
    assert is_placeholder(value) is placeholder


# -- identifiers ------------------------------------------------------------


def test_an_identifier_has_two_spellings():
    value = uuid.uuid4()
    assert try_uuid(str(value)) == value
    assert try_uuid(value.hex.upper()) == value
    assert try_uuid(value) == value
    for other in (
        "{" + str(value) + "}",
        "urn:uuid:" + str(value),
        str(value).replace("-", "") + "-",
        "not-a-uuid",
    ):
        assert try_uuid(other) is None


# -- request text -----------------------------------------------------------


def test_text_is_trimmed_folded_and_bounded():
    assert text.clean_text("  a  ", max_len=5) == "a"
    assert text.clean_text(None, max_len=5) == ""
    assert text.clean_text(" a \n\n b ", max_len=5, single_line=True) == "a b"
    with pytest.raises(DomainError) as missing:
        text.clean_text(" ", max_len=5, required=True, label="Title")
    assert (missing.value.status_code, missing.value.detail) == (
        400,
        "Title is required",
    )
    with pytest.raises(DomainError) as long:
        text.clean_text("abcdef", max_len=5, label="Title")
    assert long.value.detail == "Title is too long"


def test_an_email_value_is_one_mailbox_or_nothing():
    assert text.clean_email(" a@example.org ") == "a@example.org"
    assert text.clean_email("  ") is None
    with pytest.raises(DomainError, match="email address is required"):
        text.clean_email(None, required=True)
    with pytest.raises(DomainError) as refused:
        text.clean_email("a@example.org, b@example.org", label="recipient")
    assert refused.value.detail == "Invalid recipient"


def test_filter_values_are_split_and_identifiers_checked():
    assert text.split_filter_values(" a, ,b ,") == ["a", "b"]
    assert text.split_filter_values(None) == []
    first, second = uuid.uuid4(), uuid.uuid4()
    assert text.uuid_filter_values(f"{first}, {second.hex}", label="ids") == [
        first,
        second,
    ]
    with pytest.raises(DomainError) as refused:
        text.uuid_filter_values(f"{first},nope", label="ids")
    assert refused.value.detail == "ids must contain UUID values"


# -- JSON shape -------------------------------------------------------------


def test_depth_counts_containers_and_stops_at_its_limits():
    assert json_shape.json_depth(1) == 0
    assert json_shape.json_depth({"a": [1, (2,)]}) == 3
    assert json_shape.json_depth([[[]]], limit=2) is None
    assert json_shape.json_depth([1, 2, 3], max_values=3) is None
    assert json_shape.json_depth([1, 2, 3], max_values=4) == 1


def test_values_are_bounded_without_decoding():
    assert json_shape.decodes_within("[1,2]", limit=3)
    assert not json_shape.decodes_within("[1,2]", limit=2)
    assert json_shape.decodes_within(b"{}", limit=2)
    assert not json_shape.decodes_within(b"[{},{}]", limit=4)


def test_a_document_nested_too_deeply_keeps_its_shallow_values():
    deep = "[" * 200_000 + "]" * 200_000
    document = '{"keep": "a\\"[{", "deep": ' + deep + ', "after": [1]}'
    decoded = json_shape.decode_json(document.encode())

    assert decoded["keep"] == 'a"[{'
    assert decoded["after"] == [1]
    level, depth = decoded["deep"], 2
    while isinstance(level, list):
        (level,) = level
        depth += 1
    assert (level, depth) == (json_shape.NESTED_TOO_DEEPLY, json_shape.MAX_DEPTH + 1)
    assert json_shape.decode_json(bytearray(b'{"a": 1}')) == {"a": 1}


def test_text_that_is_not_json_still_fails_as_json():
    with pytest.raises(json.JSONDecodeError):
        json_shape.decode_json("[" * 200_000)
    with pytest.raises(json.JSONDecodeError):
        json_shape.decode_json("[" * 200_000 + "}")
    with pytest.raises(json.JSONDecodeError):
        json_shape.decode_json("[" * 200_000 + "\\")
