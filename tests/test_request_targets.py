"""A request target names one route: encoded separators cannot reach another.

Browser pages build API paths from record identifiers and query values, and
send them with the page's session and CSRF token. A path parameter carrying an
encoded "/" or "../" that some proxy decodes and resolves would turn such a
request into one for a different route. The supplied nginx forwards the API
target as the browser sent it, and the API refuses any target with a "." or
".." segment, or an encoded slash outside a ``:path`` parameter.
"""

import re

import pytest

from mosp.security.request_limits import target_traverses
from tests.assembled import unsafe


def _scope(raw: bytes):
    from urllib.parse import unquote

    return {"type": "http", "path": unquote(raw.decode()), "raw_path": raw}


@pytest.mark.parametrize(
    "raw",
    [
        # The reported link: a quiz round id that climbs to another route.
        b"/v1/me/quizzes/rounds/..%2F..%2F..%2Fadmin%2Fusers%2FU1%2Fpassword/attempt",
        b"/v1/pestle/items/..%2Fadmin%2Fgroups%2Fg1",
        b"/v1/sources/%2e%2e%2Fme",
        b"/v1/sources/x%2Fy/insights",
        b"/v1/sources/x%5Cy/insights",
        b"/v1/./me",
        b"/v1/sources/../me",
    ],
)
def test_traversing_targets_are_recognised(raw):
    assert target_traverses(_scope(raw))


@pytest.mark.parametrize(
    "raw",
    [
        b"/v1/me",
        b"/v1/sources/site-agent/insights",
        b"/v1/sources/a.b..c/insights",
    ],
)
def test_ordinary_targets_pass(raw):
    assert not target_traverses(_scope(raw))


def test_an_application_names_the_routes_that_take_an_encoded_slash(hook):
    raw = b"/v1/frameworks/iso/nodes/A%2F1"
    assert target_traverses(_scope(raw))
    hook(encoded_slash_routes=lambda: re.compile(r"/v1/frameworks/[^/]+/nodes/.+"))
    assert not target_traverses(_scope(raw))
    assert target_traverses(_scope(b"/v1/other/A%2F1"))


@pytest.mark.parametrize(
    "path",
    [
        "/v1/me/quizzes/rounds/..%2F..%2F..%2Fme%2Finbox%2Fread-all/attempt",
        "/v1/sources/..%2Fme",
        "/v1/sources/%2e%2e%2Fme",
    ],
)
def test_the_application_refuses_them_before_authentication(
    site,
    path,
):
    client = site.client(site.user())
    assert client.get("/v1/me").status_code == 200
    response = client.post(path, headers=unsafe(client))
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid request target"}
    refused = client.get(path)
    assert (refused.status_code, refused.json()) == (
        400,
        {"detail": "Invalid request target"},
    )
