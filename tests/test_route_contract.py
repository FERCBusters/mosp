"""Every route's error contract and body parsing (mosp.api.errors and
mosp.api.forms), on a router of its own as an application mounts one."""

import asyncio
import json
import logging

import pytest
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy.exc import DataError

from mosp.api import errors
from mosp.api.errors import (
    decode_json_body,
    domain_error_response,
    json_object,
    validation_error_response,
)
from mosp.api.forms import parse_form
from mosp.api.routing import Router
from mosp.services.errors import DomainError

JSON = {"Content-Type": "application/json"}


class Payload(BaseModel):
    name: str
    count: int = 0


def _app():
    router = Router()

    @router.post("/model")
    def model(payload: Payload):
        return payload.model_dump()

    @router.post("/object")
    async def obj(request: Request):
        return await json_object(request)

    @router.post("/twice")
    async def twice(request: Request):
        first = await request.json()
        return {"same": first is await request.json()}

    @router.get("/domain")
    def domain():
        raise DomainError(status_code=409, detail="Taken", headers={"X-Why": "1"})

    class Orig(Exception):
        pass

    @router.get("/data")
    def data():
        raise DataError("INSERT ...", {"secret": 1}, Orig("value out of range"))

    @router.get("/overflow")
    def overflow():
        raise OverflowError("date value out of range")

    @router.post("/form")
    def form(name: str = Form(), upload: UploadFile = File()):
        return {"name": name, "file": upload.filename, "body": upload.file.read()}

    @router.post("/fields")
    async def fields(request: Request):
        first = await request.form()
        again = await request.form()
        return {"fields": dict(first), "same": first is again}

    app = FastAPI(
        exception_handlers={
            DomainError: domain_error_response,
            RequestValidationError: validation_error_response,
        }
    )
    app.include_router(router)
    return TestClient(app)


@pytest.fixture(scope="module")
def client():
    with _app() as client:
        yield client


def test_a_domain_error_keeps_its_status_detail_and_headers(client):
    response = client.get("/domain")
    assert (response.status_code, response.json()) == (409, {"detail": "Taken"})
    assert response.headers["x-why"] == "1"


def test_a_domain_error_outside_a_route_has_the_same_answer():
    response = asyncio.run(
        domain_error_response(None, DomainError(status_code=404, detail="Gone"))
    )
    assert (response.status_code, json.loads(response.body)) == (
        404,
        {"detail": "Gone"},
    )


def test_a_value_the_database_refuses_is_named_without_its_values(client, caplog):
    with caplog.at_level(logging.WARNING, logger="mosp.api.errors"):
        response = client.get("/data")
    assert (response.status_code, response.json()) == (
        400,
        {"detail": "A request value cannot be stored"},
    )
    assert [r.getMessage() for r in caplog.records] == [
        "Database rejected a request value: Orig"
    ]


def test_arithmetic_out_of_range_is_a_bad_request(client, caplog):
    with caplog.at_level(logging.WARNING, logger="mosp.api.errors"):
        response = client.get("/overflow")
    assert (response.status_code, response.json()) == (
        400,
        {"detail": "A request value is out of range"},
    )
    assert [r.getMessage() for r in caplog.records] == [
        "Request value out of range in /overflow"
    ]


def test_validation_errors_name_fields_without_echoing_values(client):
    response = client.post(
        "/model", content=b'{"name": 5, "count": "password-123"}', headers=JSON
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert [item["loc"] for item in detail] == [["body", "name"], ["body", "count"]]
    assert "password-123" not in response.text
    assert set(detail[0]) == {"type", "loc", "msg"}


@pytest.mark.parametrize(
    "body,status,detail",
    [
        (b"{", 400, "Request body must be valid JSON"),
        (b'{"name": NaN}', 400, "Request body must be valid JSON"),
        (b'{"name": "a", "count": 1e999}', 400, "Request body must be valid JSON"),
        (b"[" * 65 + b"]" * 65, 400, "Request body is nested too deeply"),
    ],
)
def test_bodies_that_are_not_standard_storable_json_are_refused(
    client, body, status, detail
):
    response = client.post("/model", content=body, headers=JSON)
    assert (response.status_code, response.json()) == (status, {"detail": detail})


def test_the_application_bounds_body_size_and_value_count(client, hook):
    hook(json_body_limit=lambda path: 20, json_value_limit=lambda path: 3)
    large = client.post(
        "/model", content=b'{"name": "' + b"a" * 30 + b'"}', headers=JSON
    )
    assert (large.status_code, large.json()) == (
        413,
        {"detail": "Request body too large"},
    )
    many = client.post("/object", content=b"[1, 2, 3, 4]", headers=JSON)
    assert (many.status_code, many.json()) == (
        413,
        {"detail": "Request body holds too many values"},
    )


def test_nul_characters_become_replacement_characters(client):
    response = client.post("/model", content=b'{"name": "a\\u0000b"}', headers=JSON)
    assert response.json() == {"name": "a�b", "count": 0}


def test_a_handler_reading_the_body_gets_one_object_once(client):
    assert client.post("/object", json={"a": 1}).json() == {"a": 1}
    refused = client.post("/object", json=[1])
    assert (refused.status_code, refused.json()) == (
        400,
        {"detail": "Request body must be a JSON object"},
    )
    assert client.post("/twice", json={"a": 1}).json() == {"same": True}


def test_decoding_alone_needs_no_value_limit():
    assert decode_json_body(b"[1, 2.5, 3]") == [1, 2.5, 3]
    with pytest.raises(HTTPException):
        decode_json_body(b"Infinity")


def test_the_application_adds_its_route_dependencies_once(hook):
    calls = []

    def enforced():
        calls.append("enforced")

    hook(route_dependencies=lambda: (enforced,))
    router = Router()

    @router.get("/plain")
    def plain():
        return {}

    from fastapi import Depends

    @router.get("/declared", dependencies=[Depends(enforced)])
    def declared():
        return {}

    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as test:
        test.get("/plain")
        test.get("/declared")
    assert calls == ["enforced", "enforced"]


# -- forms --------------------------------------------------------------------


def test_a_multipart_form_is_parsed_with_its_files(client, hook):
    hook(body_limit=lambda path: 4 * 1024 * 1024)
    response = client.post(
        "/form",
        data={"name": "report"},
        files={"upload": ("r.txt", b"x" * (2 * 1024 * 1024), "text/plain")},
    )
    assert response.status_code == 200
    assert (response.json()["name"], response.json()["file"]) == ("report", "r.txt")
    assert len(response.json()["body"]) == 2 * 1024 * 1024


def test_an_urlencoded_form_is_parsed_once(client):
    response = client.post("/fields", data={"a": "1", "b": "2"})
    assert response.json() == {"fields": {"a": "1", "b": "2"}, "same": True}


def test_another_body_type_is_an_empty_form(client):
    response = client.post(
        "/fields", content=b"a=1", headers={"Content-Type": "text/plain"}
    )
    assert response.json() == {"fields": {}, "same": True}


def test_a_malformed_multipart_body_is_a_bad_request(client):
    response = client.post(
        "/fields",
        content=b"--x\r\nContent-Disposition: form-data\r\n\r\nv\r\n--x--\r\n",
        headers={"Content-Type": "multipart/form-data; boundary=x"},
    )
    assert response.status_code == 400


def test_form_limits_apply():
    async def receive_once():
        return {
            "type": "http.request",
            "body": b"a=1&b=2&c=3",
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        },
        receive_once,
    )
    with pytest.raises(HTTPException) as refused:
        asyncio.run(parse_form(request, max_fields=2))
    assert refused.value.status_code == 400


def test_a_form_is_held_to_the_body_limit_without_the_middleware(hook):
    # An application that reads forms without installing
    # RequestBodyLimitMiddleware still has each form bounded by its route's
    # limit, before more of the body is written to the spool.
    hook(body_limit=lambda path: 8)
    chunks = [b"a=1&b=2", b"&c=3", b"&d=4"]
    read = []

    async def receive():
        chunk = chunks.pop(0)
        read.append(chunk)
        return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}

    def form_request():
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1/upload",
                "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
            },
            receive,
        )

    with pytest.raises(HTTPException) as refused:
        asyncio.run(parse_form(form_request()))
    assert (refused.value.status_code, refused.value.detail) == (
        413,
        "Request body too large",
    )
    assert read == [b"a=1&b=2", b"&c=3"]
    # A form within the limit is parsed.
    chunks[:] = [b"a=1&b=2"]
    assert dict(asyncio.run(parse_form(form_request()))) == {"a": "1", "b": "2"}


def test_the_module_logs_under_its_own_name():
    assert errors.logger.name == "mosp.api.errors"
