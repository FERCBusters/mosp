"""Bound request bodies and screen request targets and cookies before handlers
see them."""

import re
import tempfile

import anyio
from starlette.responses import JSONResponse

from mosp.host import hooks
from mosp.security.regex import scan_pattern


def target_has_nul(scope) -> bool:
    """PostgreSQL text cannot hold NUL, so no path or query value may carry one."""
    query = scope.get("query_string") or b""
    return "\x00" in scope.get("path", "") or b"%00" in query or b"\x00" in query


_ENCODED_SEPARATOR = scan_pattern(rb"%(?:2f|5c)", re.IGNORECASE)


def target_traverses(scope) -> bool:
    """Whether a request target could name another route than it appears to.

    A path parameter that carries an encoded "/" or "../" decodes into extra
    segments. Browser pages build API paths from record identifiers and query
    values, so such a target would let a crafted link send the page's own
    authenticated request to a different route. No API path has a "." or ".."
    segment, and only routes with a ``:path`` parameter take an encoded slash.
    """
    path = scope.get("path", "")
    if any(segment in {".", ".."} for segment in path.split("/")):
        return True
    raw = scope.get("raw_path") or path.encode()
    routes = hooks.encoded_slash_routes()
    return bool(_ENCODED_SEPARATOR.search(raw)) and not (
        routes is not None and routes.fullmatch(path)
    )


def _named_plainly(pair: bytes) -> bool:
    name = pair.split(b"=", 1)[0]
    # Printable ASCII, with the spaces and tabs allowed around a name.
    return all(0x20 <= byte <= 0x7E or byte == 0x09 for byte in name)


def screen_cookies(scope) -> None:
    """Drop cookies whose names hold bytes outside printable ASCII.

    A cookie name is an ASCII token. The framework reads the Cookie header as
    Latin-1 text and strips each name of everything Python counts as white
    space, which includes the bytes 0x85 and 0xA0 and some control
    characters. A cookie named with one of those before or after
    ``__Host-<name>_session`` would so be read as the application's own session cookie,
    although a browser applies the ``__Host-`` rule, which keeps a site on a
    sibling subdomain from setting that cookie, only to the exact name. Such
    pairs are removed from the header before anything reads it, for HTTP
    requests and WebSockets alike.
    """
    headers = scope.get("headers") or []
    if any(key.lower() == b"cookie" for key, _ in headers):
        scope["headers"] = [
            (
                key,
                b";".join(pair for pair in value.split(b";") if _named_plainly(pair))
                if key.lower() == b"cookie"
                else value,
            )
            for key, value in headers
        ]


class RequestBodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            screen_cookies(scope)
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = hooks.body_limit(scope["path"])

        async def reject(status, message):
            await JSONResponse(
                {"detail": message},
                status_code=status,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)

        if target_has_nul(scope) or target_traverses(scope):
            return await reject(400, "Invalid request target")

        for key, value in scope.get("headers", []):
            if key.lower() == b"content-length":
                if not value.isdigit():
                    return await reject(400, "Invalid Content-Length")
                if len(value) > 10 or int(value) > limit:
                    return await reject(413, "Request body too large")

        # Spool larger uploads to disk. Do not dispatch a partial request: a
        # handler must never commit data before an oversized tail is rejected.
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as body:
            total = 0
            try:
                with anyio.fail_after(30):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        chunk = message.get("body", b"")
                        total += len(chunk)
                        if total > limit:
                            return await reject(413, "Request body too large")
                        if chunk:
                            await anyio.to_thread.run_sync(body.write, chunk)
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                return await reject(408, "Request body timeout")
            body.seek(0)
            remaining = total
            complete = False

            async def replay():
                nonlocal remaining, complete
                if complete:
                    return await receive()
                chunk = await anyio.to_thread.run_sync(body.read, 64 * 1024)
                remaining -= len(chunk)
                complete = remaining == 0
                return {
                    "type": "http.request",
                    "body": chunk,
                    "more_body": not complete,
                }

            await self.app(scope, replay, send)
