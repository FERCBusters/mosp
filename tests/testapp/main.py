"""The test application assembled as an application assembles mosp: its
routes, middleware and error contract, plus a few routes of its own that
exercise the route policy."""

from fastapi import Depends, FastAPI, Request, WebSocket
from fastapi.exceptions import RequestValidationError

from mosp import middleware
from mosp.api.errors import domain_error_response, validation_error_response
from mosp.api.routes import account, api_tokens, auth, mfa, sso_emails
from mosp.api.routing import Router
from mosp.realtime import sockets
from mosp.security.auth import require_admin
from mosp.security.headers import SecurityHeadersMiddleware
from mosp.security.request_limits import RequestBodyLimitMiddleware
from mosp.services.errors import DomainError

own = Router()


@own.get("/v1/things")
def things(request: Request):
    return {"user": request.state.user.username}


@own.post("/v1/things")
def make_thing(request: Request):
    return {"made": True}


@own.post("/v1/notes/{note_id}")
def note(note_id: int, request: Request):
    return {"note": note_id}


@own.post("/v1/gated")
def gated():
    return {"gated": True}


@own.post("/v1/reports/run")
def report():
    return {"ran": True}


@own.get("/v1/admin/overview")
def overview():
    return {"admin": True}


PREFERENCES: dict[str, dict] = {}


@own.get("/v1/me")
def me(request: Request):
    return {"user": request.state.user.username}


@own.get("/v1/me/preferences")
def preferences(request: Request):
    return PREFERENCES.get(request.state.user.username, {"theme": "light"})


@own.api_route("/v1/me/preferences", methods=["PUT", "PATCH"])
def save_preferences(request: Request, changes: dict):
    saved = PREFERENCES.setdefault(request.state.user.username, {"theme": "light"})
    saved.update(changes)
    return saved


@own.get("/v1/users")
def users(user=Depends(require_admin)):
    return {"users": []}


@own.websocket("/ws/notifications")
async def notifications(websocket: WebSocket):
    await sockets.serve(websocket)


@own.get("/health")
def health():
    return {"ok": True}


app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    exception_handlers={
        DomainError: domain_error_response,
        RequestValidationError: validation_error_response,
    },
)
for router in (
    account.router,
    api_tokens.router,
    auth.router,
    mfa.router,
    sso_emails.router,
    own,
):
    app.include_router(router)
middleware.install(app)
app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

__all__ = ["app", "Depends"]
