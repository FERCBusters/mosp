"""Self-service, proof-of-ownership addresses for automatic SSO linking."""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from mosp.api.context import change_context
from mosp.api.routing import Router
from mosp.host.db import get_db
from mosp.security.auth import cookie_name as session_cookie_name
from mosp.security.auth import require_authenticated
from mosp.services import sso_emails as service
from mosp.services.sso_emails import Address, Proof

router = Router()


@router.get("/v1/me/sso-emails")
def list_addresses(user=Depends(require_authenticated), db: Session = Depends(get_db)):
    return service.list_addresses(user=user, db=db)


@router.post("/v1/me/sso-emails/request")
def request_address(
    payload: Address,
    request: Request,
    user=Depends(require_authenticated),
    db: Session = Depends(get_db),
):
    return service.request_address(
        payload=payload,
        context=change_context(request),
        user=user,
        db=db,
        session_id=request.cookies.get(session_cookie_name(), ""),
    )


@router.post("/v1/me/sso-emails/confirm")
def confirm_address(
    payload: Proof,
    request: Request,
    user=Depends(require_authenticated),
    db: Session = Depends(get_db),
):
    return service.confirm_address(
        payload=payload, context=change_context(request), user=user, db=db
    )


@router.post("/v1/me/sso-emails/remove")
def remove_address(
    payload: Address,
    request: Request,
    user=Depends(require_authenticated),
    db: Session = Depends(get_db),
):
    return service.remove_address(
        payload=payload,
        context=change_context(request),
        user=user,
        db=db,
        session_id=request.cookies.get(session_cookie_name(), ""),
    )
