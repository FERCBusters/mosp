"""Administrators' API tokens (``mosp.services.api_tokens``).

An application that accepts API tokens includes this router; the route
policy keeps ``/v1/admin/api-tokens`` to administrators, and each route checks
the role again.
"""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from mosp.api.context import change_context
from mosp.api.routing import Router
from mosp.host.db import get_db
from mosp.security.auth import require_admin
from mosp.services import api_tokens as service
from mosp.services.api_tokens import ApiTokenPayload

router = Router()


@router.get("/v1/admin/api-tokens")
def list_api_tokens(_=Depends(require_admin), db: Session = Depends(get_db)):
    return service.list_tokens(db)


@router.post("/v1/admin/api-tokens", status_code=201)
def issue_api_token(
    payload: ApiTokenPayload,
    request: Request,
    actor=Depends(require_admin),
    db: Session = Depends(get_db),
):
    return service.issue_token(
        db, payload=payload, actor=actor, context=change_context(request)
    )


@router.post("/v1/admin/api-tokens/{token_id}/revoke")
def revoke_api_token(
    token_id: str,
    request: Request,
    actor=Depends(require_admin),
    db: Session = Depends(get_db),
):
    return service.revoke_token(
        db, token_id=token_id, actor=actor, context=change_context(request)
    )
