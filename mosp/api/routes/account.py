"""The signed-in account's own password."""

from __future__ import annotations

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from mosp.api.context import change_context
from mosp.api.routing import Router
from mosp.api.schemas import ChangePasswordPayload
from mosp.host.db import get_db
from mosp.services import account as service

router = Router()


@router.post("/v1/me/password")
def change_password(
    payload: ChangePasswordPayload, request: Request, db: Session = Depends(get_db)
):
    return service.change_password(
        payload=payload, context=change_context(request), db=db
    )
