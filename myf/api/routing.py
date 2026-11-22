"""Routers built with myf's route class (``myf.api.errors.DomainRoute``)."""

from fastapi import APIRouter

from myf.api.errors import DomainRoute


class Router(APIRouter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("route_class", DomainRoute)
        super().__init__(*args, **kwargs)
