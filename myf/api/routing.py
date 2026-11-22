"""Routers for myf's routes, built with the application's route class."""

from fastapi import APIRouter

from myf.host import hooks


class Router(APIRouter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("route_class", hooks.route_class())
        super().__init__(*args, **kwargs)
