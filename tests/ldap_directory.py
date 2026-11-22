"""A fake LDAP directory for the sign-in tests."""

from types import SimpleNamespace

import fakeredis
import pytest
from ldap3.operation.bind import bind_operation

from myf.security import ldap
from tests.testapp.config import settings


@pytest.fixture
def directory(monkeypatch):
    for key, value in dict(
        ldap_enabled=True,
        ldap_url="ldap://directory.example:389",
        ldap_base_dn="ou=People,dc=example",
        ldap_bind_dn="cn=reader,dc=example",
        ldap_bind_password="search-secret",
        ldap_username_attribute="uid",
        ldap_email_attribute="mail",
        ldap_id_attribute="entryUUID",
        ldap_auto_provision=True,
        ldap_group_filter="",
        ldap_group_base_dn="",
        ldap_group_member_attribute="member",
    ).items():
        monkeypatch.setattr(settings, key, value)
    events = []
    connections = []
    state = {
        "tls": True,
        "bind": True,
        "entries": [
            SimpleNamespace(
                entry_dn="uid=alice,ou=People,dc=example",
                entry_attributes_as_dict={
                    "uid": ["alice"],
                    "mail": ["alice@example.org"],
                    "entryUUID": ["immutable-id"],
                },
            )
        ],
    }

    class FakeConnection:
        def __init__(self, server, **kw):
            self.kw = kw
            self.closed = True
            self.result = {"result": 0}
            connections.append(self)

        def open(self):
            self.closed = False
            events.append("open")

        def start_tls(self):
            events.append("tls")
            return state["tls"]

        def bind(self):
            events.append(("bind", self.kw["user"]))
            if "sent" in state:
                # Build the request as ldap3 does, so its own preparation of
                # the password runs, and keep the bytes it would send.
                request = bind_operation(
                    3, ldap.SIMPLE, self.kw["user"], self.kw["password"]
                )
                state["sent"].append(bytes(request["authentication"]["simple"]))
            if self.kw["user"].startswith("uid=") and not state["bind"]:
                self.result = {"result": 49}
                return False
            if not self.kw["user"].startswith("uid=") and "service_bind" in state:
                self.result = {"result": state["service_bind"]}
                return False
            if self.kw["user"].startswith("uid=") and "user_bind" in state:
                self.result = {"result": state["user_bind"]}
                return False
            return True

        def search(self, base, query, **kw):
            state.setdefault("searched_as", []).append(self.kw["user"])
            if kw["attributes"] == ldap.NO_ATTRIBUTES:
                # The group lookup asks for no attributes.
                state["group_search"] = (base, query, kw)
                self.entries = state.get("groups", [])
                self.result = {"result": state.get("group_result", 0)}
                return True
            state["search"] = (base, query, kw)
            self.entries = state["entries"]
            self.result = {"result": state.get("result", 0)}
            return True

        def unbind(self):
            events.append("unbind")

    monkeypatch.setattr(ldap, "Connection", FakeConnection)
    # Each test counts directory-entry attempts in its own store.
    store = fakeredis.FakeRedis()
    monkeypatch.setattr(ldap, "get_valkey", lambda: store)
    return state, events, connections
