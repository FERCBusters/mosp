"""The assembled test application: requests pass through mosp's middleware,
real password sign-in, CSRF, session storage and permission resolution."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from mosp.security.passwords import hash_password

BASE = "https://app.example"
PASSWORD = "synthetic-password-for-tests"


class Site:
    def __init__(self, db, store, monkeypatch):
        self.db = db
        self.store = store
        # Settings a test changes for the site are restored after it.
        self.monkeypatch = monkeypatch

    @classmethod
    def serve(cls, db, store, monkeypatch):
        from mosp import middleware
        from tests.testapp import db as database
        from tests.testapp.config import settings
        from tests.testapp.main import app

        factory = sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            join_transaction_mode="create_savepoint",
        )

        def session():
            with factory() as s:
                yield s

        monkeypatch.setattr(middleware, "SessionLocal", factory)
        monkeypatch.setattr(database, "SessionLocal", factory)
        app.dependency_overrides[database.get_db] = session
        monkeypatch.setattr(settings, "public_base_url", BASE)
        monkeypatch.setattr(settings, "trust_remote_user", False)
        monkeypatch.setattr(settings, "mfa_policy", "optional")
        monkeypatch.setattr(settings, "local_auth_enabled", True)
        try:
            yield cls(db, store, monkeypatch)
        finally:
            app.dependency_overrides.clear()

    def user(self, *codes, role="normal"):
        from tests.testapp.models import Permission, User

        row = User(
            username="user-" + uuid.uuid4().hex[:10],
            password_hash=hash_password(PASSWORD),
            role=role,
            is_active=True,
        )
        self.db.add(row)
        for code in codes:
            permission = self.db.query(Permission).filter_by(code=code).one_or_none()
            if permission is None:
                permission = Permission(code=code, description=code)
                self.db.add(permission)
            row.permissions.append(permission)
        self.db.commit()
        return row

    def client(self, user=None):
        from tests.testapp.main import app

        client = TestClient(app, base_url=BASE, raise_server_exceptions=False)
        if user is not None:
            response = client.post(
                "/v1/auth/login",
                json={"username": user.username, "password": PASSWORD},
                headers={"Origin": BASE},
            )
            assert response.status_code == 200, response.text
        return client


def unsafe(client):
    return {"Origin": BASE, "X-CSRF-Token": client.cookies.get("__Host-testapp_csrf")}
