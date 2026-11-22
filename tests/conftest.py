import os
import uuid

import fakeredis
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

import myf.host

# Settings built in tests need the public origin the application requires.
os.environ.setdefault("TESTAPP_PUBLIC_BASE_URL", "http://testserver")

myf.host.bind(
    name="testapp",
    title="TestApp",
    config="tests.testapp.config",
    models="tests.testapp.models",
    db="tests.testapp.db",
    hooks="tests.testapp.hooks",
)

BASE = "https://app.example"


@pytest.fixture
def hook(monkeypatch):
    """Install application hooks for one test."""
    from tests.testapp import hooks

    def install(**functions):
        for name, function in functions.items():
            monkeypatch.setattr(hooks, name, function, raising=False)

    return install


def schema_engine(url, schema, **options):
    """An engine whose every connection selects the test's private schema."""
    engine = create_engine(url, **options)

    @event.listens_for(engine, "connect")
    def select_schema(connection, _record):
        if not schema.replace("_", "").isalnum():
            raise ValueError("Invalid test schema")
        with connection.cursor() as cursor:
            cursor.execute(f'SET search_path TO "{schema}"')
            cursor.execute("SET TIME ZONE 'UTC'")
        connection.commit()

    return engine


@pytest.fixture(scope="module")
def schema_engine_for_module():
    """A private PostgreSQL schema holding the test application's tables."""
    from tests.testapp import models  # noqa: F401 - registers the tables
    from tests.testapp.config import settings
    from tests.testapp.db import Base

    url = settings.database_url
    schema = "myf_" + uuid.uuid4().hex
    admin = create_engine(url, poolclass=NullPool)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = schema_engine(url, schema)
    try:
        Base.metadata.create_all(engine)
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def db(schema_engine_for_module):
    """A session whose work, committed or not, is rolled back after the test."""
    with schema_engine_for_module.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(
                bind=connection,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            ) as session:
                yield session
        finally:
            transaction.rollback()


@pytest.fixture
def valkey(monkeypatch):
    """A private in-memory Valkey for the test."""
    from myf.core import valkey as store

    server = fakeredis.FakeServer()

    class FakeValkey:
        @staticmethod
        def from_url(*args, **kwargs):
            return fakeredis.FakeRedis(server=server, decode_responses=True)

    store.get_valkey.cache_clear()
    monkeypatch.setattr(store, "Redis", FakeValkey)
    yield store.get_valkey()
    store.get_valkey.cache_clear()


@pytest.fixture
def site(db, valkey, monkeypatch):
    """The test application on the test's database and Valkey, with helpers
    to create accounts and sign them in."""
    from tests.assembled import Site

    yield from Site.serve(db, valkey, monkeypatch)


@pytest.fixture
def production_client(db, monkeypatch):
    """The assembled test application with an administrator and a reader,
    sessions in a private in-memory Valkey."""
    from fastapi.testclient import TestClient

    from myf import middleware
    from myf.security import auth, permissions
    from tests.testapp.config import settings
    from tests.testapp.main import app
    from tests.testapp.models import User

    redis = fakeredis.FakeRedis(decode_responses=True)
    admin = User(
        username="security-admin", password_hash="unused", role="admin", is_active=True
    )
    reader = User(
        username="security-reader",
        password_hash="unused",
        role="normal",
        is_active=True,
    )
    db.add_all([admin, reader])
    db.commit()
    factory = sessionmaker(
        bind=db.get_bind(),
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    monkeypatch.setattr(middleware, "SessionLocal", factory)
    monkeypatch.setattr(auth, "get_valkey", lambda: redis)
    monkeypatch.setattr(permissions, "get_valkey", lambda: redis)
    monkeypatch.setattr(settings, "public_base_url", BASE)
    monkeypatch.setattr(settings, "trust_remote_user", False)
    monkeypatch.setattr(settings, "mfa_policy", "optional")
    client = TestClient(app, base_url=BASE)
    yield client, redis, admin, reader
    client.close()
