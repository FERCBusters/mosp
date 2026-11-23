# myf

myf ("My Framework") is the shared backend of KEEN, OSPMAE and MIDENA: the sign-in, session, single sign-on, second-factor, CSRF, role and permission machinery, the request middleware and the security primitives each of them runs on. It plays the part on the server that the MOSP Design System plays in the browser. An application built on myf holds only its own routes, services, models, migrations, permission catalogue and middleware.

## What myf provides

- **Sign-in and sessions** (`myf.security.auth`, `sessions`, `sign_in_throttle`, `myf.services.login`, `myf.api.routes.auth`): local passwords, LDAP and trusted remote-user sign-in; sessions stored in Valkey under the SHA-256 of their identifiers; `__Host-` cookies; the device-cookie sign-in throttle.
- **Second factors** (`myf.security.mfa`, `myf.services.mfa_management`, `myf.api.routes.mfa`): TOTP, WebAuthn security keys and passkeys, recovery codes and the pending-ceremony cookie.
- **Single sign-on** (`myf.security.oidc`, `sso_http`, `myf.services.sso_emails`): OpenID Connect, Google and GitHub for existing accounts only, linked through mailbox-proved addresses, with ID tokens verified under a configured list of asymmetric algorithms and providers reached through a bounded transport.
- **Browser boundaries** (`myf.security.csrf`, `headers`, `request_limits`): Origin checks, session-bound CSRF tokens, response headers, request-body limits, JSON shape limits, request-target checks and cookie screening.
- **Request middleware** (`myf.middleware`): CSRF, authentication and the request audit trail, installed together by `myf.middleware.install(app)`, and the first administrator of an empty installation (`bootstrap_initial_admin`).
- **Route policy** (`myf.security.route_policy`): which routes are public, which writes an account makes for itself, which writes need a permission (one per route, or one of several under a prefix), which namespaces only administrators reach, and which requests the audit trail leaves out. myf declares its own routes (`MYF_POLICY`); the application's `route_policy` hook returns a `RoutePolicy` holding its own, and the two apply together. A write the policy does not name needs an administrator.
- **Error contract and routing** (`myf.api.errors`, `routing`, `forms`): `Router` and `DomainRoute` give every route strict JSON decoding, form parsing off the event loop, and the same answers for domain, validation and database errors.
- **Roles and permissions** (`myf.security.roles`, `permissions`): effective roles from accounts and groups, permission checks with cached snapshots; the application supplies its permission catalogue.
- **Database** (`myf.db.engine`, `accounts`, `sql_trace`): an engine whose statements respect a worker task's deadline, the account model mixins, and SQL statement labels for tracing.
- **Primitives**: the regular-expression boundary (`regex`), untrusted XML (`xml`), redaction (`redaction`), client addresses and per-address allowances (`client_ip`, `rate_limit`), passwords (`passwords`), email addresses (`myf.core.email_address`), identifiers, rich text and CSV output, task deadlines and SQL statement labels.
- **Mail and notices** (`myf.services.mailer`, `security_notifications`): SMTP delivery, calendar invitations and the security notices sent to account owners.
- **Worker** (`myf.worker`, `myf.services.audit_retention`): `myf.worker.connect(celery_app, sql_trace=...)` gives each task its deadline and, when tracing, its statement labels; `remove_expired` keeps the audit trail to its retention period.

## Using myf in an application

An application depends on myf by commit, as it depends on the MOSP Design System:

```toml
[tool.poetry.dependencies]
myf = { git = "https://github.com/FERCBusters/myf.git", rev = "<commit>" }
```

It binds itself once, in its package's `__init__`, before anything imports myf's modules:

```python
import myf.host

myf.host.bind(
    name="keen",  # store keys, cookie names, <NAME>_ environment variables
    title="Keen",  # the application's name in messages and emails
    config="app.core.config",  # a module with `settings`, an instance of a MyfSettings subclass
    models="app.db.models",  # the application's models (see "Models" below)
    db="app.db.session",  # a module with `SessionLocal` and `get_db`
    hooks="app.myf_hooks",  # the application's hooks (see myf/host/hooks.py)
)
```

Its settings class subclasses `myf.config.MyfSettings`, sets its own `env_prefix` and adds its own fields; its own checks across fields go in an override of `check_application`, which ends by calling the base class's. Hooks (`myf/host/hooks.py`) are where myf asks the application to take part: its route policy, whether a session still stands, what happens when an account is created, dependencies every route takes, body and JSON limits per route, its permission implications, the tokens it issues for redaction, measured fields redaction keeps, its own security notices, the pages its browser interface serves, and how it authenticates requests of its own (such as an MCP tool's). A hook an application leaves out keeps myf's default.

The application's `main` includes myf's routers (`myf.api.routes.auth`, `mfa`, `sso_emails`) beside its own, then calls `myf.middleware.install(app)`; it creates its engine with `myf.db.engine.application_engine` and connects its Celery app with `myf.worker.connect`.

### Models

myf reads the application's account models by name: `User`, `Group`, `Permission`, `UserIdentity`, `OidcLoginState`, `MfaCredential`, `MfaRecoveryCode`, `MfaChallenge`, `UserLoginIP`, `SecurityNotification`, `UserSsoEmail`, `SsoEmailChallenge`, `AuditLog`, and the `user_groups`, `user_permissions` and `group_permissions` tables. `myf.db.accounts` supplies a mixin for each model and `association_tables(metadata)` for the tables; an application declares `class User(Base, UserMixin)` and adds its own columns. The application owns these tables and their migrations.

## Development

The suite runs against PostgreSQL, each test module in a schema of its own, with an in-memory Valkey. Create the database with the collation CI's PostgreSQL image uses, so text sorts as it does there:

```bash
createdb --template=template0 --encoding=UTF8 --lc-collate=en_US.UTF-8 --lc-ctype=en_US.UTF-8 --owner=myf_test myf_test
```

```bash
poetry install
export MYF_TEST_DATABASE_URL=postgresql+psycopg2://myf_test:myf_test@127.0.0.1:5432/myf_test
poetry run pytest --cov=myf --cov-branch --cov-fail-under=100
poetry run ruff check . && poetry run ruff format --check . && poetry run mypy
```

myf's own suite binds a small test application (`tests/testapp`) that assembles myf as an application does, with a few routes of its own for the route policy, and covers every branch of myf: sign-in, sessions, second factors, single sign-on, directories, permissions, the middleware and the primitives. Each application's suite also runs myf's flows through its own routes and hooks.

`AGENTS.md` describes how to change myf safely; `SECURITY.md` describes how to report a vulnerability.

## Licence

Apache License 2.0; see `LICENSE`.
