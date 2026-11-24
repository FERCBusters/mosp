# MOSP

[![Coverage](https://github.com/FERCBusters/mosp/raw/badges/coverage.svg)](https://github.com/FERCBusters/mosp/actions/workflows/tests.yml?query=branch%3Amain)
[![mypy](https://github.com/FERCBusters/mosp/raw/badges/mypy.svg)](https://github.com/FERCBusters/mosp/actions/workflows/tests.yml?query=branch%3Amain)
[![ruff](https://github.com/FERCBusters/mosp/raw/badges/ruff.svg)](https://github.com/FERCBusters/mosp/actions/workflows/tests.yml?query=branch%3Amain)

MOSP is the shared backend of KEEN, OSPMAE and MIDENA: the sign-in, session, single sign-on, second-factor, CSRF, role and permission machinery, the request middleware and the security primitives each of them runs on. It plays the part on the server that the MOSP Design System plays in the browser. An application built on mosp holds only its own routes, services, models, migrations, permission catalogue and middleware.

## What MOSP provides

- **Sign-in and sessions** (`mosp.security.auth`, `sessions`, `sign_in_throttle`, `mosp.services.login`, `mosp.api.routes.auth`): local passwords, LDAP and trusted remote-user sign-in; sessions stored in Valkey under the SHA-256 of their identifiers; `__Host-` cookies; the device-cookie sign-in throttle; account names free of control, format and line-break characters; the page checks nginx's `auth_request` reads, which name the account in a header (percent-encoded outside printable ASCII).
- **The account's own password** (`mosp.services.account`, `mosp.api.routes.account`): `POST /v1/me/password`, limited per address and per account, ending every session of the account however it was opened, and every browser's recognition.
- **Second factors** (`mosp.security.mfa`, `mosp.services.mfa_management`, `mosp.api.routes.mfa`): TOTP, WebAuthn security keys and passkeys, recovery codes, the pending-ceremony cookie, and an operator's reset of an account that has lost its factors or been taken over (`mfa.operator_reset`), which ends every session and, for an account that can sign in without SSO, also removes its SSO identities and linking addresses; for one that signs in only through SSO, the operator can name the identity to keep (`keep_identity`), and every other SSO identity and linking address goes, or, where none is the owner's, give an address confirmed with the owner (`link_address`), which replaces every SSO identity and linking address so the owner's next verified sign-in links again.
- **Single sign-on** (`mosp.security.oidc`, `sso_http`, `mosp.services.sso_emails`): OpenID Connect, Google and GitHub for existing accounts only, linked through mailbox-proved addresses; the account holder is told of each identity linked, sees the linked identities (`GET /v1/me/sso-identities`) and can remove any that is not the account's only way to sign in (`POST /v1/me/sso-identities/remove`); removing one also removes the address it was linked through and ends every session. ID tokens are verified under a configured list of asymmetric algorithms, and providers are reached through a bounded transport.
- **Browser boundaries** (`mosp.security.csrf`, `headers`, `request_limits`): Origin checks, session-bound CSRF tokens, response headers (with a sandboxing `default-src 'none'` CSP on every response that sets none of its own), request-body limits, JSON shape limits, request-target checks and cookie screening.
- **Request middleware** (`mosp.middleware`): CSRF, authentication and the request audit trail, installed together by `mosp.middleware.install(app)`, and the first administrator of an empty installation (`bootstrap_initial_admin`).
- **Route policy** (`mosp.security.route_policy`): which routes are public, which writes an account makes for itself, which writes need a permission (one per route, or one of several under a prefix), which namespaces and writes only administrators reach (with any routes in those namespaces that check a permission themselves), and which requests the audit trail leaves out. mosp declares its own routes (`MOSP_POLICY`); the application's `route_policy` hook returns a `RoutePolicy` holding its own, and the two apply together. A write the policy does not name needs an administrator, or is refused for everyone when the application sets `refuse_undeclared_writes`.
- **Error contract and routing** (`mosp.api.errors`, `routing`, `forms`): `Router` and `DomainRoute` give every route strict JSON decoding, form parsing off the event loop, and the same answers for domain, validation and database errors.
- **Roles and permissions** (`mosp.security.roles`, `permissions`): effective roles from accounts and groups, permission checks with cached snapshots; the application supplies its permission catalogue.
- **Database** (`mosp.db.engine`, `accounts`, `sql_trace`): an engine whose statements respect a worker task's deadline, the account model mixins, and SQL statement labels for tracing.
- **Notification sockets** (`mosp.realtime`): a signed-in browser's WebSocket, its Origin and handshake allowance checked and its account re-read on a schedule (`sockets.serve`), fanned out across processes through Valkey.
- **Primitives**: the regular-expression boundary (`regex`), untrusted XML with an optional strict mode and a caller's size bound (`xml`), allowlist SVG sanitising under the same bound (`svg`), stored links and same-site paths (`urls`), redaction (`redaction`), client addresses and per-address allowances (`client_ip`, `rate_limit`), passwords (`passwords`), email addresses (`mosp.core.email_address`), identifiers, rich text and CSV output, task deadlines and SQL statement labels.
- **Mail and notices** (`mosp.services.mailer`, `security_notifications`): SMTP delivery, calendar invitations and the security notices sent to account owners.
- **Worker** (`mosp.worker`, `mosp.services.audit_retention`, `housekeeping`): `mosp.worker.connect(celery_app, sql_trace=...)` gives each task its deadline and, when tracing, its statement labels; `audit_retention.remove_expired` keeps the audit trail to its retention period, and `housekeeping.remove_expired` removes expired sign-in states, second-factor challenges and SSO address proofs.

## Using MOSP in an application

An application depends on MOSP by commit, just as it depends on the MOSP Design System:

```toml
[tool.poetry.dependencies]
mosp = { git = "https://github.com/FERCBusters/mosp.git", rev = "<commit>" }
```

It binds itself once, in its package's `__init__`, before anything imports mosp's modules:

```python
import mosp.host

mosp.host.bind(
    name="keen",  # store keys, cookie names, <NAME>_ environment variables
    title="Keen",  # the application's name in messages and emails
    config="app.core.config",  # a module with `settings`, an instance of a MospSettings subclass
    models="app.db.models",  # the application's models (see "Models" below)
    db="app.db.session",  # a module with `SessionLocal` and `get_db`
    hooks="app.mosp_hooks",  # the application's hooks (see mosp/host/hooks.py)
)
```

Its settings class subclasses `mosp.config.MospSettings`, sets its own `env_prefix` and adds its own fields; its own checks across fields go in an override of `check_application`, which ends by calling the base class's. Hooks (`mosp/host/hooks.py`) are where MOSP asks the application to take part: its route policy, whether a session still stands, what happens when an account is created, dependencies every route takes, body and JSON limits per route, its permission implications, the tokens it issues for redaction, measured fields redaction keeps, its own security notices, the pages its browser interface serves, what its paths carry that the audit trail masks, and how it authenticates requests of its own (such as an MCP tool's). A hook an application leaves out keeps MOSP's default.

The application's `main` includes MOSP's routers (`mosp.api.routes.account`, `auth`, `mfa`, `sso_emails`) beside its own, then calls `mosp.middleware.install(app)`; it creates its engine with `mosp.db.engine.application_engine` and connects its Celery app with `mosp.worker.connect`.

### Models

MOSP reads the application's account models by name: `User`, `Group`, `Permission`, `UserIdentity`, `OidcLoginState`, `MfaCredential`, `MfaRecoveryCode`, `MfaChallenge`, `UserLoginIP`, `SecurityNotification`, `UserSsoEmail`, `SsoEmailChallenge`, `AuditLog`, and the `user_groups`, `user_permissions` and `group_permissions` tables. `mosp.db.accounts` supplies a mixin for each model and `association_tables(metadata)` for the tables; an application declares `class User(Base, UserMixin)` and adds its own columns. The application owns these tables and their migrations. A user's `login_key` (the digest of the name sign-in compares, which finds an account's namesakes by an indexed read) is set whenever its username is assigned through the ORM; a migration or script that writes `users` rows directly sets it with `mosp.security.names.login_key`.

## Development

The suite runs against PostgreSQL, each test module in a schema of its own, with an in-memory Valkey. Create the database with the collation CI's PostgreSQL image uses, so text sorts as it does there:

```bash
createdb --template=template0 --encoding=UTF8 --lc-collate=en_US.UTF-8 --lc-ctype=en_US.UTF-8 --owner=mosp_test mosp_test
```

```bash
poetry install
export MOSP_TEST_DATABASE_URL=postgresql+psycopg2://mosp_test:mosp_test@127.0.0.1:5432/mosp_test
poetry run pytest --cov=mosp --cov-branch --cov-fail-under=100
poetry run ruff check . && poetry run ruff format --check . && poetry run mypy
```

MOSP's own suite binds a small test application (`tests/testapp`) that assembles MOSP as an application does, with a few routes of its own for the route policy, and covers every branch of MOSP: sign-in, sessions, second factors, single sign-on, directories, permissions, the middleware and the primitives. Each application's suite also runs MOSP's flows through its own routes and hooks.

When MOSP CI passes on a push to main, the bump workflow (`.github/workflows/bump-dependants.yml`) proposes the new commit to KEEN, MIDENA and OSPMAE: a pull request in each that uses MOSP moves its pin and lock file, and that application's CI decides it. The workflow needs a GitHub App installed on all four repositories (its header says which settings).

MOSP's own suite covers every branch, so coverage cannot show code that no application uses. `tools/unused_by_apps.py` can: it follows each application's references to MOSP through MOSP's own calls, and lists what none of them reaches, what only one of them reaches, methods whose name nothing uses and hooks no application provides. Given coverage data from the applications' suites run with `--cov=mosp` against the same checkout, it also lists reachable code none of them ran. Its findings are candidates to read, not to delete unread:

```bash
poetry run python tools/unused_by_apps.py --tests tests \
  keen=../keen/services/api/app keen=../keen/services/api/scripts keen=../keen/services/api/alembic \
  midena=../midena/services/api/app midena=../midena/services/api/scripts midena=../midena/services/api/alembic \
  --coverage ../keen-mosp.coverage --coverage ../midena-mosp.coverage
```

`AGENTS.md` describes how to change MOSP safely; `SECURITY.md` describes how to report a vulnerability.

## Licence

Apache License 2.0; see `LICENSE`.
