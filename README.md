# myf

myf ("My Framework") is the shared backend of KEEN, OSPMAE and MIDENA: the sign-in, session, single sign-on, second-factor, CSRF, role and permission machinery, the request middleware and the security primitives each of them runs on. It plays the part on the server that the MOSP Design System plays in the browser. An application built on myf holds only its own routes, services, models, migrations, permission catalogue and middleware.

## What myf provides

- **Sign-in and sessions** (`myf.security.auth`, `sessions`, `sign_in_throttle`, `myf.services.login`, `myf.api.routes.auth`): local passwords, LDAP and trusted remote-user sign-in; sessions stored in Valkey under the SHA-256 of their identifiers; `__Host-` cookies; the device-cookie sign-in throttle.
- **Second factors** (`myf.security.mfa`, `myf.services.mfa_management`, `myf.api.routes.mfa`): TOTP, WebAuthn security keys and passkeys, recovery codes and the pending-ceremony cookie.
- **Single sign-on** (`myf.security.oidc`, `sso_http`, `myf.services.sso_emails`): OpenID Connect, Google and GitHub for existing accounts only, linked through mailbox-proved addresses, with ID tokens verified under a configured list of asymmetric algorithms and providers reached through a bounded transport.
- **Browser boundaries** (`myf.security.csrf`, `headers`, `request_limits`): Origin checks, session-bound CSRF tokens, response headers, request-body limits, JSON shape limits, request-target checks and cookie screening.
- **Roles and permissions** (`myf.security.roles`, `permissions`): effective roles from accounts and groups, permission checks with cached snapshots; the application supplies its permission catalogue.
- **Primitives**: the regular-expression boundary (`regex`), untrusted XML (`xml`), redaction (`redaction`), client addresses and per-address allowances (`client_ip`, `rate_limit`), passwords (`passwords`), email addresses (`myf.core.email_address`), identifiers, rich text and CSV output, task deadlines and SQL statement labels.
- **Mail and notices** (`myf.services.mailer`, `security_notifications`): SMTP delivery, calendar invitations and the security notices sent to account owners.

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

Its settings class subclasses `myf.config.MyfSettings`, sets its own `env_prefix` and adds its own fields. Hooks (`myf/host/hooks.py`) are where myf asks the application to take part: whether a session still stands, what happens when an account is created, the route class for myf's routers, body limits per route, its permission implications, the tokens it issues for redaction, and its own security notices. A hook an application leaves out keeps myf's default.

### Models

myf reads the application's account models by name: `User`, `Group`, `Permission`, `UserIdentity`, `OidcLoginState`, `MfaCredential`, `MfaRecoveryCode`, `MfaChallenge`, `UserLoginIP`, `SecurityNotification`, `UserSsoEmail`, `SsoEmailChallenge`, `AuditLog`, the `user_groups`, `user_permissions` and `group_permissions` tables, and the columns KEEN's versions of them hold. The application owns these tables and their migrations.

## Development

```bash
poetry install
poetry run pytest
poetry run ruff check . && poetry run ruff format --check . && poetry run mypy
```

myf's own suite binds a small test application (`tests/testapp`) and covers the binding, hooks, settings and stateless primitives. The flows that need an application's database (sign-in, sessions, second factors, single sign-on, permissions) are exercised end to end by each application's suite; KEEN's runs them with branch coverage of myf.

`AGENTS.md` describes how to change myf safely; `SECURITY.md` describes how to report a vulnerability.

## Licence

Apache License 2.0; see `LICENSE`.
