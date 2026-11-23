# Working on MOSP 

MOSP holds what KEEN, OSPMAE and MIDENA share. A change here reaches all three, so every change keeps or strengthens each property the applications rely on; none may weaken one to suit a single application.

## What belongs in MOSP 

- Sign-in, sessions, second factors, single sign-on, CSRF and Origin checks, request limits, roles and the permission mechanism, mail delivery, security notices and the security primitives.
- Nothing that names one application's routes, models, permissions or vocabulary. Where MOSP needs an application's knowledge (its route policy, route body limits, permission implications, tokens it issues, its own notices, its pages), it asks through a hook in `mosp/host/hooks.py` with a safe default.
- Store keys, cookie names, environment-variable names and product names come from the host binding (`mosp.host.name()`, `title()`, `env()`), never from literals.

## Changing MOSP

- Read the module and its callers in each application before editing. Keep each module's behaviour identical unless the change makes it stronger; record a deliberate difference beside the code.
- A second copy of a helper in an application is a defect. Applications import from MOSP; MOSP never imports an application except through `mosp.host`.
- Regular expressions compile through `mosp.security.regex.scan_pattern`; untrusted XML parses through `mosp.security.xml`; client addresses come from `mosp.security.client_ip` and per-address allowances from `mosp.security.rate_limit`.
- Add a hook only with a default that keeps MOSP safe when an application leaves it out, and document it in `mosp/host/hooks.py`.
- Every change comes with tests in MOSP's own suite, which keeps full branch coverage of `mosp`. A flow that needs an account or a route runs through the test application (`tests/testapp`, `tests/assembled.py`); a hook's effect is tested with the `hook` fixture. Run KEEN's suite too before proposing a change that touches sign-in, sessions, second factors, single sign-on, permissions or the middleware.

## Validation

- `poetry run pytest --cov=mosp --cov-branch --cov-fail-under=100` (with `MOSP_TEST_DATABASE_URL` naming a PostgreSQL database), `poetry run ruff format --check .`, `poetry run ruff check .` and `poetry run mypy` pass.
- KEEN's `tests.sh` passes with MOSP at the proposed commit, and so do OSPMAE's and MIDENA's suites once they depend on MOSP.

## Releasing

Applications pin MOSP by commit. After a change lands, update each application's `mosp` revision and lock file in its own pull request, run its full suite and review its security checklist.

Write documentation in present tense and British English.
