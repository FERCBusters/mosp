# Working on myf

myf holds what KEEN, OSPMAE and MIDENA share. A change here reaches all three, so every change keeps or strengthens each property the applications rely on; none may weaken one to suit a single application.

## What belongs in myf

- Sign-in, sessions, second factors, single sign-on, CSRF and Origin checks, request limits, roles and the permission mechanism, mail delivery, security notices and the security primitives.
- Nothing that names one application's routes, models, permissions or vocabulary. Where myf needs an application's knowledge (route body limits, permission implications, tokens it issues, its own notices), it asks through a hook in `myf/host/hooks.py` with a safe default.
- Store keys, cookie names, environment-variable names and product names come from the host binding (`myf.host.name()`, `title()`, `env()`), never from literals.

## Changing myf

- Read the module and its callers in each application before editing. Keep each module's behaviour identical unless the change makes it stronger; record a deliberate difference beside the code.
- A second copy of a helper in an application is a defect. Applications import from myf; myf never imports an application except through `myf.host`.
- Regular expressions compile through `myf.security.regex.scan_pattern`; untrusted XML parses through `myf.security.xml`; client addresses come from `myf.security.client_ip` and per-address allowances from `myf.security.rate_limit`.
- Add a hook only with a default that keeps myf safe when an application leaves it out, and document it in `myf/host/hooks.py`.
- Add tests to myf's own suite for anything that runs without an application database, and run KEEN's suite (which covers myf with branch coverage) before proposing a change that touches sign-in, sessions, second factors, single sign-on or permissions.

## Validation

- `poetry run pytest`, `poetry run ruff format --check .`, `poetry run ruff check .` and `poetry run mypy` pass.
- KEEN's `tests.sh` passes with myf at the proposed commit, and so do OSPMAE's and MIDENA's suites once they depend on myf.

## Releasing

Applications pin myf by commit. After a change lands, update each application's `myf` revision and lock file in its own pull request, run its full suite and review its security checklist.

Write documentation in present tense and British English.
