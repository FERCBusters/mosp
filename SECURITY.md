# Security policy

myf is the shared backend of KEEN, OSPMAE and MIDENA, so a vulnerability in myf is a vulnerability in each of them. Each application's SECURITY.md describes its security model and threat model; myf's modules implement the parts of those models the applications share: sign-in, sessions, second factors, single sign-on, CSRF and Origin checks, request limits, roles and permissions, redaction and the security primitives.

## Reporting a vulnerability

Please report suspected vulnerabilities through this project's GitHub repository. Prefer **Security → Advisories → Report a vulnerability** for a private report. If private reporting is unavailable, open an issue asking for a private reporting channel and keep exploit details, credentials and sensitive data out of the public issue.

Every report must include a reproducible proof of concept demonstrating the issue: the myf commit, the application and its configuration, the attacker's required access, minimal reproduction steps, expected and actual results, and evidence of the security impact. Test on an installation you own or have explicit permission to assess.

Our goal is to provide a preliminary response within **72 hours**. myf offers **no monetary bounties**. Authors of validated reports are credited, using their preferred name or handle, unless they request anonymity. We coordinate disclosure with reporters, and with the applications that depend on myf, after assessing impact and remediation.
