"""Settings mosp's modules read, as a base class for an application's own.

An application's settings class subclasses ``MospSettings``, sets its own
``env_prefix`` and adds its own fields; mosp reads the bound instance through
``mosp.host.config``. Validation messages name each setting by the
application's own environment variable.
"""

from __future__ import annotations

import ipaddress

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings


def _env(owner, name: str) -> str:
    """The environment variable for setting ``name`` of a settings class."""
    return f"{owner.model_config.get('env_prefix', '')}{name}"


class MospSettings(BaseSettings):
    @model_validator(mode="after")
    def validate_application(self):
        """Run the application's own cross-field checks before mosp's."""
        self.check_application()
        return self

    def check_application(self) -> None:
        """The application's cross-field checks, run before mosp's own.

        An application overrides this when one of its checks explains a
        configuration better than mosp's would, for example a deployment
        profile that forbids a whole sign-in method. Raise ``ValueError``.
        """

    # Optional first-run credentials. Importing settings must also work for
    # migrations, workers and existing installations without bootstrap secrets.
    # Validate credentials at account creation, after checking the user database.
    bootstrap_admin_username: str = Field(default="")
    bootstrap_admin_password: str = Field(default="")

    # Days the audit trail keeps request and action records. The worker deletes
    # older records in short batches (mosp.services.audit_retention); 0 keeps
    # them indefinitely.
    audit_log_retention_days: int = Field(default=400, ge=0, le=36500)

    # Bearer API tokens (mosp.security.api_tokens): another application's
    # reads as one account. Off, no token is accepted or issued, whatever the
    # application declares; tokens already issued are kept and can be revoked.
    api_tokens_enabled: bool = Field(default=False)

    # Diagnostics: label each SQL statement with the request or task that ran
    # it (mosp.db.sql_trace). Leave off in normal operation.
    sql_trace: bool = Field(default=False)

    # Cookie-backed sessions stored in Valkey/Redis
    session_cookie_name: str = Field(default="session")
    session_ttl_seconds: int = Field(default=60 * 60 * 24 * 7)  # 7 days
    # Absolute lifetime from sign-in, whatever the session's use (30 days).
    session_max_age_seconds: int = Field(default=60 * 60 * 24 * 30, ge=300)

    # Cookie settings - secure by default for production
    cookie_secure: bool = Field(default=True)
    cookie_samesite: str = Field(default="strict")  # lax|strict|none
    cookie_domain: str = Field(default="")

    # Local username/password login. Disable this when native OIDC is the only
    # allowed interactive login path.
    local_auth_enabled: bool = Field(default=True)
    ldap_enabled: bool = False
    ldap_url: str = "ldaps://localhost:636"
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    # Search below this DN; set it to an OU DN to restrict access to that OU.
    ldap_base_dn: str = ""
    ldap_username_attribute: str = "uid"
    ldap_email_attribute: str = "mail"
    ldap_id_attribute: str = "entryUUID"
    ldap_user_filter: str = "(objectClass=person)"
    # Optional: sign-in also needs a group matching this filter to list the
    # user. For directories that record membership on the group entry.
    ldap_group_filter: str = ""
    ldap_group_base_dn: str = ""
    ldap_group_member_attribute: str = "member"
    ldap_ca_cert_path: str = ""
    ldap_timeout_seconds: int = Field(default=5, ge=1, le=30)
    ldap_auto_provision: bool = True

    mfa_policy: str = Field(default="optional")
    mfa_encryption_key: str = Field(default="", repr=False)

    @field_validator("mfa_policy")
    @classmethod
    def validate_mfa_policy(cls, value):
        if value not in {"optional", "admins", "all"}:
            raise ValueError("MFA policy must be optional, admins or all")
        return value

    # Characters a new local password needs. NIST SP 800-63B-4 asks for 15
    # where a password can be an account's only factor, and allows as few as
    # eight where every account also uses a second factor.
    password_min_length: int = Field(default=15, ge=8, le=128)

    @model_validator(mode="after")
    def validate_password_min_length(self):
        if self.password_min_length < 15 and self.mfa_policy != "all":
            raise ValueError(
                f"{_env(self, 'PASSWORD_MIN_LENGTH')} below 15 requires "
                f"{_env(self, 'MFA_POLICY')}=all"
            )
        return self

    # Trusted proxy auth (REMOTE_USER)
    # When enabled, an upstream reverse proxy can authenticate a user and pass
    # their username via a header (default: REMOTE_USER). If present, this
    # identity overrides the cookie-backed session.
    #
    # IMPORTANT: Only enable this if you have a trusted proxy that strips any
    # client-supplied REMOTE_USER header and injects its own. Native OIDC ignores
    # REMOTE_USER even if this is accidentally enabled.
    trust_remote_user: bool = Field(default=False)
    remote_user_header_name: str = Field(default="REMOTE_USER")
    # The authenticating proxies whose identity header the application accepts, as
    # comma-separated addresses or CIDRs. This is a separate list from
    # <PREFIX>SECURITY_TRUSTED_PROXY_CIDRS: a hop trusted to forward client
    # addresses is not thereby trusted to name the signed-in account. Required
    # while <PREFIX>TRUST_REMOTE_USER is on; there is no default.
    remote_user_trusted_cidrs: str = Field(default="")

    @field_validator("remote_user_trusted_cidrs", "security_trusted_proxy_cidrs")
    @classmethod
    def validate_proxy_networks(cls, value):
        """Each comma-separated entry is an address or network."""
        for entry in value.split(","):
            if entry.strip():
                ipaddress.ip_network(entry.strip())
        return value

    @model_validator(mode="after")
    def validate_remote_user_trust(self):
        if self.trust_remote_user and not self.remote_user_trusted_cidrs.strip(", "):
            raise ValueError(
                f"{_env(self, 'TRUST_REMOTE_USER')} requires "
                f"{_env(self, 'REMOTE_USER_TRUSTED_CIDRS')}: "
                "the addresses of the proxies that authenticate users"
            )
        return self

    # -----------------------------------------------------------------------------
    # Native generic OpenID Connect relying party
    # -----------------------------------------------------------------------------
    oidc_enabled: bool = Field(default=False)
    oidc_provider_label: str = Field(default="Single sign-on")
    oidc_authorization_endpoint: str = Field(default="")
    oidc_token_endpoint: str = Field(default="")
    oidc_token_endpoint_auth_method: str = Field(default="client_secret_basic")
    oidc_jwks_uri: str = Field(default="")
    oidc_issuer: str = Field(default="")
    oidc_userinfo_endpoint: str = Field(default="")
    oidc_client_id: str = Field(default="")
    oidc_client_secret: str = Field(default="")
    oidc_scopes: str = Field(default="openid email profile")
    oidc_redirect_uri: str = Field(default="")
    oidc_end_session_endpoint: str = Field(default="")
    oidc_post_logout_redirect_uri: str = Field(default="")
    oidc_id_token_leeway_seconds: int = Field(default=60)
    oidc_username_claims: str = Field(default="preferred_username,email")
    oidc_allowed_email_domains: str = Field(default="")
    oidc_auto_link_existing: bool = Field(default=True)
    # Present for deployment parity with Statistics, but intentionally unsupported
    # by Keen's OIDC resolver because Keen must not auto-register users.
    oidc_auto_provision: bool = Field(default=False)
    oidc_allowed_algs: str = Field(default="RS256")
    oidc_allow_insecure_http: bool = Field(default=False)

    # Google OpenID Connect
    google_sso_enabled: bool = Field(default=False)
    google_provider_label: str = Field(default="Google")
    google_authorization_endpoint: str = Field(
        default="https://accounts.google.com/o/oauth2/v2/auth"
    )
    google_token_endpoint: str = Field(default="https://oauth2.googleapis.com/token")
    google_jwks_uri: str = Field(default="https://www.googleapis.com/oauth2/v3/certs")
    google_issuer: str = Field(
        default="https://accounts.google.com,accounts.google.com"
    )
    google_userinfo_endpoint: str = Field(
        default="https://openidconnect.googleapis.com/v1/userinfo"
    )
    google_client_id: str = Field(default="")
    google_client_secret: str = Field(default="")
    google_scopes: str = Field(default="openid email profile")
    google_redirect_uri: str = Field(default="")
    google_end_session_endpoint: str = Field(default="")
    google_post_logout_redirect_uri: str = Field(default="")
    google_auto_provision: bool = Field(default=False)
    google_auto_link_existing: bool = Field(default=True)
    google_allowed_email_domains: str = Field(default="")
    google_username_claims: str = Field(default="email")

    # GitHub OAuth
    github_sso_enabled: bool = Field(default=False)
    github_provider_label: str = Field(default="GitHub")
    github_authorization_endpoint: str = Field(
        default="https://github.com/login/oauth/authorize"
    )
    github_token_endpoint: str = Field(
        default="https://github.com/login/oauth/access_token"
    )
    github_user_endpoint: str = Field(default="https://api.github.com/user")
    github_emails_endpoint: str = Field(default="https://api.github.com/user/emails")
    github_issuer: str = Field(default="https://github.com/login/oauth")
    github_client_id: str = Field(default="")
    github_client_secret: str = Field(default="")
    github_scopes: str = Field(default="read:user user:email")
    github_redirect_uri: str = Field(default="")
    github_auto_provision: bool = Field(default=False)
    github_auto_link_existing: bool = Field(default=True)
    github_allowed_email_domains: str = Field(default="")

    # CSRF (double-submit cookie)
    # - Token is stored in a non-HttpOnly cookie so the UI can echo it in a header.
    # - For unsafe methods, the API requires the header value to match the cookie.
    # - With Secure cookies and no cookie domain the name takes the __Host-
    #   prefix (security/csrf.py); the UI reads that cookie first.
    csrf_cookie_name: str = Field(default="csrf")
    csrf_header_name: str = Field(default="X-CSRF-Token")
    csrf_cookie_samesite: str = Field(default="strict")  # lax|strict|none

    # Public base URL (required): the browser-facing origin, without a path.
    # Absolute links in emails, notifications and outbound webhook messages are
    # built from it, and browser Origin checks compare against it.
    # Example: https://keen.example.com
    public_base_url: str = Field(default="", validate_default=True)

    @field_validator("public_base_url")
    @classmethod
    def validate_public_base_url(cls, v: str) -> str:
        from urllib.parse import urlsplit

        value = (v or "").strip().rstrip("/")
        if not value:
            raise ValueError(
                f"{_env(cls, 'PUBLIC_BASE_URL')} is required: set it to the "
                "browser-facing origin, for example https://app.example.com"
            )
        try:
            parts = urlsplit(value)
            parts.port  # Rejects a malformed port.
        except ValueError:
            parts = None
        if (
            parts is None
            or parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.path
            or parts.query
            or parts.fragment
            or any(ord(c) < 33 or ord(c) == 127 or c == "\\" for c in value)
        ):
            raise ValueError(
                f"{_env(cls, 'PUBLIC_BASE_URL')} must be an http:// or https:// "
                "origin without a path, query or credentials, for example "
                "https://app.example.com"
            )
        return f"{parts.scheme}://{parts.netloc.lower()}"

    # SMTP outbound mail
    # -----------------------------------------------------------------------------
    security_trusted_proxy_cidrs: str = Field(default="")

    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=587)
    smtp_username: str = Field(default="")
    smtp_password: str = Field(default="")
    smtp_use_tls: bool = Field(default=True)  # STARTTLS
    smtp_use_ssl: bool = Field(default=False)  # SMTPS (465)
    smtp_timeout_seconds: int = Field(default=20)
    smtp_from_email: str = Field(default="")
    smtp_from_name: str = Field(default="")

    # Database / broker
    database_url: str = Field(default="")
    redis_url: str = Field(default="redis://localhost:6379/0")

    # -----------------------------------------------------------------------------
    # Login rate limiting (Valkey/Redis)
    # -----------------------------------------------------------------------------
    # Simple fixed-window rate limiting applied to /v1/auth/login.
    # These are defense-in-depth; a reverse proxy should still enforce limits.
    login_rate_limit_window_seconds: int = Field(default=300)  # 5 minutes
    login_rate_limit_per_ip: int = Field(default=30)
    # Password changes each account may attempt per login window, whatever
    # address they come from, so a session holder cannot test many current
    # passwords by spreading attempts across addresses.
    password_change_rate_limit_per_account: int = Field(default=15)
