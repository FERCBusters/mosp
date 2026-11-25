"""The account tables mosp reads, as mixins for an application's own models.

An application declares each model from its mixin on its own declarative
base, adding columns and relationships of its own, and creates the three
association tables on its metadata::

    user_groups, user_permissions, group_permissions = association_tables(
        Base.metadata
    )

    class User(Base, UserMixin):
        pref_theme: Mapped[str] = mapped_column(String(32), default="ink")

The application owns these tables and their migrations; the mixins fix the
columns mosp relies on.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import (
    Mapped,
    declared_attr,
    mapped_column,
    relationship,
    validates,
)

from mosp.core.datetime_utils import utc_now_naive as utcnow
from mosp.security.names import login_key


def association_tables(metadata: MetaData) -> tuple[Table, Table, Table]:
    """The user-group, user-permission and group-permission tables."""

    def link(name: str, left: str, right: str) -> Table:
        return Table(
            name,
            metadata,
            Column(
                f"{left}_id",
                UUID(as_uuid=True),
                ForeignKey(f"{left}s.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            Column(
                f"{right}_id",
                UUID(as_uuid=True),
                ForeignKey(f"{right}s.id", ondelete="CASCADE"),
                primary_key=True,
            ),
        )

    return (
        link("user_groups", "user", "group"),
        link("user_permissions", "user", "permission"),
        link("group_permissions", "group", "permission"),
    )


class UserMixin:
    __tablename__ = "users"
    # Lets the request-scoped attributes below be annotated without mapping them.
    __allow_unmapped__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    # security.rate_limit.login_key of the username, set with it: the accounts
    # a name compares equal to are found without reading every username.
    login_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_backend: Mapped[str] = mapped_column(
        String(16), nullable=False, default="local", server_default="local"
    )
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    session_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    mfa_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    mfa_totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_totp_last_step: Mapped[int] = mapped_column(
        Integer, nullable=False, default=-1, server_default="-1"
    )
    # Wrong TOTP and recovery codes since mfa_code_failures_since, across
    # sign-ins; see security/mfa.py.
    mfa_code_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    mfa_code_failures_since: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # One of: admin | normal
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="normal")

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )
    # Bumped whenever RBAC/role-related state changes for this user.
    # The value is loaded with the user row and compared to the session snapshot,
    # so permission caching remains invalidatable without querying permission joins
    # on every request.
    authz_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Request-scoped authorisation state: session authentication attaches the
    # session's snapshot (revalidated against authz_version) and sign-in attaches
    # the effective role. Never persisted.
    effective_role: str | None = None
    # What a password sign-in proved, read with the row the password was
    # checked against (auth.credential_generation); the session is issued only
    # while the account still matches it.
    verified_credential: tuple[str, int, int] | None = None
    effective_permission_codes: set[str] | None = None
    # A connection acting for the account under granted scopes (an MCP
    # client's, say) counts those scopes for their own domains only: it holds
    # the codes in effective_permission_codes and none they imply
    # (security.permissions.has_permission), and an application's own checks
    # that let one domain's permission stand in for another's refuse it.
    scope_limited: bool = False
    session_id: str | None = None
    session_authz_version: int | None = None

    @validates("username")
    def _keep_login_key(self, _key: str, username: str) -> str:
        self.login_key = login_key(username)
        return username

    # The CSRF token issued with the session, when it has one (security/csrf.py).
    session_csrf: str | None = None

    @declared_attr
    def groups(cls):
        return relationship("Group", secondary="user_groups", back_populates="users")

    @declared_attr
    def permissions(cls):
        return relationship(
            "Permission", secondary="user_permissions", back_populates="users"
        )

    @declared_attr
    def identities(cls):
        return relationship(
            "UserIdentity", back_populates="user", cascade="all, delete-orphan"
        )


class GroupMixin:
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional role assigned to this group. When a user has role='inherit',
    # their effective role is resolved from group roles.
    # One of: admin | normal | NULL
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    @declared_attr
    def users(cls):
        return relationship("User", secondary="user_groups", back_populates="groups")

    @declared_attr
    def permissions(cls):
        return relationship(
            "Permission", secondary="group_permissions", back_populates="groups"
        )


class PermissionMixin:
    __tablename__ = "permissions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    code: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False, index=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    @declared_attr
    def users(cls):
        return relationship(
            "User", secondary="user_permissions", back_populates="permissions"
        )

    @declared_attr
    def groups(cls):
        return relationship(
            "Group", secondary="group_permissions", back_populates="permissions"
        )


class UserIdentityMixin:
    __tablename__ = "user_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False, default="oidc")
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    preferred_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claims: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )

    @declared_attr
    def user(cls):
        return relationship("User", back_populates="identities")

    @declared_attr.directive
    def __table_args__(cls):
        return (
            UniqueConstraint(
                "issuer", "subject", name="uq_user_identities_issuer_subject"
            ),
        )


class OidcLoginStateMixin:
    __tablename__ = "oidc_login_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    state: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    code_verifier: Mapped[str] = mapped_column(Text, nullable=False)
    next_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )


class MfaCredentialMixin:
    __tablename__ = "mfa_credentials"
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    credential_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MfaRecoveryCodeMixin:
    __tablename__ = "mfa_recovery_codes"
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)


class MfaChallengeMixin:
    __tablename__ = "mfa_challenges"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    password_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class UserLoginIPMixin:
    __tablename__ = "user_login_ips"
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    address: Mapped[str] = mapped_column(String(45), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )


class SsoEmailChallengeMixin:
    __tablename__ = "sso_email_challenges"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(256), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    mfa_version: Mapped[int] = mapped_column(Integer, nullable=False)
    password_digest: Mapped[str] = mapped_column(String(64), nullable=False)


class SecurityNotificationMixin:
    __tablename__ = "security_notifications"
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    recipient: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(100), nullable=True)

    @declared_attr.directive
    def __table_args__(cls):
        return (
            Index("ix_security_notifications_pending", "status", "next_attempt_at"),
        )


class UserSsoEmailMixin:
    """Addresses whose ownership the application has verified for SSO linking."""

    __tablename__ = "user_sso_emails"
    email: Mapped[str] = mapped_column(String(256), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    verified_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=utcnow
    )


class ApiTokenMixin:
    """Bearer tokens an administrator issues for one account, for another
    application's reads (``mosp.security.api_tokens``).

    Optional: an application that declares no ``ApiToken`` model accepts no
    API token. Only the token's SHA-256 digest is kept, so a copy of the
    database authenticates nothing; ``hint`` holds its last four characters,
    which tell tokens apart in a listing.
    """

    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    hint: Mapped[str] = mapped_column(String(8), nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLogMixin:
    """The request audit trail (``mosp.middleware``)."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )

    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    query_string: Mapped[str | None] = mapped_column(Text, nullable=True)

    status_code: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    referer: Mapped[str | None] = mapped_column(String(512), nullable=True)
