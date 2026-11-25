"""The test application's account tables, built from mosp's mixins."""

from mosp.db.accounts import (
    ApiTokenMixin,
    AuditLogMixin,
    GroupMixin,
    MfaChallengeMixin,
    MfaCredentialMixin,
    MfaRecoveryCodeMixin,
    OidcLoginStateMixin,
    PermissionMixin,
    SecurityNotificationMixin,
    SsoEmailChallengeMixin,
    UserIdentityMixin,
    UserLoginIPMixin,
    UserMixin,
    UserSsoEmailMixin,
    association_tables,
)
from tests.testapp.db import Base

user_groups, user_permissions, group_permissions = association_tables(Base.metadata)


class User(Base, UserMixin):
    __allow_unmapped__ = True


class Group(Base, GroupMixin):
    pass


class Permission(Base, PermissionMixin):
    pass


class UserIdentity(Base, UserIdentityMixin):
    pass


class OidcLoginState(Base, OidcLoginStateMixin):
    pass


class MfaCredential(Base, MfaCredentialMixin):
    pass


class MfaRecoveryCode(Base, MfaRecoveryCodeMixin):
    pass


class MfaChallenge(Base, MfaChallengeMixin):
    pass


class UserLoginIP(Base, UserLoginIPMixin):
    pass


class SecurityNotification(Base, SecurityNotificationMixin):
    pass


class UserSsoEmail(Base, UserSsoEmailMixin):
    pass


class SsoEmailChallenge(Base, SsoEmailChallengeMixin):
    pass


class AuditLog(Base, AuditLogMixin):
    pass


class ApiToken(Base, ApiTokenMixin):
    pass
