"""Request bodies of mosp's routes."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from mosp.security.names import login_name


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(max_length=1024)
    method: str = Field(default="local", pattern="^(local|ldap)$")

    @field_validator("username")
    @classmethod
    def require_username(cls, value: str) -> str:
        # A username with nothing visible in it names no account and would
        # share one rate-limit allowance with every other blank name.
        if not login_name(value):
            raise ValueError("Enter a username")
        return value


class ChangePasswordPayload(BaseModel):
    current_password: str = Field(max_length=1024)
    # The password rules refuse a long new password with their own message;
    # the request body limit bounds what is read.
    new_password: str
