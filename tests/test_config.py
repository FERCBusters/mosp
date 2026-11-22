import pytest
from pydantic import ValidationError

from tests.testapp.config import Settings


def test_messages_name_the_application_environment_variables():
    with pytest.raises(ValidationError, match="TESTAPP_PUBLIC_BASE_URL is required"):
        Settings(public_base_url="")
    with pytest.raises(ValidationError, match="TESTAPP_TRUST_REMOTE_USER requires"):
        Settings(public_base_url="https://app.example", trust_remote_user=True)
    with pytest.raises(ValidationError, match="TESTAPP_PASSWORD_MIN_LENGTH below 15"):
        Settings(public_base_url="https://app.example", password_min_length=8)


def test_the_public_base_url_is_one_canonical_origin():
    assert Settings(public_base_url="https://APP.example/").public_base_url == (
        "https://app.example"
    )
    with pytest.raises(ValidationError):
        Settings(public_base_url="https://app.example/path")
