import os

from pydantic_settings import SettingsConfigDict

from mosp.config import MospSettings


class Settings(MospSettings):
    model_config = SettingsConfigDict(env_prefix="TESTAPP_", case_sensitive=False)


settings = Settings(
    public_base_url="https://app.example",
    session_cookie_name="testapp_session",
    csrf_cookie_name="testapp_csrf",
    smtp_from_name="TestApp",
    database_url=os.environ.get(
        "MOSP_TEST_DATABASE_URL",
        "postgresql+psycopg2://mosp_test:mosp_test@127.0.0.1:5432/mosp_test",
    ),
)
