from pydantic_settings import SettingsConfigDict

from myf.config import MyfSettings


class Settings(MyfSettings):
    model_config = SettingsConfigDict(env_prefix="TESTAPP_", case_sensitive=False)


settings = Settings(public_base_url="https://app.example")
