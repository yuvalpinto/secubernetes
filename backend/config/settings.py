from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    mongo_uri: str = Field(default="mongodb://app:apppass@localhost:27018/secubernetes?authSource=secubernetes")
    mongo_db: str = "secubernetes"

    model_config = SettingsConfigDict(
        env_prefix="SECUB_",
        env_file=".env",
        case_sensitive=False,
    )

settings = Settings()
