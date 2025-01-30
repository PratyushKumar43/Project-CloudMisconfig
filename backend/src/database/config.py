from functools import lru_cache
import os
from typing import Optional
from pydantic_settings import BaseSettings

class DatabaseSettings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./aws_config.db"
    TEST_DATABASE_URL: str = "sqlite:///./test_aws_config.db"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_database_settings() -> DatabaseSettings:
    return DatabaseSettings()
