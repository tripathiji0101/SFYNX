"""
SFYNX application configuration.

All configuration is loaded from environment variables.
No secrets are ever hardcoded.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_env: str = "development"
    app_debug: bool = True
    app_host: str = "0.0.0.0"  # noqa: S104 — intentional for dev server binding
    app_port: int = 8000

    # Database (Phase 4+)
    database_url: str = ""

    # Allowed targets (comma-separated, added to built-in safe targets)
    sfynx_allowed_targets: str = ""

    # Scanner timeouts (seconds)
    sfynx_httpx_timeout: int = 120
    sfynx_nuclei_timeout: int = 300

    # Scanner binary paths
    sfynx_httpx_bin: str = "httpx"
    sfynx_nuclei_bin: str = "nuclei"

    # LLM (Phase 5+)
    sfynx_llm_api_key: str = ""
    sfynx_llm_model: str = ""
    sfynx_llm_base_url: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


# Singleton settings instance
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the cached settings instance."""
    global _settings  # noqa: PLW0603
    if _settings is None:
        _settings = Settings()
    return _settings
