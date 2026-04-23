"""
Configuration Module
====================
Loads configuration from environment variables and optional config.yaml.
Provides a single Config object consumed across the application.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class Config:
    """Global configuration for LLM Red Teamer."""

    # API Settings
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    provider: str = "openai"
    model: str = "gpt-4o"

    # Scan Settings
    max_workers: int = 4
    request_timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.5
    temperature: float = 0.0

    # Output Settings
    output_dir: str = "./reports"
    log_level: str = "WARNING"

    # Payload Settings
    payload_dir: str = "./payloads"


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from environment variables and optional YAML file.
    Environment variables take precedence over file config.
    """
    cfg = Config()

    # Load from YAML if available
    if config_path and YAML_AVAILABLE and os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}
            for key, value in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, value)
        except Exception as e:
            logger.warning(f"Could not load config file {config_path}: {e}")

    # Environment variables override file config
    env_map = {
        "OPENAI_API_KEY": "api_key",
        "LLM_API_KEY": "api_key",
        "LLM_BASE_URL": "base_url",
        "LLM_PROVIDER": "provider",
        "LLM_MODEL": "model",
        "LLM_MAX_WORKERS": "max_workers",
        "LLM_OUTPUT_DIR": "output_dir",
        "LLM_LOG_LEVEL": "log_level",
    }

    for env_var, attr in env_map.items():
        val = os.environ.get(env_var)
        if val:
            # Type-coerce integer fields
            if attr in ("max_workers", "max_retries"):
                try:
                    val = int(val)
                except ValueError:
                    pass
            setattr(cfg, attr, val)

    return cfg
