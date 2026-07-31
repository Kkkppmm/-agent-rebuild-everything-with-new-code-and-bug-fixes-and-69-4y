"""Load DevAI configuration from project files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigError

CONFIG_FILENAMES = (
    ".devai.yaml",
    ".devai.yml",
    "devai.yaml",
    "devai.yml",
    ".devai.json",
    "devai.json",
)


def find_config_file(start: str | Path | None = None) -> Path | None:
    """Search upward from *start* for a DevAI config file."""
    current = Path(start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent

    for directory in (current, *current.parents):
        for name in CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _load_raw(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ConfigError(
                "YAML config requires PyYAML. Install with: pip install 'devai[yaml]'"
            ) from exc
        data = yaml.safe_load(text)
    elif suffix == ".json":
        data = json.loads(text)
    else:
        raise ConfigError(f"Unsupported config format: {path.suffix}")

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config file must contain a mapping: {path}")
    return data


def _normalize_config_data(data: dict[str, Any]) -> dict[str, Any]:
    """Map common config file keys to DevAIConfig fields."""
    mapping = {
        "api_key": "api_key",
        "apiKey": "api_key",
        "base_url": "base_url",
        "baseUrl": "base_url",
        "model": "model",
        "max_tokens": "max_tokens",
        "maxTokens": "max_tokens",
        "temperature": "temperature",
        "timeout": "timeout",
        "max_retries": "max_retries",
        "maxRetries": "max_retries",
        "retry_delay": "retry_delay",
        "retryDelay": "retry_delay",
        "provider": "provider",
        "extra_headers": "extra_headers",
        "extraHeaders": "extra_headers",
    }
    normalized: dict[str, Any] = {}
    for key, value in data.items():
        if key in mapping:
            normalized[mapping[key]] = value
    return normalized


def load_config_file(
    path: str | Path | None = None,
    *,
    overrides: dict[str, Any] | None = None,
) -> DevAIConfig:
    """Load DevAIConfig from a file, with optional overrides.

  If *path* is omitted, searches for a config file from the current directory.
  Environment variables still apply via DevAIConfig.__post_init__ after loading.
    """
    if path is None:
        found = find_config_file()
        if found is None:
            raise ConfigError(
                "No DevAI config file found. Create .devai.yaml or pass an explicit path."
            )
        path = found

    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")

    raw = _normalize_config_data(_load_raw(config_path))
    if overrides:
        raw.update(overrides)

    provider = raw.pop("provider", None)
    if provider:
        return DevAIConfig.from_provider(provider, **raw)
    return DevAIConfig(**raw)


def config_file_template(*, provider: str = "openai", model: str = "gpt-4o-mini") -> str:
    """Return a starter config file body for documentation and CLI init."""
    return (
        "# DevAI project configuration\n"
        f"provider: {provider}\n"
        f"model: {model}\n"
        "# api_key: sk-...  # or set DEVAI_API_KEY in the environment\n"
        "temperature: 0.2\n"
        "max_tokens: 4096\n"
    )
