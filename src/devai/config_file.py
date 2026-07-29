"""Load DevAI configuration from project files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from devai.core.config import DevAIConfig

CONFIG_NAMES = (
    ".devai.yaml",
    ".devai.yml",
    ".devai.json",
    "devai.yaml",
    "devai.yml",
    "devai.json",
)


def find_config_file(start: str | Path | None = None) -> Path | None:
    """Search upward from *start* for a DevAI config file."""
    current = Path(start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    for directory in [current, *current.parents]:
        for name in CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _load_raw(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required for YAML config. Install with: pip install 'devai[yaml]'"
            ) from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a mapping: {path}")
    return data


def load_config_file(path: str | Path | None = None) -> DevAIConfig:
    """Load a :class:`DevAIConfig` from a file or by searching the tree."""
    if path is None:
        found = find_config_file()
        if found is None:
            raise FileNotFoundError(
                "No DevAI config file found. Run `devai config-init` to create one."
            )
        path = found
    path = Path(path)
    data = _load_raw(path)
    return DevAIConfig(**{k: v for k, v in data.items() if k in DevAIConfig.__dataclass_fields__})


def config_file_template() -> str:
    """Return a starter ``.devai.yaml`` template."""
    return """# DevAI project configuration
model: gpt-4o-mini
temperature: 0.2
max_tokens: 4096
timeout: 60.0
# api_key: set via DEVAI_API_KEY environment variable
# base_url: https://api.openai.com/v1
"""
