"""Template interpolation for DevAI programs and prompts."""

from __future__ import annotations

import os
import re
from pathlib import Path

PLACEHOLDER_PATTERN = re.compile(r"\$\{([^}]+)\}")


def interpolate(
    text: str,
    variables: dict[str, str] | None = None,
    *,
    base_path: str | Path | None = None,
) -> str:
    """Resolve ``${var:}``, ``${env:}``, and ``${file:}`` placeholders.

    Supported forms:
    - ``${name}`` or ``${var:name}`` — lookup in *variables*
    - ``${env:NAME}`` — environment variable
    - ``${file:relative/path}`` — file contents relative to *base_path*
    """

    variables = variables or {}
    base = Path(base_path) if base_path else Path.cwd()

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("env:"):
            return os.environ.get(token[4:], "")
        if token.startswith("file:"):
            file_path = base / token[5:]
            if file_path.is_file():
                return file_path.read_text(encoding="utf-8", errors="replace")
            return ""
        if token.startswith("var:"):
            return variables.get(token[4:], "")
        return variables.get(token, "")

    return PLACEHOLDER_PATTERN.sub(_replace, text)


def interpolate_dict(
    data: dict[str, str],
    variables: dict[str, str] | None = None,
    *,
    base_path: str | Path | None = None,
) -> dict[str, str]:
    """Interpolate all string values in a dictionary."""
    return {
        key: interpolate(value, variables, base_path=base_path)
        for key, value in data.items()
    }
