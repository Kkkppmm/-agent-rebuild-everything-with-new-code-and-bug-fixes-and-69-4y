"""Template interpolation for DevAI programs and workflows."""

from __future__ import annotations

import os
import re
from pathlib import Path

_TEMPLATE = re.compile(r"\$\{([^}]+)\}")


def interpolate(
    value: str,
    context: dict[str, str] | None = None,
    *,
    base_path: str | Path | None = None,
) -> str:
    """Resolve template variables in a string.

    Supported forms:
    - ``${var:name}`` — context key ``name``
    - ``${env:NAME}`` — environment variable
    - ``${file:path}`` — file contents (relative to ``base_path`` when set)
    - ``$name`` — legacy context key shorthand (whole string only)
  """
    if context is None:
        context = {}

    if value.startswith("$") and not value.startswith("${") and value[1:] in context:
        return context[value[1:]]

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("var:"):
            return context.get(token[4:], "")
        if token.startswith("env:"):
            return os.environ.get(token[4:], "")
        if token.startswith("file:"):
            file_path = Path(token[5:])
            if base_path is not None and not file_path.is_absolute():
                file_path = Path(base_path) / file_path
            if not file_path.exists():
                return ""
            return file_path.read_text(encoding="utf-8", errors="replace")
        return context.get(token, "")

    return _TEMPLATE.sub(_replace, value)


def interpolate_context(
    context: dict[str, str],
    *,
    base_path: str | Path | None = None,
) -> dict[str, str]:
    """Interpolate all values in a context dictionary."""
    return {
        key: interpolate(value, context, base_path=base_path)
        for key, value in context.items()
    }
