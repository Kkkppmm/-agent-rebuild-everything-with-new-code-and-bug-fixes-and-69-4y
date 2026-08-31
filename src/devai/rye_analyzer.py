"""RyeAnalyzer — audit Rye pyproject.toml, rye.lock, and requirements.lock for security."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_RYE_MARKER = re.compile(
    r"(?:^\[tool\.rye\]|^\[tool\.rye\.|rye\s*=\s*\{)",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG = PackagingToolConfig(
    tool_name="rye",
    secret_message="hardcoded secret in Rye config — use env vars or CI secret stores",
    marker_patterns=(_RYE_MARKER,),
    extra_filenames=("rye.lock", "requirements.lock"),
    lock_filenames=("rye.lock",),
    file_kind_map={"rye.lock": "lock", "requirements.lock": "requirements_lock"},
    hardened_snippet="""\
# pyproject.toml [tool.rye] — hardened defaults
[tool.rye]
# Use HTTPS PyPI indexes; store credentials via environment variables
# Commit rye.lock for reproducible installs
""",
)

RyeFinding, RyeInfo, RyeStats, RyeAnalyzer = make_packaging_analyzer("Rye", _CONFIG)
