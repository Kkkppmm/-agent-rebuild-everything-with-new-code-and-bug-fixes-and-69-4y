"""HatchAnalyzer — audit Hatch pyproject.toml and hatch.toml for security and build hardening."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_HATCH_MARKER = re.compile(
    r"(?:^\[tool\.hatch\]|^\[tool\.hatch\.|^\[tool\.hatchling\]|hatchling)",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG = PackagingToolConfig(
    tool_name="hatch",
    secret_message="hardcoded secret in Hatch config — use env vars or CI secret stores",
    marker_patterns=(_HATCH_MARKER,),
    extra_filenames=("hatch.toml",),
    file_kind_map={"hatch.toml": "hatch_config"},
    hardened_snippet="""\
# hatch.toml — hardened defaults for Hatch projects
[build]
# Use HTTPS PyPI indexes only; store credentials via environment variables

[envs.default]
# Pin dependencies in pyproject.toml and use lockfiles where possible
""",
)

HatchFinding, HatchInfo, HatchStats, HatchAnalyzer = make_packaging_analyzer("Hatch", _CONFIG)
