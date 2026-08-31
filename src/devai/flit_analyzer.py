"""FlitAnalyzer — audit Flit pyproject.toml and flit.ini for security and build hardening."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_FLIT_MARKER = re.compile(
    r"(?:^\[tool\.flit\]|^\[tool\.flit\.|flit_core|flit\s*=\s*\{)",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG = PackagingToolConfig(
    tool_name="flit",
    secret_message="hardcoded secret in Flit config — use env vars or CI secret stores",
    marker_patterns=(_FLIT_MARKER,),
    extra_filenames=("flit.ini", ".flit"),
    file_kind_map={"flit.ini": "flit_ini", ".flit": "flit_meta"},
    hardened_snippet="""\
# flit.ini — hardened defaults for Flit projects
[metadata]
# Store repository URLs and credentials via environment variables

[sdist]
# Pin dependencies in pyproject.toml with exact versions
""",
)

FlitFinding, FlitInfo, FlitStats, FlitAnalyzer = make_packaging_analyzer("Flit", _CONFIG)
