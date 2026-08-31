"""SetuptoolsAnalyzer — audit setup.py, setup.cfg, and pyproject.toml for setuptools projects."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_SETuptools_MARKER = re.compile(
    r"(?:^\[tool\.setuptools\]|^\[tool\.setuptools\.|setup\s*\(|setuptools|"
    r"^\[build-system\].*setuptools)",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG = PackagingToolConfig(
    tool_name="setuptools",
    secret_message="hardcoded secret in setuptools config — use env vars or CI secret stores",
    marker_patterns=(_SETuptools_MARKER,),
    extra_filenames=("setup.py", "setup.cfg"),
    file_kind_map={"setup.py": "setup_py", "setup.cfg": "setup_cfg"},
    hardened_snippet="""\
# setup.cfg — hardened setuptools defaults
[metadata]
# Store credentials via environment variables, not in setup files

[options]
# Pin install_requires with exact versions in pyproject.toml or requirements files
""",
)

SetuptoolsFinding, SetuptoolsInfo, SetuptoolsStats, SetuptoolsAnalyzer = make_packaging_analyzer(
    "Setuptools", _CONFIG
)
