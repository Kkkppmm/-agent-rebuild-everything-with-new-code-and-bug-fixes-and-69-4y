"""PdmAnalyzer — audit PDM pyproject.toml, .pdm.toml, and pdm.lock for security."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_PDM_MARKER = re.compile(
    r"(?:^\[tool\.pdm\]|^\[tool\.pdm\.|^\[tool\.pdm\.dev-dependencies\]|pdm-backend)",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG = PackagingToolConfig(
    tool_name="pdm",
    secret_message="hardcoded secret in PDM config — use pdm config or CI secret stores",
    marker_patterns=(_PDM_MARKER,),
    extra_filenames=(".pdm.toml", "pdm.lock"),
    lock_filenames=("pdm.lock",),
    file_kind_map={".pdm.toml": "pdm_config", "pdm.lock": "lock"},
    hardened_snippet="""\
# .pdm.toml — hardened defaults for PDM projects
[pypi]
# Use HTTPS indexes; store credentials via:
#   pdm config pypi.url https://pypi.org/simple
# Never commit tokens in pyproject.toml

[venv]
# Prefer project-local .venv for reproducibility
""",
)

PdmFinding, PdmInfo, PdmStats, PdmAnalyzer = make_packaging_analyzer("Pdm", _CONFIG)
