"""CondaAnalyzer — audit Conda environment.yml and recipe meta.yaml for security."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_CONDA_MARKER = re.compile(
    r"(?:^name\s*:|^channels\s*:|^dependencies\s*:|^conda\s|meta\.yaml)",
    re.IGNORECASE | re.MULTILINE,
)

_CONFIG = PackagingToolConfig(
    tool_name="conda",
    secret_message="hardcoded secret in Conda config — use conda env vars or secret stores",
    marker_patterns=(_CONDA_MARKER,),
    extra_filenames=("environment.yml", "environment.yaml", "meta.yaml", "conda-lock.yml"),
    pyproject_names=(),
    file_kind_map={
        "environment.yml": "environment",
        "environment.yaml": "environment",
        "meta.yaml": "recipe",
        "conda-lock.yml": "lock",
    },
    hardened_snippet="""\
# environment.yml — hardened defaults for Conda environments
name: myenv
channels:
  - conda-forge
dependencies:
  - python=3.12
  # Pin package versions for reproducibility
# Use conda-lock for lockfile-based installs
""",
)

CondaFinding, CondaInfo, CondaStats, CondaAnalyzer = make_packaging_analyzer("Conda", _CONFIG)
