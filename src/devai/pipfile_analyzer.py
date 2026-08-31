"""PipfileAnalyzer — audit Pipenv Pipfile and Pipfile.lock for security and build hardening."""

from __future__ import annotations

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_CONFIG = PackagingToolConfig(
    tool_name="pipenv",
    secret_message="hardcoded secret in Pipfile — use pipenv variables or CI secret stores",
    extra_filenames=("Pipfile", "Pipfile.lock"),
    pyproject_names=(),
    lock_filenames=("Pipfile.lock",),
    lock_parent_pyproject="Pipfile",
    file_kind_map={"Pipfile": "pipfile", "Pipfile.lock": "lock"},
    hardened_snippet="""\
# Pipfile — hardened defaults for Pipenv projects
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
# Pin packages with exact versions and commit Pipfile.lock
""",
)

PipfileFinding, PipfileInfo, PipfileStats, PipfileAnalyzer = make_packaging_analyzer(
    "Pipfile", _CONFIG
)
