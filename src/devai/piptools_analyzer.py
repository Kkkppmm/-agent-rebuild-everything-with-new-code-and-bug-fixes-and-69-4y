"""PipToolsAnalyzer — audit pip-tools requirements.in and compiled output for security."""

from __future__ import annotations

import re

from devai._packaging_common import PackagingToolConfig, make_packaging_analyzer

_REQUIREMENTS_IN_PATTERN = re.compile(
    r"^requirements(?:[-_.][\w.-]+)?\.in$",
    re.IGNORECASE,
)

_CONFIG = PackagingToolConfig(
    tool_name="pip-tools",
    secret_message="hardcoded secret in pip-tools requirements — use env vars or CI secret stores",
    extra_filenames=(),
    pyproject_names=(),
    file_kind_map={
        "requirements.in": "requirements_in",
        "requirements-dev.in": "requirements_in",
        "requirements-test.in": "requirements_in",
        "requirements.txt": "compiled",
        "requirements-dev.txt": "compiled",
    },
    hardened_snippet="""\
# requirements.in — hardened defaults for pip-tools
# Pin top-level deps; let pip-compile generate exact versions in requirements.txt
# Use HTTPS indexes only; store credentials via PIP_INDEX_URL env var
httpx==0.27.0
""",
)

PipToolsFinding, PipToolsInfo, PipToolsStats, PipToolsAnalyzer = make_packaging_analyzer(
    "PipTools", _CONFIG
)

# Override configs() to also match requirements*.in files
_original_configs = PipToolsAnalyzer.configs


def _piptools_configs(self: PipToolsAnalyzer) -> list:  # type: ignore[name-defined]
    found = _original_configs(self)
    seen = {p.resolve() for p in found}
    for path in sorted(self.root.rglob("*")):
        if path.is_file() and _REQUIREMENTS_IN_PATTERN.match(path.name):
            resolved = path.resolve()
            if resolved not in seen:
                found.append(path)
                seen.add(resolved)
    return sorted(found, key=lambda p: str(p))


PipToolsAnalyzer.configs = _piptools_configs  # type: ignore[method-assign]
