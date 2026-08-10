"""AzurePipelinesAnalyzer — audit Azure Pipelines YAML for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PIPELINE_NAMES = ("azure-pipelines.yml", "azure-pipelines.yaml")
PIPELINE_DIRS = (".azure-pipelines", "azure-pipelines")

UNPINNED_TASK_PATTERN = re.compile(
    r"^\s*-\s*task:\s*[^\s@]+@(main|master|dev|latest)\b",
    re.IGNORECASE,
)
FLOATING_MAJOR_TASK_PATTERN = re.compile(
    r"^\s*-\s*task:\s*[^\s@]+@v\d+\s*$",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"['\"]?[^'\"${}\s][^'\"]*['\"]?",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget|Invoke-WebRequest)\s+[^\n|]*\|\s*(sh|bash|zsh|pwsh|powershell)\b",
    re.IGNORECASE,
)
SYSTEM_ACCESS_TOKEN_PATTERN = re.compile(
    r"System\.AccessToken|SYSTEM_ACCESSTOKEN",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\((?:Build\.|variables\[|env:)[^)]+\)",
    re.IGNORECASE,
)
CONTINUE_ON_ERROR_PATTERN = re.compile(
    r"^\s*continueOnError\s*:\s*true\b",
    re.IGNORECASE,
)
EXECUTION_POLICY_BYPASS_PATTERN = re.compile(
    r"-ExecutionPolicy\s+Bypass",
    re.IGNORECASE,
)
INLINE_VARIABLE_SECRET_PATTERN = re.compile(
    r"^\s*-\s*name:\s*(password|secret|api[_-]?key|token)\b",
    re.IGNORECASE,
)
PERSIST_CREDENTIALS_PATTERN = re.compile(
    r"^\s*persistCredentials\s*:\s*true\b",
    re.IGNORECASE,
)
CHECKOUT_CLEAN_FALSE_PATTERN = re.compile(
    r"^\s*clean\s*:\s*false\b",
    re.IGNORECASE,
)
ALLOW_SCRIPTS_PATTERN = re.compile(
    r"^\s*allowScriptsAuthAccess\s*:\s*true\b",
    re.IGNORECASE,
)


@dataclass
class AzurePipelinesFinding:
    """A security or best-practice issue in an Azure Pipelines file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class AzurePipelineInfo:
    """Parsed metadata about an Azure Pipelines file."""

    path: str
    triggers: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    tasks: int = 0
    lines: int = 0


@dataclass
class AzurePipelinesStats:
    """Aggregate Azure Pipelines analysis statistics."""

    pipelines: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pipeline_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in PIPELINE_NAMES:
        return True
    if path.suffix.lower() not in (".yml", ".yaml"):
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(PIPELINE_DIRS):
        return True
    return False


def _looks_like_azure_pipeline(content: str) -> bool:
    """Heuristic for YAML files that are Azure Pipelines but not in standard paths."""
    lowered = content.lower()
    markers = ("pool:", "trigger:", "pr:", "stages:", "jobs:", "steps:")
    task_marker = "task:"
    return sum(1 for m in markers if m in lowered) >= 2 and task_marker in lowered


class AzurePipelinesAnalyzer:
    """Audit Azure Pipelines YAML for security risks and CI best practices.

    Scans for unpinned tasks, secrets in env blocks, curl-pipe-to-shell,
    System.AccessToken exposure, script injection via build variables,
    continueOnError on security steps, and unsafe PowerShell execution policy.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AzurePipelinesFinding] | None = None
        self._stats: AzurePipelinesStats | None = None
        self._infos: list[AzurePipelineInfo] | None = None

    def pipelines(self) -> list[Path]:
        """Return Azure Pipelines file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_pipeline_file(path):
                found.append(path)
                continue
            if path.suffix.lower() in (".yml", ".yaml"):
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _looks_like_azure_pipeline(content):
                    found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AzurePipelinesFinding], AzurePipelineInfo]:
        findings: list[AzurePipelinesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AzurePipelineInfo(path=rel)

        info = AzurePipelineInfo(path=rel, lines=len(raw_lines))
        in_env_block = False
        in_variables_block = False
        env_indent = 0
        variables_indent = 0
        current_job: str | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("trigger:") or line.startswith("pr:"):
                info.triggers.append(line.split(":", 1)[0].strip())

            if re.match(r"^\S+:\s*$", line) and not line.startswith("-"):
                key = line[:-1].strip()
                if key not in ("pool", "steps", "variables", "jobs", "stages", "trigger", "pr"):
                    if key and key[0].isalpha():
                        info.jobs.append(key)
                        current_job = key

            if line.startswith("- task:"):
                info.tasks += 1

            if line == "env:" or line.startswith("env:"):
                in_env_block = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if line == "variables:" or line.startswith("variables:"):
                in_variables_block = True
                variables_indent = len(raw) - len(raw.lstrip())
                continue

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key not in ("env", "variables"):
                    if in_env_block and (len(raw) - len(raw.lstrip())) <= env_indent:
                        in_env_block = False
                    if in_variables_block and (len(raw) - len(raw.lstrip())) <= variables_indent:
                        in_variables_block = False

            if UNPINNED_TASK_PATTERN.match(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="unpinned_task",
                        severity="high",
                        message="task pinned to mutable branch (@main/@latest) — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_MAJOR_TASK_PATTERN.match(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="floating_task_version",
                        severity="medium",
                        message="task uses floating major version (@v1) — pin to full semver",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env_block and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent:
                    findings.append(
                        AzurePipelinesFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in env — use Azure Key Vault or secret variables",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if in_variables_block and INLINE_VARIABLE_SECRET_PATTERN.match(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="secret_variable_name",
                        severity="medium",
                        message="inline variable named like a secret — use secret variables or Key Vault",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            script_line = line
            if line.startswith("- script:") or line.startswith("- bash:") or line.startswith("- pwsh:"):
                script_line = line
            elif line.startswith("script:") or line.startswith("bash:") or line.startswith("pwsh:"):
                script_line = line

            if "script:" in line or "bash:" in line or "pwsh:" in line:
                if CURL_PIPE_SHELL_PATTERN.search(line):
                    findings.append(
                        AzurePipelinesFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in pipeline script is unsafe",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if SCRIPT_INJECTION_PATTERN.search(line) and "$(Build." in line:
                    findings.append(
                        AzurePipelinesFinding(
                            kind="script_injection",
                            severity="medium",
                            message=(
                                "build variable interpolated into script — "
                                "pass via env with quoting to prevent injection"
                            ),
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if SYSTEM_ACCESS_TOKEN_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="system_access_token",
                        severity="high",
                        message="System.AccessToken referenced — restrict scope and avoid logging",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CONTINUE_ON_ERROR_PATTERN.match(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="continue_on_error",
                        severity="medium",
                        message="continueOnError: true can mask security test failures",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EXECUTION_POLICY_BYPASS_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="execution_policy_bypass",
                        severity="medium",
                        message="PowerShell ExecutionPolicy Bypass weakens script safety",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PERSIST_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="persist_credentials",
                        severity="medium",
                        message="persistCredentials: true can leak tokens to later steps",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CHECKOUT_CLEAN_FALSE_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="checkout_not_clean",
                        severity="low",
                        message="checkout clean: false may leave artifacts from prior runs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_SCRIPTS_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="allow_scripts_auth",
                        severity="high",
                        message="allowScriptsAuthAccess: true grants scripts OAuth token access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if current_job and not info.jobs:
            info.jobs = [current_job]

        return findings, info

    def analyze(self) -> list[AzurePipelinesFinding]:
        """Scan pipeline files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AzurePipelinesFinding] = []
        infos: list[AzurePipelineInfo] = []
        paths = self.pipelines()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = AzurePipelinesStats(
            pipelines=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AzurePipelinesStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AzurePipelineInfo]:
        """Return parsed pipeline metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no pipelines)."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Azure Pipelines template."""
        return """\
# Generated by DevAI AzurePipelinesAnalyzer
trigger:
  - main

pr:
  - main

pool:
  vmImage: ubuntu-latest

variables:
  pythonVersion: '3.12'

steps:
  - checkout: self
    persistCredentials: false
    clean: true

  - task: UsePythonVersion@0
    displayName: 'Use Python $(pythonVersion)'
    inputs:
      versionSpec: '$(pythonVersion)'

  - script: |
      python -m pip install --upgrade pip
      pip install -e ".[dev]"
    displayName: 'Install dependencies'

  - script: python -m pytest
    displayName: 'Run tests'
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Azure Pipelines: none found"
        return (
            f"Azure Pipelines: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Azure Pipelines analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            triggers = ", ".join(info.triggers[:5]) or "none"
            lines.append(
                f"  - {info.path}: {info.tasks} task(s), {len(info.jobs)} job(s), triggers=[{triggers}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
