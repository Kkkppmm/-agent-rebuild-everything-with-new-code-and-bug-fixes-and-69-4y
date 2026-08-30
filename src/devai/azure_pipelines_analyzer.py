"""AzurePipelinesAnalyzer — audit Azure Pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

AZURE_PIPELINE_NAMES = (
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "azure-pipeline.yml",
    "azure-pipeline.yaml",
)
AZURE_DIRS = (".azure", "pipelines", "ci", ".pipelines")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget|Invoke-WebRequest)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|container|vmImage)\s*:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:script|bash|powershell|pwsh)\s*:\s*.*\$\{?\{?\s*(?:variables|parameters)\.",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
UNPINNED_TASK_PATTERN = re.compile(
    r"^\s*-\s*task:\s*[^\s@]+@(latest|main|master|develop)\s*$",
    re.IGNORECASE,
)
FLOATING_TASK_PATTERN = re.compile(
    r"^\s*-\s*task:\s*([A-Za-z0-9._/-]+)@(\d+)\s*$",
    re.IGNORECASE,
)
PRIVILEGED_CONTAINER_PATTERN = re.compile(
    r"(?:privileged|runOptions)\s*:\s*['\"]?true['\"]?",
    re.IGNORECASE,
)
SYSTEM_DEBUG_PATTERN = re.compile(
    r"^\s*system\.debug\s*:\s*true\s*$",
    re.IGNORECASE,
)
PR_CHECKOUT_PATTERN = re.compile(
    r"^\s*-\s*checkout:\s*self\s*$",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\s+", re.IGNORECASE)
DOCKER_TASK_PATTERN = re.compile(
    r"^\s*-\s*task:\s*Docker@",
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
class AzurePipelinesInfo:
    """Parsed metadata about an Azure Pipelines file."""

    path: str
    triggers: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)
    jobs: int = 0
    lines: int = 0


@dataclass
class AzurePipelinesStats:
    """Aggregate Azure Pipelines analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_azure_pipelines_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in AZURE_PIPELINE_NAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(AZURE_DIRS) and lower.endswith((".yml", ".yaml")):
        if "azure" in lower or "pipeline" in lower:
            return True
    return False


class AzurePipelinesAnalyzer:
    """Audit Azure Pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `azure-pipelines.yml` for curl-pipe-to-shell, unpinned tasks, privileged
    containers, hardcoded credentials, and unsafe PR checkout patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AzurePipelinesFinding] | None = None
        self._stats: AzurePipelinesStats | None = None
        self._infos: list[AzurePipelinesInfo] | None = None

    def files(self) -> list[Path]:
        """Return Azure Pipelines files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_azure_pipelines_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AzurePipelinesFinding], AzurePipelinesInfo]:
        findings: list[AzurePipelinesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AzurePipelinesInfo(path=rel)

        info = AzurePipelinesInfo(path=rel, lines=len(raw_lines))
        in_script = False
        script_indent = 0
        in_variables = False
        variables_indent = 0
        has_pr_trigger = False
        in_security_step = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^trigger\s*:", line, re.IGNORECASE):
                info.triggers.append("branch")
            if re.match(r"^pr\s*:", line, re.IGNORECASE):
                info.triggers.append("pr")
                has_pr_trigger = True

            if re.match(r"^\s*-?\s*stage\s*:", line, re.IGNORECASE):
                stage_name = re.sub(r"^\s*-?\s*stage\s*:\s*", "", line, flags=re.IGNORECASE)
                if stage_name:
                    info.stages.append(stage_name.strip())

            if re.match(r"^\s*-?\s*job\s*:", line, re.IGNORECASE):
                info.jobs += 1
                in_security_step = False

            if re.match(r"^\s*displayName\s*:\s*.*(?:security|audit|scan|sast|dast)", line, re.IGNORECASE):
                in_security_step = True

            if re.match(r"^\s*-?\s*(script|bash|powershell|pwsh)\s*:", line, re.IGNORECASE):
                in_script = True
                script_indent = len(raw) - len(raw.lstrip())
                script_body = re.sub(
                    r"^\s*-?\s*(?:script|bash|powershell|pwsh)\s*:\s*",
                    "",
                    line,
                    flags=re.IGNORECASE,
                )
                if script_body:
                    if CURL_PIPE_SHELL_PATTERN.search(script_body):
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
                    if SCRIPT_INJECTION_PATTERN.search(script_body):
                        findings.append(
                            AzurePipelinesFinding(
                                kind="script_injection",
                                severity="high",
                                message="unquoted pipeline variable in script — validate untrusted PR input",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                continue

            if re.match(r"^\s*variables\s*:", line, re.IGNORECASE):
                in_variables = True
                variables_indent = len(raw) - len(raw.lstrip())
                continue

            if in_variables:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= variables_indent and not line.startswith("-"):
                    in_variables = False
                elif HARDCODED_SECRET_PATTERN.search(line):
                    findings.append(
                        AzurePipelinesFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded credential in variables — use Azure DevOps variable groups or Key Vault",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if in_script:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= script_indent and not line.startswith("-"):
                    in_script = False
                else:
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
                    if SCRIPT_INJECTION_PATTERN.search(line):
                        findings.append(
                            AzurePipelinesFinding(
                                kind="script_injection",
                                severity="high",
                                message="unquoted pipeline variable in script — validate untrusted PR input",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    if SUDO_PATTERN.search(line):
                        findings.append(
                            AzurePipelinesFinding(
                                kind="sudo_usage",
                                severity="medium",
                                message="sudo in pipeline script — use service containers instead of elevated privileges",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if HARDCODED_SECRET_PATTERN.search(line) and not in_variables:
                findings.append(
                    AzurePipelinesFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Azure DevOps secret variables or Key Vault",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_CONTAINER_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container — avoid privileged mode in pipeline jobs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_TASK_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="unpinned_task",
                        severity="medium",
                        message="task uses floating version tag — pin to a specific major version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_TASK_PATTERN.search(line):
                match = FLOATING_TASK_PATTERN.search(line)
                if match and int(match.group(2)) < 2:
                    findings.append(
                        AzurePipelinesFinding(
                            kind="old_task_version",
                            severity="low",
                            message=f"task {match.group(1)} uses old major version — consider upgrading",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if DOCKER_TASK_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="docker_task",
                        severity="medium",
                        message="Docker task enabled — restrict to trusted branches and validate image sources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and "http://" in line.lower():
                findings.append(
                    AzurePipelinesFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SYSTEM_DEBUG_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="system_debug",
                        severity="medium",
                        message="system.debug enabled — may expose sensitive pipeline output in logs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if has_pr_trigger and PR_CHECKOUT_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="pr_checkout",
                        severity="medium",
                        message="checkout: self on PR trigger — restrict secrets for fork PRs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and re.search(r"condition:\s*failed\(\)", line, re.IGNORECASE):
                findings.append(
                    AzurePipelinesFinding(
                        kind="conditional_security_step",
                        severity="medium",
                        message="security step runs only on failure — automate security scans on every build",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[AzurePipelinesFinding]:
        """Scan Azure Pipelines files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AzurePipelinesFinding] = []
        infos: list[AzurePipelinesInfo] = []
        paths = self.files()

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
            files=len(paths),
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
    def infos(self) -> list[AzurePipelinesInfo]:
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
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

variables:
  pythonVersion: '3.12'

stages:
  - stage: Test
    jobs:
      - job: Test
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: $(pythonVersion)
          - script: |
              pip install -e ".[dev]"
              python -m pytest
            displayName: Run tests

  - stage: Security
    dependsOn: Test
    jobs:
      - job: Scan
        steps:
          - script: |
              pip install devai
              devai security-scan .
            displayName: Security scan
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
                f"  - {info.path}: {info.jobs} job(s), triggers=[{triggers}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
