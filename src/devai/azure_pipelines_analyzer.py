"""AzurePipelinesAnalyzer — audit Azure Pipelines YAML for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

AZURE_PIPELINES_NAMES = ("azure-pipelines.yml", "azure-pipelines.yaml")
AZURE_PIPELINES_SUFFIX = ".azure-pipelines.yml"

SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"]?[^'\"$\s{]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_CONTAINER_PATTERN = re.compile(
    r"privileged\s*:\s*true|--privileged\b",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"runAsUser\s*:\s*0\b|user\s*:\s*['\"]?root['\"]?|--user\s+root\b",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"image\s*:\s*['\"]?(python|node|golang|openjdk|maven|gradle|ubuntu|debian)['\"]?\s*$",
    re.IGNORECASE,
)
LATEST_POOL_PATTERN = re.compile(
    r"vmImage\s*:\s*['\"]?(ubuntu-latest|windows-latest|macos-latest)['\"]?\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"script\s*:\s*.*\$\(.*(Build\.|System\.|parameters\.|variables\.)",
    re.IGNORECASE,
)
DISABLE_TLS_PATTERN = re.compile(
    r"(NODE_TLS_REJECT_UNAUTHORIZED|GIT_SSL_NO_VERIFY|curl\s+-k\b|--insecure\b)",
    re.IGNORECASE,
)
CONTINUE_ON_ERROR_PATTERN = re.compile(
    r"continueOnError\s*:\s*true",
    re.IGNORECASE,
)
PLAIN_SECRET_VAR_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*(API_KEY|SECRET|PASSWORD|TOKEN)\s*$",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)


@dataclass
class AzurePipelinesFinding:
    """A security or best-practice issue in an Azure Pipelines config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    stage: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        stage = f" ({self.stage})" if self.stage else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{stage} — {self.message}"


@dataclass
class AzurePipelinesStageInfo:
    """Metadata about a pipeline stage."""

    name: str
    lineno: int


@dataclass
class AzurePipelinesInfo:
    """Parsed metadata about an Azure Pipelines config."""

    path: str
    trigger: str = ""
    pool: str = ""
    stages: list[AzurePipelinesStageInfo] = field(default_factory=list)
    uses_container: bool = False
    uses_variables: bool = False
    lines: int = 0


@dataclass
class AzurePipelinesStats:
    """Aggregate Azure Pipelines analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_azure_pipelines_file(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    return name in AZURE_PIPELINES_NAMES or lower.endswith(AZURE_PIPELINES_SUFFIX)


class AzurePipelinesAnalyzer:
    """Audit Azure Pipelines YAML for security risks and CI best practices.

    Scans for hardcoded secrets, curl-pipe-to-shell patterns, privileged
    containers, unpinned VM images, script injection via macro expansion, and
    disabled TLS verification.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AzurePipelinesFinding] | None = None
        self._stats: AzurePipelinesStats | None = None
        self._infos: list[AzurePipelinesInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Azure Pipelines config paths found in the project."""
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
        in_variables = False
        current_stage = ""
        next_var_is_secret = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("trigger:") or line.startswith("pr:"):
                info.trigger = line.split(":", 1)[1].strip()

            pool_match = re.search(r"vmImage\s*:\s*['\"]?([^'\"]+)['\"]?", line)
            if pool_match:
                info.pool = pool_match.group(1)

            if "container:" in line.lower() or re.search(r"^\s*image\s*:", line):
                info.uses_container = True

            if line.startswith("variables:") or line.startswith("variables "):
                in_variables = True
                info.uses_variables = True
                continue

            if in_variables and line == "":
                in_variables = False

            stage_match = re.match(r"-\s*stage\s*:\s*['\"]?([^'\"]+)['\"]?", line)
            if stage_match:
                current_stage = stage_match.group(1)
                info.stages.append(
                    AzurePipelinesStageInfo(name=current_stage, lineno=lineno)
                )

            if PLAIN_SECRET_VAR_PATTERN.match(line):
                next_var_is_secret = True
                continue

            if next_var_is_secret and re.match(r"^\s*value\s*:", line):
                if not re.search(r"\$\(|@group|KeyVault|secret", line, re.IGNORECASE):
                    findings.append(
                        AzurePipelinesFinding(
                            kind="plaintext_secret_var",
                            severity="high",
                            message="plaintext secret in variables — use Azure Key Vault or secret variables",
                            path=rel,
                            lineno=lineno,
                            stage=current_stage,
                            line=raw.strip(),
                        )
                    )
                next_var_is_secret = False

            if in_variables and SECRET_VAR_PATTERN.search(line):
                if not re.search(r"\$\(|@group|KeyVault", line, re.IGNORECASE):
                    findings.append(
                        AzurePipelinesFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use Key Vault task bindings",
                            path=rel,
                            lineno=lineno,
                            stage=current_stage,
                            line=raw.strip(),
                        )
                    )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in pipeline is unsafe",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in pipeline script — prefer container jobs without elevated privileges",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_CONTAINER_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container — avoid host-level container access",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="root_user",
                        severity="medium",
                        message="container runs as root — use a non-root user in the job image",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="script_injection",
                        severity="high",
                        message="unescaped pipeline macro in script — risk of script injection",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if DISABLE_TLS_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="tls_verification_disabled",
                        severity="high",
                        message="TLS verification disabled — do not skip certificate validation in CI",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_IMAGE_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="unpinned_container_image",
                        severity="low",
                        message="unpinned container image tag — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if LATEST_POOL_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="floating_vm_image",
                        severity="low",
                        message="floating VM image tag — pin to a specific image version for reproducibility",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if CONTINUE_ON_ERROR_PATTERN.search(line):
                findings.append(
                    AzurePipelinesFinding(
                        kind="continue_on_error",
                        severity="low",
                        message="continueOnError enabled — security steps should fail the pipeline",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[AzurePipelinesFinding]:
        """Scan Azure Pipelines configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AzurePipelinesFinding] = []
        infos: list[AzurePipelinesInfo] = []
        paths = self.configs()

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
            configs=len(paths),
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
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
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
  vmImage: ubuntu-22.04

variables:
  - group: shared-secrets  # Link Azure Key Vault variable group — never commit secrets

stages:
  - stage: Test
    jobs:
      - job: UnitTests
        container: python:3.12-slim
        steps:
          - checkout: self
            fetchDepth: 1
          - script: python -m pytest
            displayName: Run tests
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Azure Pipelines: none found"
        return (
            f"Azure Pipelines: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Azure Pipelines analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(s.name for s in info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: pool={info.pool or 'unknown'}, "
                f"container={info.uses_container}, stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
