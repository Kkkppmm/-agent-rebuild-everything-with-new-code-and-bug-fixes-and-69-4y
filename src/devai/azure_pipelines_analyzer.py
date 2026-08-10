"""AzurePipelinesAnalyzer — audit Azure Pipelines configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
)
CONFIG_DIR = ".azure-pipelines"

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"\b(eval|exec)\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
LATEST_TAG_PATTERN = re.compile(
    r"image:\s*['\"]?[a-z0-9._/-]+:latest['\"]?",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"privileged\s*:\s*true\b|--privileged\b",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"^\s*image:\s*['\"]?(?!.*:)[a-z0-9._/-]+['\"]?\s*$",
    re.IGNORECASE,
)
UNTRUSTED_VAR_IN_SCRIPT_PATTERN = re.compile(
    r"\$\((Build\.Source(VersionMessage|BranchName)|System\.PullRequest\.(SourceBranch|Title)|Build\.RequestedFor)\)",
    re.IGNORECASE,
)
PERSIST_CREDENTIALS_PATTERN = re.compile(
    r"persistCredentials\s*:\s*true\b",
    re.IGNORECASE,
)
SYSTEM_DEBUG_PATTERN = re.compile(
    r"system\.debug\s*:\s*true\b|System\.Debug\s*:\s*true\b",
    re.IGNORECASE,
)
DEPLOY_STAGE_PATTERN = re.compile(
    r"^\s*(deploy|release|production)\s*:",
    re.IGNORECASE,
)
DEPLOY_JOB_PATTERN = re.compile(
    r"^\s*-\s*(deployment|deploy)\s*:",
    re.IGNORECASE,
)
BRANCH_CONDITION_PATTERN = re.compile(
    r"condition:\s*.*(refs/heads/main|refs/heads/master|eq\(variables\['Build\.SourceBranch'\])",
    re.IGNORECASE,
)


@dataclass
class AzureFinding:
    """A security or best-practice issue in an Azure Pipelines config file."""

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
class AzureInfo:
    """Parsed metadata about an Azure Pipelines config file."""

    path: str
    stages: list[str] = field(default_factory=list)
    job_count: int = 0
    has_deploy_stage: bool = False
    lines: int = 0


@dataclass
class AzureStats:
    """Aggregate Azure Pipelines config analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    if path.name in CONFIG_NAMES:
        return True
    rel = str(path).replace("\\", "/")
    return rel.endswith((".azure-pipelines/azure-pipelines.yml", ".azure-pipelines/azure-pipelines.yaml"))


class AzurePipelinesAnalyzer:
    """Audit Azure Pipelines configuration files for security risks and best practices.

    Scans for secrets in variables, curl-pipe-to-shell scripts, privileged
    containers, persistCredentials on checkout, untrusted pipeline variables
    in scripts, and unsafe deploy configurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AzureFinding] | None = None
        self._stats: AzureStats | None = None
        self._infos: list[AzureInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Azure Pipelines config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        azure_dir = self.root / CONFIG_DIR
        if azure_dir.is_dir():
            for name in CONFIG_NAMES:
                path = azure_dir / name
                if path.is_file() and path not in found:
                    found.append(path)
            for path in sorted(azure_dir.glob("*.yml")) + sorted(azure_dir.glob("*.yaml")):
                if path.is_file() and path not in found:
                    found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AzureFinding], AzureInfo]:
        findings: list[AzureFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AzureInfo(path=rel)

        info = AzureInfo(path=rel, lines=len(raw_lines))
        in_variables_block = False
        variables_indent = 0
        in_script_block = False
        script_indent = 0
        current_stage: str | None = None
        stage_has_condition = False
        deploy_stage_without_condition = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            stage_match = re.match(r"^-\s*stage:\s*(\S+)", line, re.IGNORECASE)
            if stage_match:
                current_stage = stage_match.group(1)
                info.stages.append(current_stage)
                stage_has_condition = False
                if DEPLOY_STAGE_PATTERN.match(f"{current_stage}:"):
                    info.has_deploy_stage = True

            if line.startswith("- stage:") or line.startswith("stage:"):
                stage_name = line.split(":", 1)[1].strip()
                if stage_name:
                    current_stage = stage_name
                    info.stages.append(stage_name)
                    stage_has_condition = False
                    if DEPLOY_STAGE_PATTERN.match(f"{stage_name}:"):
                        info.has_deploy_stage = True

            if line.startswith("- job:") or line.startswith("job:"):
                info.job_count += 1

            if DEPLOY_JOB_PATTERN.match(line):
                info.has_deploy_stage = True

            if line.startswith("condition:") or "condition:" in line:
                if BRANCH_CONDITION_PATTERN.search(line):
                    stage_has_condition = True

            if line.startswith("variables:") or line == "variables:":
                in_variables_block = True
                variables_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline:
                    in_variables_block = False
                continue

            if in_variables_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= variables_indent and not line.startswith("variables"):
                    in_variables_block = False
                elif SECRET_VAR_PATTERN.search(line):
                    findings.append(
                        AzureFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use Azure DevOps variable groups",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if SECRET_VAR_PATTERN.search(line) and not in_variables_block:
                findings.append(
                    AzureFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret in Azure Pipelines config — use secret variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("- script:") or line.startswith("script:"):
                in_script_block = True
                script_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline and inline not in ("|", ">"):
                    self._check_script_line(findings, rel, lineno, raw, line)
                    in_script_block = False
                continue

            if in_script_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= script_indent and not line.startswith("script"):
                    in_script_block = False
                else:
                    self._check_script_line(findings, rel, lineno, raw, line)

            if not in_script_block and (
                line.startswith("- bash:") or line.startswith("bash:") or line.startswith("- pwsh:")
            ):
                self._check_script_line(findings, rel, lineno, raw, line)

            if UNPINNED_IMAGE_PATTERN.match(line):
                findings.append(
                    AzureFinding(
                        kind="unpinned_image",
                        severity="low",
                        message="unpinned container image — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    AzureFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="container image uses :latest tag — pin to a digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    AzureFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PERSIST_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    AzureFinding(
                        kind="persist_credentials",
                        severity="high",
                        message="checkout persistCredentials enabled — credentials may leak to subsequent steps",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SYSTEM_DEBUG_PATTERN.search(line):
                findings.append(
                    AzureFinding(
                        kind="system_debug",
                        severity="medium",
                        message="system.debug enabled — may expose sensitive pipeline output",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.has_deploy_stage and not stage_has_condition:
            deploy_stage_without_condition = True

        if deploy_stage_without_condition:
            findings.append(
                AzureFinding(
                    kind="deploy_without_branch_guard",
                    severity="medium",
                    message="deploy stage/job without branch condition — restrict to protected branches",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        return findings, info

    def _check_script_line(
        self,
        findings: list[AzureFinding],
        rel: str,
        lineno: int,
        raw: str,
        line: str,
    ) -> None:
        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                AzureFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="pipeline script uses eval/exec — review for injection risk",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                AzureFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in pipeline script is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if SUDO_PATTERN.search(line):
            findings.append(
                AzureFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in pipeline script — prefer container-based builds without sudo",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if UNTRUSTED_VAR_IN_SCRIPT_PATTERN.search(line):
            findings.append(
                AzureFinding(
                    kind="untrusted_pipeline_var",
                    severity="medium",
                    message="untrusted pipeline variable in script — risk of script injection from PR metadata",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )

    def analyze(self) -> list[AzureFinding]:
        """Scan Azure Pipelines config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AzureFinding] = []
        infos: list[AzureInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = AzureStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AzureStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AzureInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config files)."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
        """Scaffold a hardened Azure Pipelines configuration template."""
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
  pythonVersion: '3.12'

stages:
  - stage: Test
    jobs:
      - job: Test
        steps:
          - checkout: self
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '$(pythonVersion)'
          - script: |
              pip install -e ".[dev]"
              python -m pytest
            displayName: Run tests
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Azure Pipelines: no config files found"
        return (
            f"Azure Pipelines: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Azure Pipelines configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: jobs={info.job_count}, deploy={info.has_deploy_stage}, "
                f"stages={len(info.stages)}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
