"""GitLabCIAnalyzer — audit GitLab CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")

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
    r"privileged\s*:\s*true\b",
    re.IGNORECASE,
)
DIND_PATTERN = re.compile(
    r"docker:\s*dind\b|docker:dind\b",
    re.IGNORECASE,
)
DIND_TLS_DISABLED_PATTERN = re.compile(
    r"DOCKER_TLS_CERTDIR\s*:\s*['\"]?['\"]?\s*$|DOCKER_TLS_CERTDIR\s*:\s*\"\"",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"^\s*image:\s*['\"]?(?!.*:)[a-z0-9._/-]+['\"]?\s*$",
    re.IGNORECASE,
)
UNTRUSTED_VAR_IN_SCRIPT_PATTERN = re.compile(
    r"\$\{?(CI_COMMIT_(MESSAGE|DESCRIPTION|BRANCH)|CI_MERGE_REQUEST_(TITLE|DESCRIPTION))\}?",
    re.IGNORECASE,
)
DEPLOY_JOB_PATTERN = re.compile(
    r"^\s*(deploy|release|production)\s*:",
    re.IGNORECASE,
)
ONLY_MAIN_PATTERN = re.compile(
    r"only:\s*$|^\s*-\s*(main|master)\s*$",
    re.IGNORECASE,
)


@dataclass
class GitLabFinding:
    """A security or best-practice issue in a GitLab CI config file."""

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
class GitLabInfo:
    """Parsed metadata about a GitLab CI config file."""

    path: str
    stages: list[str] = field(default_factory=list)
    job_count: int = 0
    has_deploy_job: bool = False
    lines: int = 0


@dataclass
class GitLabStats:
    """Aggregate GitLab CI config analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class GitLabCIAnalyzer:
    """Audit GitLab CI configuration files for security risks and best practices.

    Scans for secrets in variables, curl-pipe-to-shell scripts, privileged
    containers, docker:dind without TLS, untrusted CI variables in scripts,
    and unsafe deploy job configurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabFinding] | None = None
        self._stats: GitLabStats | None = None
        self._infos: list[GitLabInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return GitLab CI config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GitLabFinding], GitLabInfo]:
        findings: list[GitLabFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitLabInfo(path=rel)

        info = GitLabInfo(path=rel, lines=len(raw_lines))
        in_variables_block = False
        variables_indent = 0
        in_script_block = False
        script_indent = 0
        current_job: str | None = None
        current_job_has_only = False
        deploy_job_without_only = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("stages:") or line == "stages:":
                continue

            if line.startswith("- ") and not in_script_block and not in_variables_block:
                stage = line[2:].strip()
                if stage and not stage.startswith("$"):
                    info.stages.append(stage)

            job_match = re.match(r"^([a-zA-Z0-9_.-]+):\s*$", line)
            if job_match and job_match.group(1) not in (
                "stages",
                "variables",
                "include",
                "default",
                "workflow",
            ):
                current_job = job_match.group(1)
                info.job_count += 1
                current_job_has_only = False
                if DEPLOY_JOB_PATTERN.match(line):
                    info.has_deploy_job = True

            if current_job and line.startswith("only:"):
                current_job_has_only = True

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
                        GitLabFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use GitLab CI/CD variables",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if SECRET_VAR_PATTERN.search(line) and not in_variables_block:
                findings.append(
                    GitLabFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret in GitLab CI config — use masked/protected variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("script:") or line == "script:":
                in_script_block = True
                script_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline:
                    self._check_script_line(findings, rel, lineno, raw, line)
                    in_script_block = False
                continue

            if in_script_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= script_indent and not line.startswith("script"):
                    in_script_block = False
                else:
                    self._check_script_line(findings, rel, lineno, raw, line)

            if UNPINNED_IMAGE_PATTERN.match(line):
                findings.append(
                    GitLabFinding(
                        kind="unpinned_image",
                        severity="low",
                        message="unpinned Docker image — pin to a specific version or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    GitLabFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    GitLabFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged Docker service enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DIND_PATTERN.search(line):
                findings.append(
                    GitLabFinding(
                        kind="docker_dind",
                        severity="medium",
                        message="docker:dind service used — ensure TLS is enabled and images are pinned",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DIND_TLS_DISABLED_PATTERN.search(line):
                findings.append(
                    GitLabFinding(
                        kind="dind_tls_disabled",
                        severity="high",
                        message="DOCKER_TLS_CERTDIR disabled — docker:dind should use TLS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if current_job and DEPLOY_JOB_PATTERN.match(f"{current_job}:"):
                if not current_job_has_only and info.has_deploy_job:
                    deploy_job_without_only = True

        if deploy_job_without_only:
            findings.append(
                GitLabFinding(
                    kind="deploy_without_branch_guard",
                    severity="medium",
                    message="deploy job without only/except guard — restrict to protected branches",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        return findings, info

    def _check_script_line(
        self,
        findings: list[GitLabFinding],
        rel: str,
        lineno: int,
        raw: str,
        line: str,
    ) -> None:
        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                GitLabFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="GitLab script step uses eval/exec — review for injection risk",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                GitLabFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in GitLab script is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if SUDO_PATTERN.search(line):
            findings.append(
                GitLabFinding(
                    kind="sudo_usage",
                    severity="medium",
                    message="sudo in GitLab script — prefer container-based builds without sudo",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if UNTRUSTED_VAR_IN_SCRIPT_PATTERN.search(line):
            findings.append(
                GitLabFinding(
                    kind="untrusted_ci_var",
                    severity="medium",
                    message="untrusted CI variable in script — risk of script injection from MR titles",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )

    def analyze(self) -> list[GitLabFinding]:
        """Scan GitLab CI config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitLabFinding] = []
        infos: list[GitLabInfo] = []
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
        self._stats = GitLabStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GitLabStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GitLabInfo]:
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
        """Scaffold a hardened GitLab CI configuration template."""
        return """\
# Generated by DevAI GitLabCIAnalyzer
stages:
  - test

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

test:
  stage: test
  image: python:3.12.0-slim
  only:
    - main
    - merge_requests
  script:
    - pip install -e ".[dev]"
    - python -m pytest
  cache:
    paths:
      - .cache/pip
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "GitLab CI: no config files found"
        return (
            f"GitLab CI: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitLab CI configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: jobs={info.job_count}, deploy={info.has_deploy_job}, "
                f"stages={len(info.stages)}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
