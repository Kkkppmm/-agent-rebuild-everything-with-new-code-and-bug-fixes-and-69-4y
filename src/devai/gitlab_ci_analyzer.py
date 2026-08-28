"""GitLabCIAnalyzer — audit GitLab CI/CD pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GITLAB_CI_NAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")
GITLAB_CI_DIRS = (".gitlab", "ci", "gitlab")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"image:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
PRIVILEGED_SERVICE_PATTERN = re.compile(
    r"privileged:\s*true\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:- |\s)(?:script|before_script|after_script):\s*.*\$\{?[A-Z_]+\}?",
    re.IGNORECASE,
)
UNSAFE_JOB_TOKEN_PATTERN = re.compile(
    r"CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|CI_DEPLOY_PASSWORD",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
ALLOW_FAILURE_SECURITY_PATTERN = re.compile(
    r"^\s*allow_failure:\s*true\b",
    re.IGNORECASE,
)
UNPINNED_INCLUDE_PATTERN = re.compile(
    r"include:\s*\n(?:\s+-\s+)?(?:remote|project|template):\s*",
    re.IGNORECASE,
)
FLOATING_REF_PATTERN = re.compile(
    r"ref:\s*(main|master|latest|develop)\s*$",
    re.IGNORECASE,
)
UNTRUSTED_MR_TRIGGER_PATTERN = re.compile(
    r"^\s*-\s*merge_requests\s*$",
    re.IGNORECASE,
)
SHELL_EXECUTOR_PATTERN = re.compile(
    r"^\s*tags:\s*$",
    re.IGNORECASE,
)


@dataclass
class GitLabCIFinding:
    """A security or best-practice issue in a GitLab CI file."""

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
class GitLabCIInfo:
    """Parsed metadata about a GitLab CI file."""

    path: str
    stages: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    includes: int = 0
    lines: int = 0


@dataclass
class GitLabCIStats:
    """Aggregate GitLab CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gitlab_ci_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in GITLAB_CI_NAMES:
        return True
    if lower.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(GITLAB_CI_DIRS) and lower.endswith((".yml", ".yaml")):
        if "gitlab" in lower or "ci" in lower:
            return True
    return False


class GitLabCIAnalyzer:
    """Audit GitLab CI/CD pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans ``.gitlab-ci.yml`` and included CI files for curl-pipe-to-shell, privileged
    services, floating image tags, script injection via unquoted variables, and
    hardcoded credentials in ``variables`` blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabCIFinding] | None = None
        self._stats: GitLabCIStats | None = None
        self._infos: list[GitLabCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return GitLab CI file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_gitlab_ci_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GitLabCIFinding], GitLabCIInfo]:
        findings: list[GitLabCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitLabCIInfo(path=rel)

        info = GitLabCIInfo(path=rel, lines=len(raw_lines))
        in_variables = False
        in_script = False
        variables_indent = 0
        script_indent = 0
        current_job: str | None = None
        has_mr_trigger = False
        in_security_job = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("stages:"):
                in_variables = False
                in_script = False
                continue

            if line.startswith("- ") and not in_script and not in_variables:
                stage = line[2:].strip()
                if stage and stage not in info.stages:
                    info.stages.append(stage)

            if line.startswith("include:"):
                info.includes += 1
                in_variables = False
                in_script = False
                continue

            if FLOATING_REF_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="floating_ref",
                        severity="medium",
                        message="include ref pinned to mutable branch — pin to a tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("variables", "before_script", "script", "after_script"):
                    if key == "variables":
                        in_variables = True
                        variables_indent = len(raw) - len(raw.lstrip())
                    elif key in ("script", "before_script", "after_script"):
                        in_script = True
                        script_indent = len(raw) - len(raw.lstrip())
                    continue
                if key not in (
                    "stages",
                    "include",
                    "image",
                    "services",
                    "cache",
                    "artifacts",
                    "rules",
                    "workflow",
                    "default",
                ):
                    if key and key[0].isalpha():
                        current_job = key
                        info.jobs.append(key)
                        in_security_job = any(
                            token in key.lower()
                            for token in ("security", "audit", "scan", "sast", "dast")
                        )
                        in_variables = False
                        in_script = False

            if UNTRUSTED_MR_TRIGGER_PATTERN.match(line):
                has_mr_trigger = True

            if in_variables and HARDCODED_SECRET_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > variables_indent:
                    findings.append(
                        GitLabCIFinding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="potential secret hardcoded in variables — use GitLab CI/CD variables",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_SERVICE_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="privileged_service",
                        severity="high",
                        message="privileged: true in service — avoid privileged containers",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
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
                            GitLabCIFinding(
                                kind="curl_pipe_shell",
                                severity="high",
                                message="piping curl/wget to shell in CI script is unsafe",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    if SCRIPT_INJECTION_PATTERN.search(line):
                        findings.append(
                            GitLabCIFinding(
                                kind="script_injection",
                                severity="high",
                                message=(
                                    "unquoted CI variable in script — use double quotes "
                                    "and validate untrusted input"
                                ),
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    if has_mr_trigger and UNSAFE_JOB_TOKEN_PATTERN.search(line):
                        findings.append(
                            GitLabCIFinding(
                                kind="job_token_in_mr",
                                severity="medium",
                                message=(
                                    "CI_JOB_TOKEN used in merge request pipeline — "
                                    "restrict token scope for untrusted forks"
                                ),
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if line.startswith("- ") and CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in CI script is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_FAILURE_SECURITY_PATTERN.match(line) and in_security_job:
                findings.append(
                    GitLabCIFinding(
                        kind="security_allow_failure",
                        severity="medium",
                        message="allow_failure: true on security job — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and "http://" in line.lower():
                findings.append(
                    GitLabCIFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key not in ("variables", "script", "before_script", "after_script"):
                    in_variables = False

        return findings, info

    def analyze(self) -> list[GitLabCIFinding]:
        """Scan GitLab CI files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitLabCIFinding] = []
        infos: list[GitLabCIInfo] = []
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
        self._stats = GitLabCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GitLabCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GitLabCIInfo]:
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
        """Scaffold a hardened GitLab CI pipeline template."""
        return """\
# Generated by DevAI GitLabCIAnalyzer
stages:
  - test
  - security

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

test:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install -e ".[dev]"
  script:
    - python -m pytest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

security_scan:
  stage: security
  image: python:3.12-slim
  script:
    - pip install devai
    - devai security-scan .
  allow_failure: false
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "GitLab CI: none found"
        return (
            f"GitLab CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitLab CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.jobs)} job(s), stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
