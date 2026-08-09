"""GitLabCIAnalyzer — audit GitLab CI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GITLAB_CI_FILENAMES = (".gitlab-ci.yml", ".gitlab-ci.yaml")

SECRET_VAR_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
MUTABLE_IMAGE_TAG_PATTERN = re.compile(
    r"^\s*image:\s*[^:]+:(latest|stable|nightly|dev|main|master)\s*$",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"^\s*image:\s*(?!.*:)[a-z0-9][a-z0-9._/-]*\s*$",
    re.IGNORECASE,
)
PRIVILEGED_SERVICE_PATTERN = re.compile(r"privileged\s*:\s*true\b", re.IGNORECASE)
DIND_SERVICE_PATTERN = re.compile(r"docker:\d[\w.-]*-dind", re.IGNORECASE)
UNPINNED_INCLUDE_PATTERN = re.compile(
    r"^\s*-\s*project:\s*.+\n\s*file:\s*.+\n(?!\s*ref:)",
    re.IGNORECASE | re.MULTILINE,
)
REMOTE_INCLUDE_PATTERN = re.compile(
    r"remote:\s*https?://",
    re.IGNORECASE,
)
UNTRUSTED_INPUT_SCRIPT_PATTERN = re.compile(
    r"\$\{?CI_(COMMIT_MESSAGE|COMMIT_DESCRIPTION|MERGE_REQUEST_TITLE)\}?",
    re.IGNORECASE,
)
ALLOW_FAILURE_PATTERN = re.compile(r"^\s*allow_failure\s*:\s*true\b", re.IGNORECASE)
DEPRECATED_ONLY_PATTERN = re.compile(r"^\s*(only|except)\s*:", re.IGNORECASE)
INSECURE_ARTIFACT_ACCESS_PATTERN = re.compile(
    r"^\s*access\s*:\s*all\b",
    re.IGNORECASE,
)
UNPROTECTED_MANUAL_DEPLOY_PATTERN = re.compile(
    r"^\s*when\s*:\s*manual\b",
    re.IGNORECASE,
)


@dataclass
class GitLabCIFinding:
    """A security or best-practice issue in a GitLab CI config."""

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
    """Parsed metadata about a GitLab CI config file."""

    path: str
    stages: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    includes: int = 0
    uses_docker: bool = False
    lines: int = 0


@dataclass
class GitLabCIStats:
    """Aggregate GitLab CI analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gitlab_ci_file(path: Path) -> bool:
    return path.name.lower() in GITLAB_CI_FILENAMES


class GitLabCIAnalyzer:
    """Audit GitLab CI configuration files for security risks and CI best practices.

    Scans for hardcoded secrets, curl-pipe-to-shell scripts, unpinned Docker images,
  privileged services, untrusted CI variable injection, and deprecated directives.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitLabCIFinding] | None = None
        self._stats: GitLabCIStats | None = None
        self._infos: list[GitLabCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return GitLab CI config file paths found in the project."""
        found: list[Path] = []
        for name in GITLAB_CI_FILENAMES:
            direct = self.root / name
            if direct.is_file():
                found.append(direct)
        for path in sorted(self.root.rglob("*.gitlab-ci.yml")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("*.gitlab-ci.yaml")):
            if path.is_file() and path not in found:
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
        in_variables_block = False
        variables_indent = 0
        current_job: str | None = None
        in_script_block = False
        script_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("stages:"):
                continue

            if re.match(r"^\s*-\s+\w", raw) and "stages:" in "\n".join(
                raw_lines[max(0, lineno - 5) : lineno]
            ):
                stage = line[2:].strip()
                if stage and stage not in info.stages:
                    info.stages.append(stage)

            if line.endswith(":") and not line.startswith("-") and not line.startswith(" "):
                key = line[:-1].strip()
                if key in ("variables", "default"):
                    in_variables_block = True
                    variables_indent = len(raw) - len(raw.lstrip())
                elif key == "script":
                    in_script_block = True
                    script_indent = len(raw) - len(raw.lstrip())
                elif key in ("before_script", "after_script"):
                    in_script_block = True
                    script_indent = len(raw) - len(raw.lstrip())
                else:
                    if in_script_block and len(raw) - len(raw.lstrip()) <= script_indent:
                        in_script_block = False
                    if in_variables_block and len(raw) - len(raw.lstrip()) <= variables_indent:
                        in_variables_block = False
                    if key not in ("include", "stages", "default", "workflow"):
                        current_job = key
                        if key not in info.jobs:
                            info.jobs.append(key)

            if line.startswith("include:"):
                info.includes += 1

            if line.startswith("image:") or re.match(r"^\s*-\s*image:", raw):
                info.uses_docker = True
                if MUTABLE_IMAGE_TAG_PATTERN.match(line) or UNPINNED_IMAGE_PATTERN.match(line):
                    findings.append(
                        GitLabCIFinding(
                            kind="unpinned_image",
                            severity="medium",
                            message="Docker image unpinned or uses mutable tag — pin to a specific version",
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
                        message="privileged service grants full host access to the job",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DIND_SERVICE_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="docker_in_docker",
                        severity="medium",
                        message="docker-in-docker service increases attack surface — prefer Kaniko or buildah",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_variables_block and SECRET_VAR_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > variables_indent and "vault" not in line.lower():
                    findings.append(
                        GitLabCIFinding(
                            kind="secret_in_variables",
                            severity="high",
                            message="potential secret hardcoded in variables — use GitLab CI/CD variables or vault",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            script_context = in_script_block or line.startswith("- ") or "script:" in line
            if script_context:
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
                if UNTRUSTED_INPUT_SCRIPT_PATTERN.search(line):
                    findings.append(
                        GitLabCIFinding(
                            kind="untrusted_input_in_script",
                            severity="medium",
                            message="CI commit/MR message used in script — risk of script injection from untrusted input",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if REMOTE_INCLUDE_PATTERN.search(line):
                findings.append(
                    GitLabCIFinding(
                        kind="remote_include",
                        severity="medium",
                        message="remote include from URL — pin to a specific ref and verify source integrity",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DEPRECATED_ONLY_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="deprecated_only_except",
                        severity="low",
                        message="only/except is deprecated — use rules: instead",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_FAILURE_PATTERN.match(line) and current_job:
                findings.append(
                    GitLabCIFinding(
                        kind="allow_failure",
                        severity="low",
                        message="allow_failure: true may hide security or test failures",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_ARTIFACT_ACCESS_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="public_artifact_access",
                        severity="medium",
                        message="artifacts access: all exposes build artifacts to all jobs — restrict access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPROTECTED_MANUAL_DEPLOY_PATTERN.match(line):
                findings.append(
                    GitLabCIFinding(
                        kind="manual_deploy",
                        severity="low",
                        message="manual deploy job — ensure protected branches and environment approvals",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        content = path.read_text(encoding="utf-8", errors="replace")
        for match in UNPINNED_INCLUDE_PATTERN.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            findings.append(
                GitLabCIFinding(
                    kind="unpinned_include",
                    severity="medium",
                    message="project include without ref — pin to a tag or commit SHA",
                    path=rel,
                    lineno=line_no,
                    line=match.group(0).splitlines()[0].strip(),
                )
            )

        return findings, info

    def analyze(self) -> list[GitLabCIFinding]:
        """Scan GitLab CI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitLabCIFinding] = []
        infos: list[GitLabCIInfo] = []
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
        self._stats = GitLabCIStats(
            configs=len(paths),
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
        """Return parsed GitLab CI metadata."""
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
        """Scaffold a hardened GitLab CI configuration template."""
        return """\
# Generated by DevAI GitLabCIAnalyzer
stages:
  - test

variables:
  PIP_DISABLE_PIP_VERSION_CHECK: "1"

default:
  image: python:3.12-slim
  before_script:
    - pip install -e ".[dev]"

test:
  stage: test
  script:
    - python -m pytest
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "GitLab CI: none found"
        return (
            f"GitLab CI: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "GitLab CI analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: jobs={len(info.jobs)}, stages={len(info.stages)}, "
                f"includes={info.includes}, docker={info.uses_docker}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
