"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile", "jenkinsfile")
JENKINSFILE_SUFFIXES = (".jenkins", ".jenkinsfile")

UNPINNED_PLUGIN_PATTERN = re.compile(
    r"^\s*(?:@Library\s*\(\s*['\"][^'\"]+['\"]\s*\)|library\s+['\"][^'\"]+['\"])\s*$",
    re.IGNORECASE,
)
MUTABLE_LIBRARY_PATTERN = re.compile(
    r"(?:@Library\s*\(\s*['\"][^'\"]+['\"]\s*\)|library\s+['\"][^'\"]+['\"])\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
DANGEROUS_SH_PATTERN = re.compile(
    r"sh\s+['\"].*\b(eval|exec|sudo)\b",
    re.IGNORECASE,
)
PARAM_IN_SH_PATTERN = re.compile(
    r"sh\s+['\"].*\$\{?\s*(params|env)\.",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"privileged\s*:?\s*true\b",
    re.IGNORECASE,
)
HOST_MOUNT_PATTERN = re.compile(
    r"args\s+['\"].*(/:/|\\-v\s+/)",
    re.IGNORECASE,
)
MUTABLE_LIBRARY_REF_PATTERN = re.compile(
    r"@(?:main|master|develop|latest)\b",
    re.IGNORECASE,
)
CREDENTIALS_STRING_PATTERN = re.compile(
    r"credentials\s*\(\s*['\"][^'\"]+['\"]\s*\)",
    re.IGNORECASE,
)
DISABLE_CONCURRENT_BUILDS_PATTERN = re.compile(
    r"disableConcurrentBuilds\s*\(\s*\)",
    re.IGNORECASE,
)
TIMESTAMPS_PATTERN = re.compile(
    r"timestamps\s*\(\s*\)",
    re.IGNORECASE,
)


@dataclass
class JenkinsfileFinding:
    """A security or best-practice issue in a Jenkins pipeline file."""

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
class JenkinsfileInfo:
    """Parsed metadata about a Jenkins pipeline file."""

    path: str
    has_agent: bool = False
    has_options: bool = False
    has_timestamps: bool = False
    has_disable_concurrent: bool = False
    stages: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class JenkinsfileStats:
    """Aggregate Jenkinsfile analysis statistics."""

    pipelines: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkinsfile(path: Path) -> bool:
    name = path.name
    if name in JENKINSFILE_NAMES:
        return True
    lower = name.lower()
    if lower.endswith(JENKINSFILE_SUFFIXES):
        return True
    if "jenkins" in path.parts and lower.endswith((".yml", ".yaml", ".groovy")):
        return True
    return False


class JenkinsfileAnalyzer:
    """Audit Jenkins pipeline files for security risks and CI best practices.

    Scans Jenkinsfiles for unpinned shared libraries, secrets in environment
    blocks, curl-pipe-to-shell patterns, dangerous shell steps, unvalidated
  parameter interpolation, privileged Docker agents, and missing pipeline options.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JenkinsfileFinding] | None = None
        self._stats: JenkinsfileStats | None = None
        self._infos: list[JenkinsfileInfo] | None = None

    def pipelines(self) -> list[Path]:
        """Return Jenkins pipeline file paths found in the project."""
        found: list[Path] = []
        for name in JENKINSFILE_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_jenkinsfile(path) and path not in found:
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[JenkinsfileFinding], JenkinsfileInfo]:
        findings: list[JenkinsfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JenkinsfileInfo(path=rel)

        info = JenkinsfileInfo(path=rel, lines=len(raw_lines))
        in_env_block = False
        env_indent = 0
        in_options = False
        options_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue

            if re.match(r"^agent\s*\{", line) or line.startswith("agent "):
                info.has_agent = True

            if line.startswith("options") and line.endswith("{") or line == "options {":
                info.has_options = True
                in_options = True
                options_indent = len(raw) - len(raw.lstrip())
                continue

            if in_options:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= options_indent and not line.startswith("options"):
                    in_options = False
                if TIMESTAMPS_PATTERN.search(line):
                    info.has_timestamps = True
                if DISABLE_CONCURRENT_BUILDS_PATTERN.search(line):
                    info.has_disable_concurrent = True

            if re.match(r"^stage\s*\(\s*['\"]", line):
                match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line)
                if match:
                    info.stages.append(match.group(1))

            if line.startswith("environment") and line.endswith("{") or line == "environment {":
                in_env_block = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_env_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= env_indent and not line.startswith("environment"):
                    in_env_block = False
                elif SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        JenkinsfileFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in environment — use Jenkins credentials",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if "@Library" in line or line.lower().startswith("library "):
                if MUTABLE_LIBRARY_REF_PATTERN.search(line):
                    findings.append(
                        JenkinsfileFinding(
                            kind="mutable_library",
                            severity="high",
                            message="shared library pinned to mutable branch — pin to a tag or commit",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                elif UNPINNED_PLUGIN_PATTERN.search(line):
                    findings.append(
                        JenkinsfileFinding(
                            kind="unpinned_library",
                            severity="medium",
                            message="shared library without version pin — pin to a specific tag or commit",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in pipeline step is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DANGEROUS_SH_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="dangerous_sh",
                        severity="high",
                        message="shell step uses eval/exec/sudo — review for injection risk",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PARAM_IN_SH_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="param_in_sh",
                        severity="medium",
                        message="params/env interpolated in shell step — validate untrusted input",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="Docker agent runs in privileged mode — avoid unless required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_MOUNT_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="host_mount",
                        severity="medium",
                        message="host path mount in Docker agent — restrict mount paths",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CREDENTIALS_STRING_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="credentials_string",
                        severity="medium",
                        message="credentials() with string ID — ensure ID is not hardcoded secret value",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.has_options and not info.has_timestamps:
            findings.append(
                JenkinsfileFinding(
                    kind="missing_timestamps",
                    severity="low",
                    message="options block missing timestamps() — add for build log clarity",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        if not info.has_disable_concurrent and info.stages:
            findings.append(
                JenkinsfileFinding(
                    kind="missing_disable_concurrent",
                    severity="low",
                    message="consider disableConcurrentBuilds() to avoid overlapping deploys",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[JenkinsfileFinding]:
        """Scan Jenkins pipeline files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JenkinsfileFinding] = []
        infos: list[JenkinsfileInfo] = []
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
        self._stats = JenkinsfileStats(
            pipelines=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JenkinsfileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JenkinsfileInfo]:
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
        """Scaffold a hardened Jenkins pipeline template."""
        return """\
// Generated by DevAI JenkinsfileAnalyzer
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        CI = 'true'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Test') {
            steps {
                sh 'python -m pytest'
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Jenkins: no pipeline files found"
        return (
            f"Jenkins: {stats.pipelines} pipeline(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Jenkins pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.stages)} stage(s) [{stages}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
