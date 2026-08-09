"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile",)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
HARDCODED_CREDENTIAL_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"--privileged\b|privileged\s*:\s*true", re.IGNORECASE)
CREDENTIALS_IN_ECHO_PATTERN = re.compile(
    r"echo\s+.*\$\{?\s*(PASSWORD|SECRET|TOKEN|CREDENTIALS?)\s*\}?",
    re.IGNORECASE,
)
UNTRUSTED_INPUT_PATTERN = re.compile(
    r"(params\.|env\.CHANGE_TITLE|env\.CHANGE_BRANCH|env\.GIT_COMMIT_MESSAGE)",
    re.IGNORECASE,
)
SHELL_INTERPOLATION_PATTERN = re.compile(
    r"sh\s+['\"].*\$\{?(params|env)\.",
    re.IGNORECASE,
)


@dataclass
class JenkinsfileFinding:
    """A security or best-practice issue in a Jenkinsfile."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    stage: str = ""
    line: str = ""

    def format(self) -> str:
        stage = f" ({self.stage})" if self.stage else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{stage} — {self.message}"


@dataclass
class JenkinsfileInfo:
    """Parsed metadata about a Jenkinsfile."""

    path: str
    stages: list[str] = field(default_factory=list)
    uses_docker: bool = False
    lines: int = 0


@dataclass
class JenkinsfileStats:
    """Aggregate Jenkinsfile analysis statistics."""

    jenkinsfiles: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkinsfile(path: Path) -> bool:
    name = path.name
    if name in JENKINSFILE_NAMES:
        return True
    return name.startswith("Jenkinsfile.") and path.suffix in ("", ".groovy")


class JenkinsfileAnalyzer:
    """Audit Jenkins pipelines for security risks and CI best practices.

    Scans for curl-pipe-to-shell, hardcoded credentials, docker socket mounts,
    privileged containers, credential leakage in echo, and shell injection via params.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JenkinsfileFinding] | None = None
        self._stats: JenkinsfileStats | None = None
        self._infos: list[JenkinsfileInfo] | None = None

    def jenkinsfiles(self) -> list[Path]:
        """Return Jenkinsfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_jenkinsfile(path):
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
        current_stage = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//"):
                continue

            if re.match(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", line):
                match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", line)
                if match:
                    current_stage = match.group(1)
                    info.stages.append(current_stage)

            if "docker" in line.lower():
                info.uses_docker = True

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in pipeline step is unsafe",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_CREDENTIAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="hardcoded_credential",
                        severity="high",
                        message="hardcoded credential in Jenkinsfile — use Jenkins credentials store",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="docker_sock",
                        severity="high",
                        message="docker socket mount grants host-level access",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged container enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if CREDENTIALS_IN_ECHO_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="credentials_in_echo",
                        severity="high",
                        message="credentials may be logged via echo — mask sensitive values",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

            if SHELL_INTERPOLATION_PATTERN.search(line) and UNTRUSTED_INPUT_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="shell_injection",
                        severity="high",
                        message="untrusted input interpolated into shell command — use quoting or env vars",
                        path=rel,
                        lineno=lineno,
                        stage=current_stage,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[JenkinsfileFinding]:
        if self._findings is not None:
            return self._findings

        findings: list[JenkinsfileFinding] = []
        infos: list[JenkinsfileInfo] = []
        paths = self.jenkinsfiles()

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
            jenkinsfiles=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JenkinsfileStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JenkinsfileInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.jenkinsfiles == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        return """\
// Generated by DevAI JenkinsfileAnalyzer
pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
            args '-u root:root'
        }
    }
    stages {
        stage('Test') {
            steps {
                sh 'pip install -e ".[dev]"'
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
        self.analyze()
        stats = self.stats
        if stats.jenkinsfiles == 0:
            return "Jenkinsfiles: none found"
        return (
            f"Jenkinsfiles: {stats.jenkinsfiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Jenkinsfile analysis:",
            f"  jenkinsfiles: {stats.jenkinsfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(f"  - {info.path}: stages=[{stages}], docker={info.uses_docker}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
