"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile", "jenkinsfile")

HARDCODED_CRED_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*[=:]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DISABLE_SANDBOX_PATTERN = re.compile(
    r"disableSandbox\s*\(\s*true\s*\)|sandbox\s+false",
    re.IGNORECASE,
)
UNSAFE_GROOVY_PATTERN = re.compile(
    r"\b(eval|execute|GroovyShell|ProcessBuilder)\b",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"image\s*['\"][^'\"]+:latest['\"]",
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
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


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
    lower = name.lower()
    if name in JENKINSFILE_NAMES or lower in JENKINSFILE_NAMES:
        return True
    return lower.endswith(".jenkinsfile")


class JenkinsfileAnalyzer:
    """Audit Jenkinsfiles for security risks and pipeline best practices.

    Scans for hardcoded credentials, disabled sandboxing, unsafe Groovy
    execution, unpinned Docker images, and curl-pipe-to-shell patterns.
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

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue

            if re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line, re.IGNORECASE):
                match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line, re.IGNORECASE)
                if match:
                    info.stages.append(match.group(1))

            if re.search(r"\bdocker\s*\(|image\s*['\"]", line, re.IGNORECASE):
                info.uses_docker = True

            if HARDCODED_CRED_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="hardcoded_credential",
                        severity="high",
                        message="hardcoded credential in pipeline — use Jenkins credentials store",
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

            if DISABLE_SANDBOX_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="sandbox_disabled",
                        severity="high",
                        message="sandbox disabled — pipeline can execute arbitrary code on agent",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNSAFE_GROOVY_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="unsafe_groovy",
                        severity="medium",
                        message="dynamic Groovy execution detected — restrict to trusted inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_IMAGE_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="latest_image",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[JenkinsfileFinding]:
        """Scan Jenkinsfiles and return findings."""
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
        """Return a 0-100 health score."""
        self.analyze()
        stats = self.stats
        if stats.jenkinsfiles == 0:
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
        """Scaffold a hardened Jenkinsfile template."""
        return """\
// Generated by DevAI JenkinsfileAnalyzer
pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
            args '-u root:root'
        }
    }
    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
        stage('Test') {
            steps {
                sh 'pip install -e ".[dev]" && python -m pytest'
            }
        }
    }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.jenkinsfiles == 0:
            return "Jenkinsfile: none found"
        return (
            f"Jenkinsfile: {stats.jenkinsfiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Jenkins pipeline analysis:",
            f"  jenkinsfiles: {stats.jenkinsfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.stages)} stage(s), docker={info.uses_docker}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
