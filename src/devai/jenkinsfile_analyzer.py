"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile", "Jenkinsfile.ci", "jenkinsfile")

SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[=:]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SHELL_STEP_PATTERN = re.compile(r"sh\s+['\"]", re.IGNORECASE)
CREDENTIALS_STRING_PATTERN = re.compile(
    r"['\"][^'\"]*(password|secret|apikey|token)[^'\"]*['\"]",
    re.IGNORECASE,
)
DOCKER_LATEST_PATTERN = re.compile(r":latest['\"]?\s*$", re.IGNORECASE)
UNSAFE_EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)


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

    pipelines: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkinsfile(path: Path) -> bool:
    name = path.name
    if name in JENKINSFILE_NAMES:
        return True
    return name.lower().startswith("jenkinsfile")


class JenkinsfileAnalyzer:
    """Audit Jenkinsfiles for hardcoded secrets, unsafe shell steps, and curl-pipe-to-shell."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JenkinsfileFinding] | None = None
        self._stats: JenkinsfileStats | None = None
        self._infos: list[JenkinsfileInfo] | None = None

    def pipelines(self) -> list[Path]:
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

            if "stage(" in line.lower():
                match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line, re.IGNORECASE)
                if match:
                    info.stages.append(match.group(1))

            if "docker" in line.lower():
                info.uses_docker = True

            if SECRET_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="potential secret hardcoded — use Jenkins credentials store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CREDENTIALS_STRING_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="credential_in_string",
                        severity="high",
                        message="sensitive value in string literal — use withCredentials or env vars",
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

            if SHELL_STEP_PATTERN.search(line) and UNSAFE_EVAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="eval_in_shell",
                        severity="high",
                        message="eval in shell step can execute arbitrary code",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_LATEST_PATTERN.search(line):
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
        if stats.pipelines == 0 or stats.findings == 0:
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
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Jenkins: none found"
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
            lines.append(f"  - {info.path}: {len(info.stages)} stage(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
