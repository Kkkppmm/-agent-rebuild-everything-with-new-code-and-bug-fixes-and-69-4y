"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("jenkinsfile",)
JENKINS_DIRS = ("jenkins", ".jenkins")

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[=:]\s*"
    r"['\"][^'\"${}\s][^'\"]*['\"]",
    re.IGNORECASE,
)
INSECURE_TLS_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n]*(-k|--insecure)\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\s+", re.IGNORECASE)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"docker\s+run\b[^\n]*--privileged\b", re.IGNORECASE)
HTTP_URL_PATTERN = re.compile(r"['\"]http://[^\s'\"]+['\"]", re.IGNORECASE)
PARAM_INTERPOLATION_PATTERN = re.compile(
    r"(sh|bat|powershell|pwsh)\s+['\"]{3}.*\$\{(params|env)\.",
    re.IGNORECASE | re.DOTALL,
)
PLAIN_TEXT_PASSWORD_PATTERN = re.compile(
    r"(password|passwd|secret)\s*=\s*['\"][^'\"${}\s][^'\"]+['\"]",
    re.IGNORECASE,
)
UNPINNED_LIBRARY_PATTERN = re.compile(
    r"@Library\s*\(\s*['\"][^'\"]+@(?:main|master|latest|HEAD)['\"]\s*\)",
    re.IGNORECASE,
)
AGENT_ANY_PATTERN = re.compile(r"^\s*agent\s+any\b", re.IGNORECASE)
DISABLE_CONCURRENT_BUILDS_FALSE_PATTERN = re.compile(
    r"disableConcurrentBuilds\s*\(\s*false\s*\)",
    re.IGNORECASE,
)
SKIP_DEFAULT_CHECKOUT_PATTERN = re.compile(
    r"skipDefaultCheckout\s*\(\s*\)",
    re.IGNORECASE,
)
WRITEFILE_SECRET_PATTERN = re.compile(
    r"writeFile\b[^\n]*(password|secret|token|credential|\.pem|\.key)",
    re.IGNORECASE,
)
ARCHIVE_CREDENTIALS_PATTERN = re.compile(
    r"archiveArtifacts\b[^\n]*(credentials|\.pem|\.key|id_rsa|secret)",
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
    agents: list[str] = field(default_factory=list)
    lines: int = 0
    declarative: bool = False


@dataclass
class JenkinsfileStats:
    """Aggregate Jenkinsfile analysis statistics."""

    jenkinsfiles: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkinsfile(path: Path) -> bool:
    lower = path.name.lower()
    if lower == "jenkinsfile" or lower.startswith("jenkinsfile."):
        return True
    if path.suffix.lower() in (".groovy", ".jenkins"):
        parts = {p.lower() for p in path.parts}
        if parts & set(JENKINS_DIRS):
            return True
    return False


def _looks_like_jenkins_pipeline(content: str) -> bool:
    """Heuristic for Groovy files that are Jenkins pipelines."""
    lowered = content.lower()
    markers = ("pipeline {", "stages {", "agent ", "stage(", "node {")
    return sum(1 for m in markers if m in lowered) >= 2


class JenkinsfileAnalyzer:
    """Audit Jenkinsfiles for security risks and CI best practices.

    Scans for curl-pipe-to-shell, hardcoded secrets, insecure TLS,
    privileged Docker, parameter injection in shell steps, unpinned
    shared libraries, and unsafe artifact archiving.
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
            if not path.is_file():
                continue
            if _is_jenkinsfile(path):
                found.append(path)
                continue
            if path.suffix.lower() == ".groovy":
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _looks_like_jenkins_pipeline(content):
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
        content = "\n".join(raw_lines)
        if "pipeline {" in content.lower() or "pipeline{" in content.lower():
            info.declarative = True

        in_environment = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//"):
                continue

            if re.match(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line, re.IGNORECASE):
                match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line, re.IGNORECASE)
                if match:
                    info.stages.append(match.group(1))

            if re.match(r"agent\s+", line, re.IGNORECASE):
                agent_val = line.split(None, 1)[1].strip().rstrip("{")
                info.agents.append(agent_val)

            if line.startswith("environment") and "{" in line:
                in_environment = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_environment and line == "}":
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= env_indent:
                    in_environment = False

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

            if in_environment and SECRET_ENV_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="secret_in_environment",
                        severity="high",
                        message="potential secret hardcoded in environment — use Jenkins credentials",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAIN_TEXT_PASSWORD_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="plain_text_password",
                        severity="high",
                        message="plaintext password/secret in pipeline — use withCredentials or credentials binding",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_TLS_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="insecure_tls",
                        severity="medium",
                        message="curl/wget with -k/--insecure disables TLS verification",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(line) and ("sh " in line or "sh'" in line or 'sh"' in line):
                findings.append(
                    JenkinsfileFinding(
                        kind="sudo_in_shell",
                        severity="medium",
                        message="sudo in shell step — prefer least-privilege agent configuration",
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
                        message="docker run --privileged grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HTTP_URL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="http_url",
                        severity="low",
                        message="HTTP URL in pipeline — prefer HTTPS for downloads and webhooks",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_LIBRARY_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="unpinned_library",
                        severity="high",
                        message="shared library pinned to mutable branch — pin to a specific version/tag",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AGENT_ANY_PATTERN.match(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="agent_any",
                        severity="low",
                        message="agent any runs on any executor — use labeled agents for isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DISABLE_CONCURRENT_BUILDS_FALSE_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="concurrent_builds",
                        severity="low",
                        message="disableConcurrentBuilds(false) allows overlapping deploys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_DEFAULT_CHECKOUT_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="skip_default_checkout",
                        severity="medium",
                        message="skipDefaultCheckout() can run steps without a trusted workspace checkout",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if WRITEFILE_SECRET_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="writefile_secret",
                        severity="high",
                        message="writeFile referencing secrets may persist credentials on disk",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ARCHIVE_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="archive_credentials",
                        severity="high",
                        message="archiveArtifacts may expose credentials or private keys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if PARAM_INTERPOLATION_PATTERN.search(content):
            for lineno, raw in enumerate(raw_lines, start=1):
                if "${params." in raw or "${env." in raw:
                    if re.search(r"(sh|bat|powershell)\s+['\"]{3}", raw, re.IGNORECASE):
                        findings.append(
                            JenkinsfileFinding(
                                kind="parameter_injection",
                                severity="medium",
                                message=(
                                    "params/env interpolated in multiline shell — "
                                    "pass via withEnv and single-quoted strings"
                                ),
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                        break

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
        """Return parsed Jenkinsfile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no Jenkinsfiles)."""
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
        """Scaffold a hardened Jenkins declarative pipeline template."""
        return """\
// Generated by DevAI JenkinsfileAnalyzer
@Library('shared-pipeline@v1.2.3') _

pipeline {
    agent {
        label 'linux'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    environment {
        PYTHON_VERSION = '3.12'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install') {
            steps {
                sh '''
                    python -m pip install --upgrade pip
                    pip install -e ".[dev]"
                '''
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
        if stats.jenkinsfiles == 0:
            return "Jenkinsfiles: none found"
        return (
            f"Jenkinsfiles: {stats.jenkinsfiles} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
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
            lines.append(f"  {info.path}: {len(info.stages)} stage(s) [{stages}]")
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
