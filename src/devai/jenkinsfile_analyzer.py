"""JenkinsfileAnalyzer — audit Jenkins pipelines for script injection and hardcoded secrets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

JENKINS_DIRS = ("jenkins", "ci", ".jenkins", "pipelines")
JENKINS_NAMES = ("jenkinsfile",)
JENKINS_SUFFIXES = (".jenkinsfile", ".groovy")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api_?key|token|credential|auth)\s*[=:]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"docker\s+run\b[^\n]*--privileged\b", re.IGNORECASE)
SUDO_PATTERN = re.compile(r"\bsudo\s+", re.IGNORECASE)
AGENT_ANY_PATTERN = re.compile(r"^\s*agent\s+any\s*$", re.IGNORECASE)
SH_DOUBLE_QUOTE_PATTERN = re.compile(r"""sh\s+["'][^"']*\$\{?(?:params|env)\.""", re.IGNORECASE)
ECHO_CREDENTIALS_PATTERN = re.compile(
    r"(?:echo|println|print)\s+.*\bcredentials\b",
    re.IGNORECASE,
)
INPUT_WITHOUT_TIMEOUT_PATTERN = re.compile(r"^\s*input\s+", re.IGNORECASE)
TIMEOUT_PATTERN = re.compile(r"^\s*timeout\s*\(", re.IGNORECASE)
DISABLE_CONCURRENT_PATTERN = re.compile(r"^\s*disableConcurrentBuilds\s*\(", re.IGNORECASE)
PIPELINE_PATTERN = re.compile(r"^\s*pipeline\s*\{", re.IGNORECASE)
MASTER_AGENT_PATTERN = re.compile(r"^\s*agent\s*\{\s*label\s+['\"]master['\"]", re.IGNORECASE)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"-v\s+/var/run/docker\.sock:/var/run/docker\.sock",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SKIP_DEFAULT_CHECKOUT_PATTERN = re.compile(r"^\s*skipDefaultCheckout\s*\(\s*true\s*\)", re.IGNORECASE)
WITH_CREDENTIALS_ECHO_PATTERN = re.compile(
    r"withCredentials\s*\([^)]*\)[^{]*\{[^}]*(?:echo|println)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class JenkinsFinding:
    """A security issue in a Jenkins pipeline file."""

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
class JenkinsPipelineInfo:
    """Parsed metadata about a Jenkins pipeline file."""

    path: str
    stages: int = 0
    lines: int = 0
    is_declarative: bool = False


@dataclass
class JenkinsStats:
    """Aggregate Jenkins pipeline analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkins_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in JENKINS_NAMES or lower == "jenkinsfile":
        return True
    if lower.endswith(JENKINS_SUFFIXES):
        return True
    if lower.startswith("jenkinsfile."):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(JENKINS_DIRS) and lower.endswith((".groovy", ".jenkinsfile")):
        return True
    return False


class JenkinsfileAnalyzer:
    """Audit Jenkinsfiles for script injection, hardcoded secrets, and unsafe shell steps.

    Scans declarative and scripted pipelines for curl-pipe-to-shell, privileged Docker,
    hardcoded credentials in environment blocks, and Groovy injection via interpolated sh steps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JenkinsFinding] | None = None
        self._stats: JenkinsStats | None = None
        self._infos: list[JenkinsPipelineInfo] | None = None

    def files(self) -> list[Path]:
        """Return Jenkins pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_jenkins_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[JenkinsFinding], JenkinsPipelineInfo]:
        findings: list[JenkinsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JenkinsPipelineInfo(path=rel)

        info = JenkinsPipelineInfo(path=rel, lines=len(raw_lines))
        has_timeout = False
        has_disable_concurrent = False
        in_input_block = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//"):
                continue

            if PIPELINE_PATTERN.search(line):
                info.is_declarative = True

            if re.match(r"^\s*stage\s*\(", line, re.IGNORECASE):
                info.stages += 1

            if TIMEOUT_PATTERN.search(line):
                has_timeout = True

            if DISABLE_CONCURRENT_PATTERN.search(line):
                has_disable_concurrent = True

            if INPUT_WITHOUT_TIMEOUT_PATTERN.search(line):
                in_input_block = True

            if in_input_block and line == "}":
                in_input_block = False

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in pipeline — use Jenkins credentials store or secret manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and use checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="docker run --privileged grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="mounting docker.sock gives container root-equivalent host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(line) and "sh " in line.lower():
                findings.append(
                    JenkinsFinding(
                        kind="sudo_in_shell",
                        severity="medium",
                        message="sudo in shell step — prefer dedicated agents with correct permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SH_DOUBLE_QUOTE_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="groovy_injection",
                        severity="high",
                        message="sh step interpolates params/env — use single quotes or sanitize input",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ECHO_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="credential_exposure",
                        severity="high",
                        message="echo/print may leak credentials to build logs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AGENT_ANY_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="agent_any",
                        severity="low",
                        message="agent any runs on any executor — pin to labeled agents for isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MASTER_AGENT_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="master_agent",
                        severity="medium",
                        message="running builds on the Jenkins master is discouraged — use agents",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_DEFAULT_CHECKOUT_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="skip_default_checkout",
                        severity="low",
                        message="skipDefaultCheckout(true) — verify manual checkout is secure",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (
                INSECURE_HTTP_PATTERN.search(line)
                and "sh " in line.lower()
                and "https://" not in line.lower()
            ):
                findings.append(
                    JenkinsFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="shell step uses plain HTTP — prefer HTTPS for remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        content = "\n".join(raw_lines)
        if WITH_CREDENTIALS_ECHO_PATTERN.search(content):
            findings.append(
                JenkinsFinding(
                    kind="withcredentials_echo",
                    severity="high",
                    message="withCredentials block may echo secrets to logs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if in_input_block or any(
            INPUT_WITHOUT_TIMEOUT_PATTERN.search(raw_lines[i])
            for i in range(len(raw_lines))
        ):
            input_lines = [
                i
                for i, raw in enumerate(raw_lines, start=1)
                if INPUT_WITHOUT_TIMEOUT_PATTERN.search(raw)
            ]
            for input_lineno in input_lines:
                window = raw_lines[input_lineno - 1 : input_lineno + 10]
                if not any(TIMEOUT_PATTERN.search(w) for w in window):
                    findings.append(
                        JenkinsFinding(
                            kind="input_without_timeout",
                            severity="medium",
                            message="input step without timeout can block builds indefinitely",
                            path=rel,
                            lineno=input_lineno,
                            line=raw_lines[input_lineno - 1].strip(),
                        )
                    )

        if info.is_declarative and info.stages > 0 and not has_timeout:
            findings.append(
                JenkinsFinding(
                    kind="missing_timeout",
                    severity="low",
                    message="pipeline without global timeout — add options { timeout(...) }",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.is_declarative and not has_disable_concurrent and info.stages > 2:
            findings.append(
                JenkinsFinding(
                    kind="missing_disable_concurrent",
                    severity="low",
                    message="consider disableConcurrentBuilds() for multi-stage deploy pipelines",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[JenkinsFinding]:
        """Scan Jenkins pipeline files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JenkinsFinding] = []
        infos: list[JenkinsPipelineInfo] = []
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
        self._stats = JenkinsStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> JenkinsStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[JenkinsPipelineInfo]:
        """Return parsed Jenkins pipeline metadata."""
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

    def generate_hardened_pipeline_snippet(self) -> str:
        """Scaffold a hardened declarative pipeline skeleton."""
        return """\
// Generated by DevAI JenkinsfileAnalyzer — hardened pipeline skeleton
pipeline {
    agent { label 'linux' }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    environment {
        // Load secrets from Jenkins credentials — never hardcode values here
        DEPLOY_KEY = credentials('deploy-ssh-key')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                // Use single quotes in sh to prevent Groovy interpolation injection
                sh 'make build'
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
            return "Jenkins pipelines: none found"
        return (
            f"Jenkins pipelines: {stats.pipelines} file(s), "
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
            kind = "declarative" if info.is_declarative else "scripted"
            lines.append(f"  - {info.path}: {info.stages} stage(s), {kind}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
