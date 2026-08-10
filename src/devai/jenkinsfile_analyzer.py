"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile",)

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"image\s*[:=]?\s*['\"]?[^\s'\"]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\b(eval|execute)\s*\(", re.IGNORECASE)
PARAMS_IN_SH_PATTERN = re.compile(
    r"sh\s+['\"].*\$\{?\s*params\.",
    re.IGNORECASE,
)
INLINE_CREDENTIAL_PATTERN = re.compile(
    r"(usernamePassword|sshUserPrivateKey|string)\s*\([^)]*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"^\s*id:\s*['\"][^'\"]+['\"]\s*$",
    re.IGNORECASE,
)
PLUGIN_VERSION_PATTERN = re.compile(r"^\s*version:\s*['\"][^'\"]+['\"]", re.IGNORECASE)
MASTER_AGENT_PATTERN = re.compile(
    r"agent\s*\{[^}]*label\s*['\"]master['\"]",
    re.IGNORECASE | re.DOTALL,
)
ROOT_USER_PATTERN = re.compile(r"runAsUser:\s*0\b|user:\s*root\b", re.IGNORECASE)
ECHO_CREDENTIAL_PATTERN = re.compile(
    r"(echo|println|print)\s+.*\$\{?\s*(credentialsId|PASSWORD|SECRET|TOKEN)",
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
    agent_type: str = ""
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
    return path.name in JENKINSFILE_NAMES


class JenkinsfileAnalyzer:
    """Audit Jenkinsfiles for security risks and CI best practices.

    Scans for hardcoded secrets, curl-pipe-to-shell patterns, unpinned plugins,
    privileged Docker agents, Groovy script injection via params, and other
    common Jenkins pipeline misconfigurations.
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
        content = "\n".join(raw_lines)
        in_environment = False
        env_indent = 0
        in_plugins = False
        plugin_block_has_version = False
        plugin_id_line = 0

        if MASTER_AGENT_PATTERN.search(content):
            findings.append(
                JenkinsfileFinding(
                    kind="master_agent",
                    severity="medium",
                    message="pipeline runs on Jenkins master — use dedicated agents for isolation",
                    path=rel,
                    lineno=1,
                    line="agent { label 'master' }",
                )
            )

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//"):
                continue

            if line.startswith("agent "):
                info.agent_type = line
            if line.startswith("agent {") or "docker {" in line:
                info.uses_docker = True
            if line.startswith("stage("):
                stage_match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line)
                if stage_match:
                    info.stages.append(stage_match.group(1))

            if line == "environment {" or line.startswith("environment {"):
                in_environment = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if line == "plugins {" or line.startswith("plugins {"):
                in_plugins = True
                plugin_block_has_version = False
                continue

            if in_plugins:
                if PLUGIN_VERSION_PATTERN.match(line):
                    plugin_block_has_version = True
                if UNPINNED_PLUGIN_PATTERN.match(line):
                    plugin_id_line = lineno
                if line == "}" and not line.startswith("}"):
                    if plugin_id_line and not plugin_block_has_version:
                        findings.append(
                            JenkinsfileFinding(
                                kind="unpinned_plugin",
                                severity="medium",
                                message="plugin declared without pinned version — pin plugin versions",
                                path=rel,
                                lineno=plugin_id_line,
                                line=raw_lines[plugin_id_line - 1].strip(),
                            )
                        )
                    in_plugins = False
                    plugin_id_line = 0
                    plugin_block_has_version = False

            if in_environment and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent:
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

            if line == "}" and in_environment:
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

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="mounting /var/run/docker.sock grants host-level access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged Docker agent can escape container isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="root_user",
                        severity="medium",
                        message="container runs as root — use a non-root user",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EVAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="eval_usage",
                        severity="high",
                        message="eval/execute in pipeline can run arbitrary code",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PARAMS_IN_SH_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="params_in_shell",
                        severity="high",
                        message="params interpolated into shell step — risk of Groovy/shell injection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INLINE_CREDENTIAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="inline_credential",
                        severity="high",
                        message="inline credential value in pipeline — use Jenkins credential store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ECHO_CREDENTIAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="credential_echo",
                        severity="high",
                        message="credential or secret echoed to console — may leak in build logs",
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
pipeline {
    agent {
        label 'linux'
    }

    options {
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
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
            "Jenkins pipeline analysis:",
            f"  jenkinsfiles: {stats.jenkinsfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.stages)} stage(s), stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
