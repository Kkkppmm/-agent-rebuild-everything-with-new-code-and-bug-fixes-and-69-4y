"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile",)
JENKINSFILE_SUFFIXES = (".jenkinsfile",)

SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
HTTP_DOWNLOAD_PATTERN = re.compile(
    r"(curl|wget)\s+(?:[^\s'\"]+\s+)*http://",
    re.IGNORECASE,
)
UNPINNED_LIBRARY_PATTERN = re.compile(
    r"@Library\s*\(\s*['\"][^'\"]+@(main|master|latest|HEAD)\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"(privileged\s*:\s*true|--privileged)\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{(params|BUILD_USER_INPUT|env\.[A-Z0-9_]+)\.",
    re.IGNORECASE,
)
INLINE_CREDENTIAL_PATTERN = re.compile(
    r"(credentials|password|string|usernamePassword)\s*\(\s*['\"][^'\"]{3,}['\"]",
    re.IGNORECASE,
)
UNRESTRICTED_INPUT_PATTERN = re.compile(r"^\s*input\b", re.IGNORECASE)
SUBMITTER_PATTERN = re.compile(r"submitter\s*:", re.IGNORECASE)
PLAINTEXT_SECRET_ASSIGN_PATTERN = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*['\"][^'\"]{4,}['\"]",
)
DOCKER_LATEST_PATTERN = re.compile(
    r"image\s*[:=]?\s*['\"]?[^\s'\"]+:latest\b",
    re.IGNORECASE,
)
SKIP_CHECKOUT_PATTERN = re.compile(r"skipDefaultCheckout\s*\(\s*true\s*\)", re.IGNORECASE)
DISABLE_CONCURRENT_PATTERN = re.compile(r"disableConcurrentBuilds\s*\(\s*\)", re.IGNORECASE)
TIMEOUT_PATTERN = re.compile(r"timeout\s*\(", re.IGNORECASE)
AGENT_ANY_PATTERN = re.compile(r"agent\s+any\b", re.IGNORECASE)


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
    is_declarative: bool = False
    is_scripted: bool = False
    stages: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
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
    if lower in ("jenkinsfile",):
        return True
    if lower.endswith(".jenkinsfile"):
        return True
    if lower.startswith("jenkinsfile.") and "." in name:
        return True
    if lower == "jenkinsfile.groovy":
        return True
    return False


def _strip_comment(line: str) -> str:
    if "//" in line:
        pos = line.find("//")
        while pos != -1:
            if pos == 0 or line[pos - 1] != ":":
                return line[:pos].strip()
            pos = line.find("//", pos + 2)
    return line.strip()


class JenkinsfileAnalyzer:
    """Audit Jenkinsfiles for security risks and CI best practices.

    Scans for hardcoded secrets, curl-pipe-to-shell patterns, sudo usage,
    unpinned shared libraries, privileged Docker agents, script injection via
    params/env interpolation, and other common Jenkins pipeline misconfigurations.
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
        has_input = False
        has_timeout = False
        has_disable_concurrent = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if re.search(r"\bpipeline\s*\{", line, re.IGNORECASE):
                info.is_declarative = True
            if re.search(r"node\s*\(", line) or re.search(r"node\s*\{", line):
                info.is_scripted = True

            stage_match = re.match(r"^\s*stage\s*\(\s*['\"]([^'\"]+)['\"]", line, re.IGNORECASE)
            if stage_match:
                info.stages.append(stage_match.group(1))

            agent_match = re.search(
                r"agent\s+(any|none|label\s+['\"]([^'\"]+)['\"]|docker\s*\{)",
                line,
                re.IGNORECASE,
            )
            if agent_match:
                agent_val = agent_match.group(1) or agent_match.group(2) or "docker"
                info.agents.append(agent_val.lower())
                if "docker" in line.lower():
                    info.uses_docker = True

            if AGENT_ANY_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="agent_any",
                        severity="medium",
                        message="agent any runs on any executor — restrict with labels for isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="potential secret hardcoded in pipeline — use Jenkins credentials store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAINTEXT_SECRET_ASSIGN_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="plaintext_secret",
                        severity="high",
                        message="plaintext secret assignment — use withCredentials or credentials binding",
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

            if SUDO_PATTERN.search(line) and re.search(r"\bsh\b", line, re.IGNORECASE):
                findings.append(
                    JenkinsfileFinding(
                        kind="sudo_in_shell",
                        severity="high",
                        message="sudo in shell step escalates privileges — avoid in CI pipelines",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HTTP_DOWNLOAD_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="http_download",
                        severity="medium",
                        message="downloading over plain HTTP — use HTTPS to prevent MITM tampering",
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
                        message="shared library pinned to mutable branch — pin to a specific tag or commit",
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
                        message="privileged Docker agent grants host-level access — avoid unless required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_LATEST_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="docker_latest_tag",
                        severity="medium",
                        message="Docker agent uses :latest tag — pin to a specific image digest or version",
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
                        message="inline credential value in binding — reference Jenkins credential IDs only",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNRESTRICTED_INPUT_PATTERN.search(line):
                has_input = True
                if not SUBMITTER_PATTERN.search(line):
                    findings.append(
                        JenkinsfileFinding(
                            kind="unrestricted_input",
                            severity="medium",
                            message="input step without submitter restriction — limit who can approve deployments",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if re.search(r"\bsh\b", line, re.IGNORECASE) and SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="script_injection",
                        severity="high",
                        message=(
                            "params/env interpolated into shell step — "
                            "use withEnv and proper quoting to prevent injection"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_CHECKOUT_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="skip_checkout",
                        severity="low",
                        message="skipDefaultCheckout(true) — verify checkout strategy is intentional",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DISABLE_CONCURRENT_PATTERN.search(line):
                has_disable_concurrent = True

            if TIMEOUT_PATTERN.search(line):
                has_timeout = True

        if info.is_declarative and not has_timeout and info.lines > 10:
            findings.append(
                JenkinsfileFinding(
                    kind="missing_timeout",
                    severity="low",
                    message="no timeout configured — add options { timeout(...) } to prevent hung builds",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.is_declarative and not has_disable_concurrent and len(info.stages) > 2:
            findings.append(
                JenkinsfileFinding(
                    kind="missing_concurrent_guard",
                    severity="low",
                    message="consider disableConcurrentBuilds() to prevent overlapping deployments",
                    path=rel,
                    lineno=1,
                    line="",
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
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
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
