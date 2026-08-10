"""JenkinsAnalyzer — audit Jenkinsfiles for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINS_FILE_NAMES = ("Jenkinsfile", "Jenkinsfile.groovy")
JENKINS_SUFFIX = ".jenkinsfile"

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[=:]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
MASTER_NODE_PATTERN = re.compile(
    r"node\s*\(\s*['\"]master['\"]\s*\)|label\s+['\"]master['\"]",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"privileged\s*:\s*true|--privileged\b",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"runAsUser\s*:\s*0\b|user\s*:\s*['\"]?root['\"]?|--user\s+root\b",
    re.IGNORECASE,
)
PLAINTEXT_CREDENTIAL_PATTERN = re.compile(
    r"(usernamePassword|string)\s*\(\s*credentialsId\s*:\s*['\"][^'\"]+['\"]\s*,\s*password\s*:\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\bevaluate\s*\(|\$\{.*\}\s*\.execute\s*\(", re.IGNORECASE)
DISABLE_SECURITY_PATTERN = re.compile(
    r"disableScriptSecurity|sandbox\s*:\s*false|skipDefaultCheckout\s*:\s*true",
    re.IGNORECASE,
)
UNPINNED_AGENT_PATTERN = re.compile(
    r"image\s*:\s*['\"]?(python|node|golang|openjdk|maven|gradle)['\"]?\s*$",
    re.IGNORECASE,
)
MISSING_DISCARDER_PATTERN = re.compile(r"buildDiscarder|logRotator", re.IGNORECASE)
TIMESTAMPS_DISABLED_PATTERN = re.compile(r"timestamps\s*\(\s*\)\s*\{\s*skip\s*:\s*true", re.IGNORECASE)


@dataclass
class JenkinsFinding:
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
class JenkinsStageInfo:
    """Metadata about a pipeline stage."""

    name: str
    lineno: int


@dataclass
class JenkinsInfo:
    """Parsed metadata about a Jenkinsfile."""

    path: str
    agent: str = ""
    stages: list[JenkinsStageInfo] = field(default_factory=list)
    uses_docker: bool = False
    uses_credentials: bool = False
    lines: int = 0


@dataclass
class JenkinsStats:
    """Aggregate Jenkins analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkins_file(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    return name in JENKINS_FILE_NAMES or lower.endswith(JENKINS_SUFFIX)


class JenkinsAnalyzer:
    """Audit Jenkinsfiles for security risks and CI best practices.

    Scans for hardcoded secrets, curl-pipe-to-shell patterns, master node usage,
    privileged Docker agents, plaintext credentials, and unsafe Groovy patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JenkinsFinding] | None = None
        self._stats: JenkinsStats | None = None
        self._infos: list[JenkinsInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Jenkinsfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_jenkins_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[JenkinsFinding], JenkinsInfo]:
        findings: list[JenkinsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, JenkinsInfo(path=rel)

        info = JenkinsInfo(path=rel, lines=len(raw_lines))
        in_env = False
        in_sh = False
        has_discarder = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//"):
                continue

            if line.startswith("agent") or line.startswith("agent {"):
                agent_value = line.split("{", 1)[0].replace("agent", "").strip()
                if agent_value:
                    info.agent = agent_value.strip("'\"")

            if "docker" in line.lower():
                info.uses_docker = True

            if "withCredentials" in line or "credentials(" in line:
                info.uses_credentials = True

            if line.startswith("environment") or line.startswith("environment {"):
                in_env = True
                continue

            if in_env and line == "}":
                in_env = False

            if line.startswith("sh ") or line.startswith("sh('") or line.startswith('sh("'):
                in_sh = True
            elif in_sh and line == "}":
                in_sh = False

            stage_match = re.match(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", line)
            if stage_match:
                info.stages.append(JenkinsStageInfo(name=stage_match.group(1), lineno=lineno))

            if MISSING_DISCARDER_PATTERN.search(line):
                has_discarder = True

            if in_env and SECRET_ENV_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="potential secret hardcoded in environment — use Jenkins credentials store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAINTEXT_CREDENTIAL_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="plaintext_credential",
                        severity="high",
                        message="plaintext password in withCredentials — use credentialsId binding only",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            script_text = line
            if CURL_PIPE_SHELL_PATTERN.search(script_text):
                findings.append(
                    JenkinsFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in pipeline is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(script_text):
                findings.append(
                    JenkinsFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in pipeline script — prefer container agents without elevated privileges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MASTER_NODE_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="master_node",
                        severity="high",
                        message="running on master node — use ephemeral agents to isolate builds",
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
                        message="privileged Docker agent — avoid host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="root_user",
                        severity="medium",
                        message="container runs as root — use a non-root user in the agent image",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EVAL_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="unsafe_eval",
                        severity="high",
                        message="dynamic Groovy evaluation — risk of script injection",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DISABLE_SECURITY_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="security_disabled",
                        severity="high",
                        message="script security or checkout safeguards disabled",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_AGENT_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="unpinned_agent_image",
                        severity="low",
                        message="unpinned agent image tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if TIMESTAMPS_DISABLED_PATTERN.search(line):
                findings.append(
                    JenkinsFinding(
                        kind="timestamps_disabled",
                        severity="low",
                        message="timestamps disabled — enable for auditability",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if not has_discarder and len(raw_lines) > 5:
            findings.append(
                JenkinsFinding(
                    kind="missing_build_discarder",
                    severity="low",
                    message="no buildDiscarder/logRotator — unbounded build history may expose secrets in logs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[JenkinsFinding]:
        """Scan Jenkinsfiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[JenkinsFinding] = []
        infos: list[JenkinsInfo] = []
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
        self._stats = JenkinsStats(
            configs=len(paths),
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
    def infos(self) -> list[JenkinsInfo]:
        """Return parsed Jenkins metadata."""
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
        """Scaffold a hardened Jenkinsfile template."""
        return """\
// Generated by DevAI JenkinsAnalyzer
pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
            args '-u 1000:1000'
        }
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        // Use Jenkins credentials — never commit plaintext secrets
        // API_TOKEN = credentials('api-token')
    }

    stages {
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
        if stats.configs == 0:
            return "Jenkins: none found"
        return (
            f"Jenkins: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Jenkins pipeline analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(s.name for s in info.stages[:5]) or "none"
            lines.append(
                f"  - {info.path}: agent={info.agent or 'unknown'}, "
                f"docker={info.uses_docker}, stages=[{stages}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
