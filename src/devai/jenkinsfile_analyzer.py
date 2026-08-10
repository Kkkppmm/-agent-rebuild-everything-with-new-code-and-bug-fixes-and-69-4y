"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINS_FILENAMES = ("Jenkinsfile", "jenkinsfile")
JENKINS_SUFFIXES = (".jenkins", ".jenkinsfile")

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"privileged\s*[:=]?\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(
    r"(runAsUser\s*[:=]\s*['\"]?0['\"]?|args\s+['\"]-u\s+root['\"]|user\s+['\"]root['\"])",
    re.IGNORECASE,
)
UNPINNED_DOCKER_IMAGE_PATTERN = re.compile(
    r"image\s+['\"](?!.*:)[a-z0-9][a-z0-9._/-]*['\"]",
    re.IGNORECASE,
)
MUTABLE_DOCKER_TAG_PATTERN = re.compile(
    r"image\s+['\"][^'\"]+:(latest|stable|nightly|dev|main|master)['\"]",
    re.IGNORECASE,
)
DISABLE_SANDBOX_PATTERN = re.compile(
    r"(disableSandbox\s*\(\s*\)|permissiveScriptSecurity\s*\(\s*\))",
    re.IGNORECASE,
)
HARDCODED_CREDENTIAL_PATTERN = re.compile(
    r"(password|usernamePassword|string)\s*\(\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(sh|bat)\s+['\"].*\$\{(params|env)\.",
    re.IGNORECASE,
)
AGENT_ANY_PATTERN = re.compile(r"agent\s+any\b", re.IGNORECASE)
MASTER_BRANCH_PATTERN = re.compile(
    r"branch\s*[:=]\s*['\"]master['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)


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
    pipeline_type: str = ""
    stages: list[str] = field(default_factory=list)
    uses_docker: bool = False
    agent_label: str = ""
    lines: int = 0


@dataclass
class JenkinsfileStats:
    """Aggregate Jenkinsfile analysis statistics."""

    pipelines: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_jenkins_file(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    if lower in JENKINS_FILENAMES:
        return True
    return any(lower.endswith(suffix) for suffix in JENKINS_SUFFIXES)


class JenkinsfileAnalyzer:
    """Audit Jenkins pipeline files for security risks and CI best practices.

    Scans Jenkinsfiles for hardcoded secrets, curl-pipe-to-shell scripts,
    unpinned Docker images, privileged containers, sandbox bypasses,
    and script injection via parameter interpolation.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[JenkinsfileFinding] | None = None
        self._stats: JenkinsfileStats | None = None
        self._infos: list[JenkinsfileInfo] | None = None

    def pipelines(self) -> list[Path]:
        """Return Jenkins pipeline file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_jenkins_file(path):
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
        in_environment = False
        env_indent = 0
        in_stages = False
        current_stage: str | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue

            if line.startswith("pipeline") or line == "pipeline {":
                info.pipeline_type = "declarative"
            elif line.startswith("node(") or line.startswith("node "):
                info.pipeline_type = "scripted"

            if re.search(r"\bdocker\b", line, re.IGNORECASE):
                info.uses_docker = True

            if line.startswith("agent"):
                label_match = re.search(r"label\s+['\"]([^'\"]+)['\"]", line)
                if label_match:
                    info.agent_label = label_match.group(1)
                elif AGENT_ANY_PATTERN.search(line):
                    findings.append(
                        JenkinsfileFinding(
                            kind="agent_any",
                            severity="low",
                            message="agent any runs on any executor — prefer labeled agents for isolation",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if line.startswith("stages") or line == "stages {":
                in_stages = True

            if in_stages and re.match(r"stage\s*\(\s*['\"]", line):
                stage_match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line)
                if stage_match:
                    current_stage = stage_match.group(1)
                    info.stages.append(current_stage)

            if line.startswith("environment") or line == "environment {":
                in_environment = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_environment and line == "}" and len(raw) - len(raw.lstrip()) <= env_indent:
                in_environment = False

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged Docker agent grants full host access to the build",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="run_as_root",
                        severity="medium",
                        message="container runs as root — use a non-root user in Docker agents",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_DOCKER_IMAGE_PATTERN.search(line) or MUTABLE_DOCKER_TAG_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="unpinned_docker_image",
                        severity="medium",
                        message="Docker image unpinned or uses mutable tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_environment and SECRET_ENV_PATTERN.search(line):
                if "credentials(" not in line.lower():
                    findings.append(
                        JenkinsfileFinding(
                            kind="secret_in_environment",
                            severity="high",
                            message="potential secret hardcoded in environment — use Jenkins credentials store",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if HARDCODED_CREDENTIAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="hardcoded_credential",
                        severity="high",
                        message="hardcoded credential value — use Jenkins credentials() binding",
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
                        message="Groovy sandbox disabled — allows arbitrary code execution in pipelines",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="script_injection",
                        severity="high",
                        message="shell step interpolates params/env — risk of script injection",
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
                        message="eval() in pipeline enables arbitrary code execution",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MASTER_BRANCH_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="master_branch",
                        severity="low",
                        message="branch filter references master — consider using main",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
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
        disableConcurrentBuilds()
    }
    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Test') {
            steps {
                sh 'pip install -e ".[dev]" && python -m pytest'
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
            ptype = info.pipeline_type or "unknown"
            lines.append(
                f"  - {info.path}: type={ptype}, docker={info.uses_docker}, "
                f"stages={len(info.stages)}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
