"""JenkinsfileAnalyzer — audit Jenkins pipelines for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

JENKINSFILE_NAMES = ("Jenkinsfile", "jenkinsfile")

SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(r"privileged\s*[=:]\s*true\b", re.IGNORECASE)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"sh\s+['\"].*\$\{?(params|env)\.",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
GROOVY_SHELL_PATTERN = re.compile(r"sh\s+['\"].*\+.*\$\{", re.IGNORECASE)
LATEST_TAG_PATTERN = re.compile(r"image:\s*['\"]?[^\s'\"]+:latest['\"]?", re.IGNORECASE)
CREDENTIALS_INLINE_PATTERN = re.compile(
    r"credentials\s*\(\s*['\"][^'\"]+['\"]\s*\)",
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
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class JenkinsfileInfo:
    """Parsed metadata about a Jenkinsfile."""

    path: str
    stages: list[str] = field(default_factory=list)
    has_docker: bool = False
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
    return path.name in JENKINSFILE_NAMES or path.name.lower().endswith(".jenkinsfile")


class JenkinsfileAnalyzer:
    """Audit Jenkins pipelines for script injection, hardcoded secrets, and privileged Docker."""

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

            if re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line):
                match = re.search(r"stage\s*\(\s*['\"]([^'\"]+)['\"]", line)
                if match:
                    info.stages.append(match.group(1))

            if "docker" in line.lower():
                info.has_docker = True

            if SECRET_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret or credential in Jenkinsfile",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="Docker container runs in privileged mode",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if DOCKER_SOCK_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="docker_sock_mount",
                        severity="high",
                        message="Docker socket mounted in pipeline",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="Remote script downloaded and piped to shell",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) or GROOVY_SHELL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="script_injection",
                        severity="high",
                        message="User-controlled value interpolated into shell command",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if EVAL_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="eval_usage",
                        severity="high",
                        message="eval() in pipeline — arbitrary code execution risk",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="Docker image uses :latest tag",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
                    )
                )

            if CREDENTIALS_INLINE_PATTERN.search(line) and SECRET_PATTERN.search(line):
                findings.append(
                    JenkinsfileFinding(
                        kind="inline_credential",
                        severity="medium",
                        message="Inline credential reference alongside hardcoded value",
                        path=rel,
                        lineno=lineno,
                        line=line[:120],
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

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
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
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
