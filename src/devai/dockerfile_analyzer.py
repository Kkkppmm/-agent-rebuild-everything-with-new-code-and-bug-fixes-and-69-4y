"""DockerfileAnalyzer — audit Dockerfiles for security and best-practice issues."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DOCKERFILE_NAMES = ("Dockerfile", "Containerfile")
DOCKERFILE_SUFFIXES = (".dockerfile",)

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r"FROM\s+[^\s]+:latest\b", re.IGNORECASE)
ADD_LOCAL_PATTERN = re.compile(r"^\s*ADD\s+(?!https?://|git@|ssh://)", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"--privileged\b", re.IGNORECASE)
APT_NO_CLEANUP_PATTERN = re.compile(
    r"apt-get\s+install(?!.*rm\s+-rf\s+/var/lib/apt/lists)",
    re.IGNORECASE,
)


@dataclass
class DockerfileFinding:
    """A security or best-practice issue in a Dockerfile."""

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
class DockerfileInfo:
    """Parsed metadata about a Dockerfile."""

    path: str
    base_images: list[str] = field(default_factory=list)
    has_user: bool = False
    has_healthcheck: bool = False
    exposed_ports: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class DockerfileStats:
    """Aggregate Dockerfile analysis statistics."""

    dockerfiles: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    if lower in ("dockerfile", "containerfile"):
        return True
    if lower.endswith(".dockerfile"):
        return True
    if lower.endswith("dockerfile") and "." in name:
        return True
    return False


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class DockerfileAnalyzer:
    """Audit Dockerfiles for security risks and container best practices.

    Scans for root execution, :latest tags, secrets in ENV/ARG, unsafe
    ADD usage, curl-pipe-to-shell patterns, and other common misconfigurations.
  """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DockerfileFinding] | None = None
        self._stats: DockerfileStats | None = None
        self._infos: list[DockerfileInfo] | None = None

    def dockerfiles(self) -> list[Path]:
        """Return Dockerfile paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_dockerfile(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[DockerfileFinding], DockerfileInfo]:
        findings: list[DockerfileFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DockerfileInfo(path=rel)

        info = DockerfileInfo(path=rel, lines=len(raw_lines))
        continuation = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            if line.endswith("\\"):
                continuation = (continuation + " " + line[:-1]).strip()
                continue

            if continuation:
                line = (continuation + " " + line).strip()
                continuation = ""

            upper = line.upper()

            if upper.startswith("FROM "):
                image = line[5:].strip().split(" ", 1)[0]
                info.base_images.append(image)
                if LATEST_TAG_PATTERN.search(line):
                    findings.append(
                        DockerfileFinding(
                            kind="latest_tag",
                            severity="medium",
                            message="base image uses :latest tag — pin a specific version",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if upper.startswith("USER "):
                user = line[5:].strip().lower()
                if user and user not in ("root", "0"):
                    info.has_user = True

            if upper.startswith("HEALTHCHECK "):
                info.has_healthcheck = True

            if upper.startswith("EXPOSE "):
                for port in line[7:].split():
                    info.exposed_ports.append(port)

            if ADD_LOCAL_PATTERN.match(line):
                findings.append(
                    DockerfileFinding(
                        kind="add_instead_of_copy",
                        severity="medium",
                        message="prefer COPY over ADD for local files",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if upper.startswith("ENV ") or upper.startswith("ARG "):
                if SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        DockerfileFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret in ENV/ARG — use runtime secrets instead",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    DockerfileFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    DockerfileFinding(
                        kind="privileged",
                        severity="high",
                        message="--privileged grants excessive container permissions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            lower = line.lower()
            if "apt-get install" in lower:
                if APT_NO_CLEANUP_PATTERN.search(line) and "rm -rf /var/lib/apt/lists" not in lower:
                    findings.append(
                        DockerfileFinding(
                            kind="apt_no_cleanup",
                            severity="low",
                            message="apt-get install without cleaning /var/lib/apt/lists increases image size",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

        if not info.has_user:
            findings.append(
                DockerfileFinding(
                    kind="runs_as_root",
                    severity="high",
                    message="no non-root USER directive — container runs as root by default",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.exposed_ports and any(p.startswith("22") for p in info.exposed_ports):
            findings.append(
                DockerfileFinding(
                    kind="ssh_exposed",
                    severity="medium",
                    message="EXPOSE 22 — avoid running SSH inside containers",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[DockerfileFinding]:
        """Scan Dockerfiles and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DockerfileFinding] = []
        infos: list[DockerfileInfo] = []
        paths = self.dockerfiles()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = DockerfileStats(
            dockerfiles=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DockerfileStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DockerfileInfo]:
        """Return parsed Dockerfile metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no Dockerfiles)."""
        self.analyze()
        stats = self.stats
        if stats.dockerfiles == 0:
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
        """Scaffold a hardened multi-stage Dockerfile template."""
        return """\
# Generated by DevAI DockerfileAnalyzer
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["python", "-m", "app"]
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.dockerfiles == 0:
            return "Dockerfiles: none found"
        lines = [
            (
                f"Dockerfiles: {stats.dockerfiles} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
            ),
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Dockerfile analysis:",
            f"  dockerfiles: {stats.dockerfiles}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.base_images)} base image(s), "
                f"user={'set' if info.has_user else 'root'}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
