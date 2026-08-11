"""CircleCIAnalyzer — audit CircleCI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIRCLECI_DIRS = (".circleci", "circleci", "ci")
CIRCLECI_NAMES = ("config.yml", "config.yaml")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|docker):\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
SETUP_REMOTE_DOCKER_PATTERN = re.compile(
    r"setup_remote_docker\b",
    re.IGNORECASE,
)
UNPINNED_ORB_PATTERN = re.compile(
    r"(?:^\s*-\s*|[a-z0-9_-]+:\s*)([a-z0-9_-]+/[a-z0-9_-]+)\s*@\s*(?:latest|main|master|develop)\s*$",
    re.IGNORECASE,
)
FLOATING_ORB_PATTERN = re.compile(
    r"^\s*-\s*([a-z0-9_-]+/[a-z0-9_-]+):\s*@\d+\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:run|command):\s*.*\$\{?[A-Z_]+\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"docker\s+run\b[^\n]*--privileged\b",
    re.IGNORECASE,
)
STORE_ARTIFACTS_SENSITIVE_PATTERN = re.compile(
    r"store_artifacts:\s*\n\s*path:\s*\.env",
    re.IGNORECASE,
)
NO_RESOURCE_CLASS_PATTERN = re.compile(
    r"^\s*resource_class:\s*(small|medium)\s*$",
    re.IGNORECASE,
)


@dataclass
class CircleCIFinding:
    """A security or best-practice issue in a CircleCI config."""

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
class CircleCIInfo:
    """Parsed metadata about a CircleCI config file."""

    path: str
    jobs: list[str] = field(default_factory=list)
    orbs: list[str] = field(default_factory=list)
    workflows: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CircleCIStats:
    """Aggregate CircleCI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_circleci_file(path: Path) -> bool:
    lower = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if ".circleci" in parts and lower in CIRCLECI_NAMES:
        return True
    if parts & set(CIRCLECI_DIRS) and lower in CIRCLECI_NAMES:
        return True
    if lower.endswith(".circleci.yml") or lower.endswith(".circleci.yaml"):
        return True
    return False


class CircleCIAnalyzer:
    """Audit CircleCI configs for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.circleci/config.yml` for curl-pipe-to-shell, unpinned orbs, privileged Docker,
    remote Docker usage, and secrets in environment blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleCIFinding] | None = None
        self._stats: CircleCIStats | None = None
        self._infos: list[CircleCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return CircleCI config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_circleci_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CircleCIFinding], CircleCIInfo]:
        findings: list[CircleCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CircleCIInfo(path=rel)

        info = CircleCIInfo(path=rel, lines=len(raw_lines))
        in_jobs = False
        in_workflows = False
        in_orbs = False
        in_run_block = False
        run_indent = 0
        in_security_job = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^jobs\s*:", line, re.IGNORECASE):
                in_jobs = True
                in_workflows = False
                in_orbs = False
                continue
            if re.match(r"^workflows\s*:", line, re.IGNORECASE):
                in_workflows = True
                in_jobs = False
                in_orbs = False
                continue
            if re.match(r"^orbs\s*:", line, re.IGNORECASE):
                in_orbs = True
                in_jobs = False
                in_workflows = False
                continue

            if in_orbs and line.startswith("- "):
                orb_match = re.match(r"-\s*([a-z0-9_-]+/[a-z0-9_-]+)", line, re.IGNORECASE)
                if orb_match:
                    info.orbs.append(orb_match.group(1))

            if UNPINNED_ORB_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="unpinned_orb",
                        severity="medium",
                        message="orb uses floating tag (latest/main) — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if FLOATING_ORB_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="floating_orb_version",
                        severity="low",
                        message="orb uses major-only version — pin to full semver for reproducibility",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_jobs and re.match(r"^\s{2}[a-zA-Z0-9_-]+:\s*$", raw):
                job_name = raw.strip()[:-1]
                if job_name not in ("version", "orbs", "commands", "executors"):
                    info.jobs.append(job_name)
                    in_security_job = any(
                        token in job_name.lower()
                        for token in ("security", "audit", "scan", "sast", "dast")
                    )

            if in_workflows and re.match(r"^\s{2}[a-zA-Z0-9_-]+:\s*$", raw):
                wf_name = raw.strip()[:-1]
                if wf_name not in ("version",):
                    info.workflows.append(wf_name)

            if re.match(r"^\s*run\s*:", line, re.IGNORECASE):
                in_run_block = True
                run_indent = len(raw) - len(raw.lstrip())
            elif in_run_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= run_indent and not line.startswith("-"):
                    in_run_block = False

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use CircleCI contexts or project environment variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and use checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="docker run --privileged grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SETUP_REMOTE_DOCKER_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="setup_remote_docker",
                        severity="medium",
                        message="setup_remote_docker enables Docker-in-Docker — restrict to trusted jobs only",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and "$" in line:
                findings.append(
                    CircleCIFinding(
                        kind="script_injection",
                        severity="high",
                        message="unquoted environment variable in run step — validate untrusted input",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if STORE_ARTIFACTS_SENSITIVE_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="sensitive_artifact",
                        severity="high",
                        message="storing .env as artifact may leak secrets — exclude sensitive files",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line) and "http://" in line.lower():
                findings.append(
                    CircleCIFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in config — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_job and re.search(r"^\s*when:\s*on_fail", line, re.IGNORECASE):
                findings.append(
                    CircleCIFinding(
                        kind="security_on_fail",
                        severity="medium",
                        message="security job configured with when: on_fail — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[CircleCIFinding]:
        """Scan CircleCI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CircleCIFinding] = []
        infos: list[CircleCIInfo] = []
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
        self._stats = CircleCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CircleCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CircleCIInfo]:
        """Return parsed pipeline metadata."""
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
        """Scaffold a hardened CircleCI config template."""
        return """\
# Generated by DevAI CircleCIAnalyzer
version: 2.1

orbs:
  python: circleci/python@2.1.0

jobs:
  test:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - python/install-packages:
          pkg-manager: pip
          app-dir: .
      - run:
          name: Run tests
          command: python -m pytest

  security_scan:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run:
          name: Security scan
          command: |
            pip install devai
            devai security-scan .

workflows:
  ci:
    jobs:
      - test
      - security_scan:
          requires:
            - test
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "CircleCI: none found"
        return (
            f"CircleCI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "CircleCI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            jobs = ", ".join(info.jobs[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.jobs)} job(s), jobs=[{jobs}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
