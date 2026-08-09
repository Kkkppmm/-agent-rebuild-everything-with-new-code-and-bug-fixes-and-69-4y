"""CircleCIAnalyzer — audit CircleCI configs for security risks and best practices."""

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
UNPINNED_ORB_PATTERN = re.compile(
    r"^\s*-\s*([a-z0-9_-]+/[a-z0-9_-]+)(?:@([^\s#]+))?\s*$",
    re.IGNORECASE,
)
ORB_MAP_PATTERN = re.compile(
    r"^\s*([a-z0-9_-]+):\s*([a-z0-9_-]+/[a-z0-9_-]+)(?:@([^\s#]+))?\s*$",
    re.IGNORECASE,
)
FLOATING_ORB_TAG_PATTERN = re.compile(
    r"@(volatile|dev|latest|main|master)\b",
    re.IGNORECASE,
)
SETUP_REMOTE_DOCKER_PATTERN = re.compile(
    r"setup_remote_docker\s*:\s*true\b",
    re.IGNORECASE,
)
SSH_FINGERPRINT_PATTERN = re.compile(
    r"add_ssh_keys|fingerprint",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
UNQUOTED_ENV_VAR_PATTERN = re.compile(
    r"(?:run|command):\s*.*\$\{?[A-Z_][A-Z0-9_]*\}?",
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
    if lower in CIRCLECI_NAMES and ".circleci" in {p.lower() for p in path.parts}:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(CIRCLECI_DIRS) and lower in CIRCLECI_NAMES:
        return True
    if lower.endswith((".circleci.yml", ".circleci.yaml")):
        return True
    return False


class CircleCIAnalyzer:
    """Audit CircleCI configs for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans ``.circleci/config.yml`` for curl-pipe-to-shell, unpinned orbs, remote Docker
  setup without version pinning, hardcoded credentials, and unquoted environment variables.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleCIFinding] | None = None
        self._stats: CircleCIStats | None = None
        self._infos: list[CircleCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return CircleCI config paths found in the project."""
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
        has_ssh_keys = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("orbs:"):
                in_orbs = True
                in_jobs = False
                in_workflows = False
                continue
            if line.startswith("jobs:"):
                in_jobs = True
                in_orbs = False
                in_workflows = False
                continue
            if line.startswith("workflows:"):
                in_workflows = True
                in_jobs = False
                in_orbs = False
                continue

            if in_orbs and UNPINNED_ORB_PATTERN.match(line):
                match = UNPINNED_ORB_PATTERN.match(line)
                if match:
                    orb_name = match.group(1)
                    version = match.group(2)
                    info.orbs.append(orb_name)
                    if not version:
                        findings.append(
                            CircleCIFinding(
                                kind="unpinned_orb",
                                severity="medium",
                                message=f"orb '{orb_name}' has no version pin — pin to a semver tag",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    elif FLOATING_ORB_TAG_PATTERN.search(f"@{version}"):
                        findings.append(
                            CircleCIFinding(
                                kind="floating_orb",
                                severity="medium",
                                message=f"orb '{orb_name}@{version}' uses mutable tag — pin semver",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if in_orbs:
                map_match = ORB_MAP_PATTERN.match(line)
                if map_match:
                    orb_ref = map_match.group(2)
                    version = map_match.group(3)
                    info.orbs.append(orb_ref)
                    if not version:
                        findings.append(
                            CircleCIFinding(
                                kind="unpinned_orb",
                                severity="medium",
                                message=f"orb '{orb_ref}' has no version pin — pin to a semver tag",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    elif FLOATING_ORB_TAG_PATTERN.search(f"@{version}"):
                        findings.append(
                            CircleCIFinding(
                                kind="floating_orb",
                                severity="medium",
                                message=f"orb '{orb_ref}@{version}' uses mutable tag — pin semver",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if in_jobs and key not in (
                    "docker",
                    "machine",
                    "macos",
                    "resource_class",
                    "steps",
                    "environment",
                    "working_directory",
                    "shell",
                    "parallelism",
                ):
                    if key and key[0].isalpha():
                        info.jobs.append(key)
                if in_workflows and key not in ("jobs", "requires", "filters", "matrix"):
                    if key and key[0].isalpha():
                        info.workflows.append(key)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="potential secret hardcoded in config — use CircleCI contexts or project env vars",
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

            if SETUP_REMOTE_DOCKER_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="remote_docker",
                        severity="low",
                        message="setup_remote_docker enabled — review image pinning and layer caching exposure",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SSH_FINGERPRINT_PATTERN.search(line):
                has_ssh_keys = True

            if line.startswith("- run:") or line == "- run:":
                in_run_block = True
                run_indent = len(raw) - len(raw.lstrip())
                continue

            if in_run_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= run_indent and not line.startswith("-"):
                    in_run_block = False
                else:
                    if CURL_PIPE_SHELL_PATTERN.search(line):
                        findings.append(
                            CircleCIFinding(
                                kind="curl_pipe_shell",
                                severity="high",
                                message="piping curl/wget to shell in CI step is unsafe",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    if UNQUOTED_ENV_VAR_PATTERN.search(line):
                        findings.append(
                            CircleCIFinding(
                                kind="unquoted_env_var",
                                severity="medium",
                                message="unquoted environment variable in run step — quote and validate input",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if line.startswith("- ") and CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in CI step is unsafe",
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
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if has_ssh_keys and not any(f.kind == "ssh_fingerprint" for f in findings):
            findings.append(
                CircleCIFinding(
                    kind="ssh_keys",
                    severity="medium",
                    message="SSH keys referenced — verify fingerprints and restrict deploy keys",
                    path=rel,
                    lineno=1,
                    line="add_ssh_keys",
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
  python: circleci/python@2.1.1

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
