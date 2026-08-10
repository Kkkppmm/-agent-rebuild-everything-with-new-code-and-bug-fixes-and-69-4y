"""CircleCIAnalyzer — audit CircleCI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIRCLECI_CONFIG = (".circleci", "config.yml")

UNPINNED_ORB_PATTERN = re.compile(
    r"^\s*[-\w]+:\s*[^\s@]+@(dev|latest|main|master)\b",
    re.IGNORECASE,
)
MUTABLE_ORB_TAG_PATTERN = re.compile(
    r"^\s*[-\w]+:\s*[^\s@]+@v\d+\b(?![.\d])",
    re.IGNORECASE,
)
LATEST_IMAGE_PATTERN = re.compile(r"image:\s*[^\s:]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SSH_STRICT_HOST_PATTERN = re.compile(
    r"add_ssh_keys|strict_host_key_checking:\s*false",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(r"^\s*user:\s*root\b", re.IGNORECASE)
UNPINNED_CHECKOUT_PATTERN = re.compile(
    r"checkout:\s*$|checkout:\s*\{\}",
    re.IGNORECASE,
)
DOCKER_LAYER_CACHING_PATTERN = re.compile(
    r"setup_remote_docker|docker_layer_caching:\s*true",
    re.IGNORECASE,
)
CONTEXT_SECRET_PATTERN = re.compile(
    r"context:\s*\[.*\]",
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
    job: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        job = f" ({self.job})" if self.job else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{job} — {self.message}"


@dataclass
class CircleCIJobInfo:
    """Parsed metadata about a CircleCI job."""

    name: str
    executor: str = ""
    docker_images: list[str] = field(default_factory=list)
    uses_orbs: bool = False


@dataclass
class CircleCIInfo:
    """Parsed metadata about a CircleCI config file."""

    path: str
    version: str = ""
    jobs: list[CircleCIJobInfo] = field(default_factory=list)
    orbs: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CircleCIStats:
    """Aggregate CircleCI analysis statistics."""

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_circleci_config(path: Path) -> bool:
    parts = path.parts
    return len(parts) >= 2 and parts[-2] == ".circleci" and path.name == "config.yml"


class CircleCIAnalyzer:
    """Audit CircleCI configs for security risks and CI best practices.

    Scans for unpinned orbs, mutable Docker images, secrets in environment
    blocks, curl-pipe-to-shell patterns, disabled SSH host verification, and
    jobs running as root.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleCIFinding] | None = None
        self._stats: CircleCIStats | None = None
        self._infos: list[CircleCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return CircleCI config file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_circleci_config(path):
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
        current_job = ""
        in_jobs = False
        in_orbs = False
        in_env = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("version:"):
                info.version = line.split(":", 1)[1].strip().strip("'\"")

            if line == "orbs:":
                in_orbs = True
                in_jobs = False
                in_env = False
                continue

            if line == "jobs:":
                in_jobs = True
                in_orbs = False
                in_env = False
                continue

            if in_orbs and ":" in line and not line.startswith("-"):
                orb_name = line.split(":", 1)[0].strip()
                if orb_name:
                    info.orbs.append(orb_name)
                if UNPINNED_ORB_PATTERN.search(line):
                    findings.append(
                        CircleCIFinding(
                            kind="unpinned_orb",
                            severity="high",
                            message="orb pinned to mutable tag (@dev/@latest) — pin to a release version",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if MUTABLE_ORB_TAG_PATTERN.search(line):
                    findings.append(
                        CircleCIFinding(
                            kind="mutable_orb_tag",
                            severity="medium",
                            message="orb uses floating major tag (@v1) — pin to full version",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if in_jobs and re.match(r"^\S+:\s*$", line) and not line.startswith("-"):
                job_name = line[:-1].strip()
                if job_name not in ("docker", "steps", "environment", "working_directory"):
                    current_job = job_name
                    info.jobs.append(CircleCIJobInfo(name=job_name))

            if line.startswith("docker:"):
                in_env = False

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="latest_image",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if line.startswith("environment:") or line == "environment:":
                in_env = True
                env_indent = len(raw) - len(raw.lstrip())
                continue

            if in_env and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent:
                    findings.append(
                        CircleCIFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in environment — use CircleCI contexts or project variables",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=raw.strip(),
                        )
                    )

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("steps", "run", "checkout", "persist_to_workspace", "attach_workspace"):
                    in_env = False
                elif key not in ("environment",):
                    if key and key[0].isalpha() and key not in info.orbs:
                        pass

            if SSH_STRICT_HOST_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="ssh_host_verification",
                        severity="high",
                        message="SSH host key verification disabled or add_ssh_keys used — verify fingerprints",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="root_user",
                        severity="medium",
                        message="job runs as root user — prefer a non-root executor image",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if line.startswith("run:") or " run:" in line or line.startswith("- run:"):
                if CURL_PIPE_SHELL_PATTERN.search(line):
                    findings.append(
                        CircleCIFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="piping curl/wget to shell in run step is unsafe",
                            path=rel,
                            lineno=lineno,
                            job=current_job,
                            line=raw.strip(),
                        )
                    )

            if DOCKER_LAYER_CACHING_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="docker_layer_caching",
                        severity="low",
                        message="docker layer caching enabled — ensure cache does not leak secrets between builds",
                        path=rel,
                        lineno=lineno,
                        job=current_job,
                        line=raw.strip(),
                    )
                )

            if CONTEXT_SECRET_PATTERN.search(line) and "context:" in line.lower():
                findings.append(
                    CircleCIFinding(
                        kind="context_usage",
                        severity="low",
                        message="workflow uses contexts — verify context access is restricted to required jobs",
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
        self._stats = CircleCIStats(
            configs=len(paths),
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
        """Return parsed CircleCI metadata."""
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
        """Scaffold a hardened CircleCI config template."""
        return """\
# Generated by DevAI CircleCIAnalyzer
version: 2.1

orbs:
  python: circleci/python@2.1.1

jobs:
  test:
    docker:
      - image: cimg/python:3.12.7
        user: circleci
    steps:
      - checkout
      - python/install-packages:
          pkg-manager: pip
          app-dir: .
          args: -e ".[dev]"
      - run:
          name: Run tests
          command: python -m pytest

workflows:
  ci:
    jobs:
      - test
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "CircleCI: none found"
        return (
            f"CircleCI: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "CircleCI config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            jobs = ", ".join(j.name for j in info.jobs[:5]) or "none"
            orbs = ", ".join(info.orbs[:5]) or "none"
            lines.append(
                f"  - {info.path}: version={info.version or 'unknown'}, "
                f"jobs=[{jobs}], orbs=[{orbs}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
