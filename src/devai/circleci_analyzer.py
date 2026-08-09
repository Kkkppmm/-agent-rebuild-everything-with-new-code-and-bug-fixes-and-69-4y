"""CircleCIAnalyzer — audit CircleCI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PATH = (".circleci", "config.yml")

LATEST_IMAGE_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
UNPINNED_ORB_PATTERN = re.compile(
    r"^\s*(?:-\s*)?[a-z0-9-]+:\s*[^\s]+@(main|master|dev|latest)\b",
    re.IGNORECASE,
)
MUTABLE_ORB_TAG_PATTERN = re.compile(r"^\s*-\s*[a-z0-9-]+:\s*v\d+\s*$", re.IGNORECASE)
DOCKER_PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)


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
    """Parsed metadata about a CircleCI config."""

    path: str
    jobs: list[str] = field(default_factory=list)
    orbs: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CircleCIStats:
    """Aggregate CircleCI analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_circleci_config(path: Path) -> bool:
    parts = path.parts
    if len(parts) < 2:
        return False
    return parts[-2] == ".circleci" and path.name.lower() in ("config.yml", "config.yaml")


class CircleCIAnalyzer:
    """Audit CircleCI configuration for security risks and CI best practices.

    Scans for unpinned orbs, :latest images, secrets in environment blocks,
    privileged Docker settings, and curl-pipe-to-shell in run steps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleCIFinding] | None = None
        self._stats: CircleCIStats | None = None
        self._infos: list[CircleCIInfo] | None = None

    def config_files(self) -> list[Path]:
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
        in_jobs = False
        in_orbs = False
        jobs_indent = 0
        orbs_indent = 0
        in_environment = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if line == "jobs:" or line.startswith("jobs:"):
                in_jobs = True
                in_orbs = False
                jobs_indent = indent
                continue

            if line == "orbs:" or line.startswith("orbs:"):
                in_orbs = True
                in_jobs = False
                orbs_indent = indent
                continue

            if in_jobs and indent <= jobs_indent and line.endswith(":") and not line.startswith("-"):
                job_name = line[:-1].strip()
                if job_name and job_name[0].isalpha():
                    info.jobs.append(job_name)

            if in_orbs and indent > orbs_indent and line.endswith(":"):
                orb_name = line[:-1].strip()
                if orb_name:
                    info.orbs.append(orb_name)

            if line == "environment:" or line.startswith("environment:"):
                in_environment = True
                env_indent = indent
                continue

            if in_environment and indent <= env_indent and not line.startswith("-"):
                in_environment = False

            if LATEST_IMAGE_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="latest_image",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_ORB_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="unpinned_orb",
                        severity="high",
                        message="orb pinned to mutable branch — pin to a release version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MUTABLE_ORB_TAG_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="mutable_orb_tag",
                        severity="medium",
                        message="orb uses floating major tag — pin to full version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_PRIVILEGED_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="docker_privileged",
                        severity="high",
                        message="docker privileged: true grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_environment and SECRET_ENV_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="secret_in_environment",
                        severity="high",
                        message="potential secret in environment — use CircleCI contexts or project variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            check_line = line.lstrip("- ").strip()
            if CURL_PIPE_SHELL_PATTERN.search(check_line):
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

        return findings, info

    def analyze(self) -> list[CircleCIFinding]:
        """Scan CircleCI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CircleCIFinding] = []
        infos: list[CircleCIInfo] = []
        paths = self.config_files()

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
            config_files=len(paths),
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
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
          pip-dependency-file: pyproject.toml
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
        if stats.config_files == 0:
            return "CircleCI: no config found"
        return (
            f"CircleCI: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "CircleCI configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.jobs)} job(s), {len(info.orbs)} orb(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
