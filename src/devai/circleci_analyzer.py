"""CircleCIAnalyzer — audit CircleCI config for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIRCLECI_CONFIG = (".circleci", "config.yml")

UNPINNED_ORB_PATTERN = re.compile(
    r"(orb:\s*[^\s@]+|:\s*[^\s@]+)@(main|master|dev|latest)\b",
    re.IGNORECASE,
)
MUTABLE_ORB_TAG_PATTERN = re.compile(
    r"orb:\s*[^\s@]+@v\d+\b(?![.\d])",
    re.IGNORECASE,
)
LATEST_IMAGE_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
DOCKER_LATEST_PATTERN = re.compile(r"docker:\s*[^\n]*:latest\b", re.IGNORECASE)


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

    configs: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_circleci_config(path: Path) -> bool:
    parts = path.parts
    return len(parts) >= 2 and parts[-2] == ".circleci" and path.name == "config.yml"


class CircleCIAnalyzer:
    """Audit CircleCI configs for unpinned orbs, secrets in env, and unsafe docker settings."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleCIFinding] | None = None
        self._stats: CircleCIStats | None = None
        self._infos: list[CircleCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return CircleCI config paths found in the project."""
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
        in_env_block = False
        env_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("jobs:"):
                in_env_block = False
            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key in ("env", "environment"):
                    in_env_block = True
                    env_indent = len(raw) - len(raw.lstrip())
                elif key not in ("docker", "steps"):
                    in_env_block = False
                if key and key[0].isalpha() and key not in (
                    "version", "orbs", "jobs", "workflows", "executors", "commands",
                ):
                    if key not in info.jobs:
                        info.jobs.append(key)

            if UNPINNED_ORB_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="unpinned_orb",
                        severity="high",
                        message="orb pinned to mutable branch — pin to a specific version",
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
                        message="orb uses floating major tag — pin to full version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            orb_match = re.search(r"(\S+@\S+)", line)
            if "orb:" in line.lower() and orb_match:
                info.orbs.append(orb_match.group(1))

            if DOCKER_LATEST_PATTERN.search(line) or (
                "image:" in line.lower() and LATEST_IMAGE_PATTERN.search(line)
            ):
                findings.append(
                    CircleCIFinding(
                        kind="latest_image",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="privileged: true grants full host access to the container",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_env_block and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent:
                    findings.append(
                        CircleCIFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in env — use CircleCI contexts",
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
                        message="piping curl/wget to shell in run step is unsafe",
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
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0 or stats.findings == 0:
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
  python: circleci/python@2.2.0

jobs:
  test:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run: pip install -e ".[dev]"
      - run: python -m pytest

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
            lines.append(f"  - {info.path}: {len(info.jobs)} job(s)")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
