"""CircleCIAnalyzer — audit CircleCI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PATHS = (
    ".circleci/config.yml",
    ".circleci/config.yaml",
)

CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"\b(eval|exec)\b",
    re.IGNORECASE,
)
UNPINNED_ORB_PATTERN = re.compile(
    r"^\s*-\s*([a-z0-9_-]+/[a-z0-9_-]+)@(?![\d])",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"^\s*(?:docker|image)\s*:\s*[-\s]*['\"]?(?!.*:)[a-z0-9._/-]+['\"]?\s*$",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"['\"]?[a-z0-9._/-]+:latest['\"]?",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"privileged\s*:\s*true\b",
    re.IGNORECASE,
)
SETUP_REMOTE_DOCKER_PATTERN = re.compile(
    r"setup_remote_docker\b",
    re.IGNORECASE,
)
SSH_FINGERPRINT_PATTERN = re.compile(
    r"fingerprint:\s*['\"][0-9a-f:]+['\"]",
    re.IGNORECASE,
)
UNPINNED_EXECUTOR_PATTERN = re.compile(
    r"^\s*-\s*(image|python|node|ruby|go)\s*$",
    re.IGNORECASE,
)


@dataclass
class CircleFinding:
    """A security or best-practice issue in a CircleCI config file."""

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
class CircleInfo:
    """Parsed metadata about a CircleCI config file."""

    path: str
    version: str | None = None
    has_workflows: bool = False
    orb_count: int = 0
    job_count: int = 0
    lines: int = 0


@dataclass
class CircleStats:
    """Aggregate CircleCI config analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    rel = str(path).replace("\\", "/")
    return rel.endswith((".circleci/config.yml", ".circleci/config.yaml"))


class CircleCIAnalyzer:
    """Audit CircleCI configuration files for security risks and best practices.

    Scans for secrets in environment blocks, curl-pipe-to-shell install scripts,
    unpinned orbs and Docker images, privileged containers, and unsafe run steps.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleFinding] | None = None
        self._stats: CircleStats | None = None
        self._infos: list[CircleInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return CircleCI config file paths found in the project."""
        found: list[Path] = []
        for rel in CONFIG_PATHS:
            path = self.root / rel
            if path.is_file():
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CircleFinding], CircleInfo]:
        findings: list[CircleFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CircleInfo(path=rel)

        info = CircleInfo(path=rel, lines=len(raw_lines))
        in_env_block = False
        env_indent = 0
        in_run_block = False
        run_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("version:"):
                info.version = line.split(":", 1)[1].strip()

            if line.startswith("workflows:") or line == "workflows:":
                info.has_workflows = True

            if line.startswith("jobs:") or line == "jobs:":
                info.job_count += 1

            if line.startswith("orbs:") or line == "orbs:":
                info.orb_count += 1

            if UNPINNED_ORB_PATTERN.match(line):
                findings.append(
                    CircleFinding(
                        kind="unpinned_orb",
                        severity="medium",
                        message="unpinned CircleCI orb — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_IMAGE_PATTERN.match(line) or UNPINNED_EXECUTOR_PATTERN.match(line):
                findings.append(
                    CircleFinding(
                        kind="unpinned_image",
                        severity="low",
                        message="unpinned Docker image or executor — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    CircleFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("environment:") or line == "environment:":
                in_env_block = True
                env_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline:
                    in_env_block = False
                continue

            if in_env_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= env_indent and not line.startswith("environment"):
                    in_env_block = False
                elif SECRET_ENV_PATTERN.search(line):
                    findings.append(
                        CircleFinding(
                            kind="secret_in_env",
                            severity="high",
                            message="potential secret hardcoded in environment — use CircleCI contexts",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if SECRET_ENV_PATTERN.search(line) and not in_env_block:
                findings.append(
                    CircleFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret in CircleCI config — use contexts or project variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("run:") or line == "run:" or line.startswith("- run:"):
                in_run_block = True
                run_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip() if ":" in line else ""
                if inline and not inline.startswith("run"):
                    self._check_run_line(findings, rel, lineno, raw, line)
                    in_run_block = False
                continue

            if in_run_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= run_indent and not line.startswith("run"):
                    in_run_block = False
                elif line.startswith("command:") or line.startswith("- "):
                    self._check_run_line(findings, rel, lineno, raw, line)
                elif DANGEROUS_SCRIPT_PATTERN.search(line) or CURL_PIPE_SHELL_PATTERN.search(line):
                    self._check_run_line(findings, rel, lineno, raw, line)

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    CircleFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged Docker container enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SETUP_REMOTE_DOCKER_PATTERN.search(line):
                findings.append(
                    CircleFinding(
                        kind="remote_docker",
                        severity="low",
                        message="setup_remote_docker used — ensure resource limits and image pinning",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SSH_FINGERPRINT_PATTERN.search(line):
                findings.append(
                    CircleFinding(
                        kind="ssh_deploy",
                        severity="medium",
                        message="SSH fingerprint deploy — ensure deploy keys have minimal scope",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.job_count > 0 and not info.has_workflows:
            findings.append(
                CircleFinding(
                    kind="missing_workflows",
                    severity="low",
                    message="jobs defined without workflows section — prefer workflows for orchestration",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        return findings, info

    def _check_run_line(
        self,
        findings: list[CircleFinding],
        rel: str,
        lineno: int,
        raw: str,
        line: str,
    ) -> None:
        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                CircleFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="CircleCI run step uses eval/exec — review for injection risk",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )
        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                CircleFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="piping curl/wget to shell in CircleCI run step is unsafe",
                    path=rel,
                    lineno=lineno,
                    line=raw.strip(),
                )
            )

    def analyze(self) -> list[CircleFinding]:
        """Scan CircleCI config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CircleFinding] = []
        infos: list[CircleInfo] = []
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
        self._stats = CircleStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CircleStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CircleInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config files)."""
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
        """Scaffold a hardened CircleCI configuration template."""
        return """\
# Generated by DevAI CircleCIAnalyzer
version: 2.1

orbs:
  python: circleci/python@2.1.0

executors:
  python-executor:
    docker:
      - image: cimg/python:3.12.0

jobs:
  test:
    executor: python-executor
    steps:
      - checkout
      - python/install-packages:
          pkg-manager: pip
          app-dir: .
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
            return "CircleCI: no config files found"
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
            version = info.version or "unknown"
            lines.append(
                f"  - {info.path}: version={version}, workflows={info.has_workflows}, "
                f"orbs={info.orb_count}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
