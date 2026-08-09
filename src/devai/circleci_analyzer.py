"""CircleCIAnalyzer — audit CircleCI configs for security and CI best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CIRCLECI_CONFIG_PATHS = (".circleci/config.yml", ".circleci/config.yaml")

SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
MUTABLE_IMAGE_TAG_PATTERN = re.compile(
    r"^\s*(?:-\s+)?image:\s*[^:]+:(latest|stable|nightly|dev|main|master)\s*$",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"^\s*(?:-\s+)?image:\s*(?!.*:)[a-z0-9][a-z0-9._/-]*\s*$",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"privileged\s*:\s*true\b", re.IGNORECASE)
UNPINNED_ORB_PATTERN = re.compile(
    r"^\s+[a-z0-9_-]+:\s*[a-z0-9_-]+/[a-z0-9_-]+(?!\s*@)",
    re.IGNORECASE,
)
SSH_KEY_PATTERN = re.compile(
    r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
ADD_SSH_KEYS_PATTERN = re.compile(r"^\s*-?\s*add_ssh_keys\s*:", re.IGNORECASE)
SETUP_REMOTE_DOCKER_PATTERN = re.compile(r"^\s*-?\s*setup_remote_docker\s*:", re.IGNORECASE)
DEPLOY_JOB_PATTERN = re.compile(r"^\s*(deploy|release|production)\s*:", re.IGNORECASE)
APPROVAL_STEP_PATTERN = re.compile(r"^\s*type\s*:\s*approval\b", re.IGNORECASE)
HARDCODED_CONTEXT_PATTERN = re.compile(
    r"^\s*context\s*:\s*[^$\s][^\n]*$",
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
    version: str = ""
    workflows: list[str] = field(default_factory=list)
    jobs: list[str] = field(default_factory=list)
    orbs: list[str] = field(default_factory=list)
    uses_docker: bool = False
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
    rel = path.as_posix()
    return rel.endswith(".circleci/config.yml") or rel.endswith(".circleci/config.yaml")


class CircleCIAnalyzer:
    """Audit CircleCI configuration files for security risks and CI best practices.

    Scans for hardcoded secrets, curl-pipe-to-shell scripts, unpinned Docker images
    and orbs, privileged containers, embedded SSH keys, and ungated deploy jobs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CircleCIFinding] | None = None
        self._stats: CircleCIStats | None = None
        self._infos: list[CircleCIInfo] | None = None

    def configs(self) -> list[Path]:
        """Return CircleCI config file paths found in the project."""
        found: list[Path] = []
        for rel in CIRCLECI_CONFIG_PATHS:
            direct = self.root / rel
            if direct.is_file():
                found.append(direct)
        for path in sorted(self.root.rglob(".circleci/config.*")):
            if path.is_file() and path.suffix.lower() in (".yml", ".yaml") and path not in found:
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CircleCIFinding], CircleCIInfo]:
        findings: list[CircleCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, CircleCIInfo(path=rel)

        info = CircleCIInfo(path=rel, lines=len(raw_lines))
        in_environment_block = False
        env_indent = 0
        in_orbs_block = False
        orbs_indent = 0
        in_workflows_block = False
        in_jobs_block = False
        has_approval_step = APPROVAL_STEP_PATTERN.search(content) is not None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("version:"):
                info.version = line.split(":", 1)[1].strip()

            if line == "orbs:":
                in_orbs_block = True
                orbs_indent = len(raw) - len(raw.lstrip())
                continue

            if in_orbs_block:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= orbs_indent and line.endswith(":"):
                    in_orbs_block = False
                else:
                    if UNPINNED_ORB_PATTERN.match(raw):
                        orb_name = line.split(":", 1)[0].strip()
                        if orb_name not in info.orbs:
                            info.orbs.append(orb_name)
                        findings.append(
                            CircleCIFinding(
                                kind="unpinned_orb",
                                severity="medium",
                                message="orb without version pin — pin orbs to a specific release tag",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )
                    continue

            if line == "workflows:":
                in_workflows_block = True
                in_jobs_block = False
                continue

            if line == "jobs:":
                in_jobs_block = True
                in_workflows_block = False
                continue

            if in_workflows_block and re.match(r"^\s+\w[\w-]*:\s*$", raw):
                workflow = line[:-1].strip()
                if workflow and workflow not in info.workflows:
                    info.workflows.append(workflow)

            if in_jobs_block and re.match(r"^\s+\w[\w-]*:\s*$", raw):
                job = line[:-1].strip()
                if job and job not in info.jobs:
                    info.jobs.append(job)

            if line.endswith(":") and not line.startswith("-"):
                key = line[:-1].strip()
                if key == "environment":
                    in_environment_block = True
                    env_indent = len(raw) - len(raw.lstrip())
                elif key in ("docker", "machine", "resource_class", "steps", "workflows", "jobs"):
                    in_environment_block = False

            if line.startswith("docker:") or line.startswith("- image:") or line.startswith("image:"):
                info.uses_docker = True

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container grants full host access to the job",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if MUTABLE_IMAGE_TAG_PATTERN.match(line) or UNPINNED_IMAGE_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="unpinned_image",
                        severity="medium",
                        message="Docker image unpinned or uses mutable tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_environment_block and SECRET_ENV_PATTERN.search(line):
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent > env_indent and not line.startswith("$"):
                    findings.append(
                        CircleCIFinding(
                            kind="secret_in_environment",
                            severity="high",
                            message="potential secret hardcoded in environment — use CircleCI contexts or project env vars",
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
                        message="piping curl/wget to shell in CircleCI command is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SSH_KEY_PATTERN.search(line):
                findings.append(
                    CircleCIFinding(
                        kind="embedded_ssh_key",
                        severity="high",
                        message="private SSH key embedded in config — use CircleCI SSH keys or contexts",
                        path=rel,
                        lineno=lineno,
                        line="[redacted private key]",
                    )
                )

            if ADD_SSH_KEYS_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="add_ssh_keys",
                        severity="low",
                        message="add_ssh_keys step — ensure deploy keys are scoped and rotated",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SETUP_REMOTE_DOCKER_PATTERN.match(line):
                findings.append(
                    CircleCIFinding(
                        kind="setup_remote_docker",
                        severity="medium",
                        message="setup_remote_docker increases attack surface — review docker image pins and layer caching",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HARDCODED_CONTEXT_PATTERN.match(line) and "context:" in line.lower():
                value = line.split(":", 1)[1].strip()
                if value and not value.startswith("$"):
                    findings.append(
                        CircleCIFinding(
                            kind="hardcoded_context",
                            severity="low",
                            message="hardcoded context name — prefer parameterized contexts for reusable pipelines",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if DEPLOY_JOB_PATTERN.match(line) and not has_approval_step:
                findings.append(
                    CircleCIFinding(
                        kind="ungated_deploy",
                        severity="low",
                        message="deploy/release job without approval step — add type: approval before production deploys",
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
        """Scaffold a hardened CircleCI configuration template."""
        return """\
# Generated by DevAI CircleCIAnalyzer
version: 2.1

orbs:
  python: circleci/python@2.1.0

jobs:
  test:
    docker:
      - image: cimg/python:3.12.0
    environment:
      PIP_DISABLE_PIP_VERSION_CHECK: "1"
    steps:
      - checkout
      - run:
          name: Install dependencies
          command: pip install -e ".[dev]"
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
            "CircleCI analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: version={info.version or 'unknown'}, "
                f"workflows={len(info.workflows)}, jobs={len(info.jobs)}, "
                f"orbs={len(info.orbs)}, docker={info.uses_docker}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
