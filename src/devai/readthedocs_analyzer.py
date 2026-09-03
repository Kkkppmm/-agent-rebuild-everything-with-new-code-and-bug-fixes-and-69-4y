"""ReadTheDocsAnalyzer — audit .readthedocs.yaml for documentation build security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".readthedocs.yaml",
    ".readthedocs.yml",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:git\+https?|https?)://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
PIPE_TO_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh)\b",
    re.IGNORECASE,
)
GIT_INSTALL_CREDENTIAL_PATTERN = re.compile(
    r"pip\s+install\s+[^\n]*git\+https?://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
PIP_UNTRUSTED_URL_PATTERN = re.compile(
    r"pip\s+install\s+[^\n]*(?:http://|--index-url\s+http://|--extra-index-url\s+http://)",
    re.IGNORECASE,
)
SUBMODULES_ALL_PATTERN = re.compile(
    r"^\s*include\s*:\s*all\b",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^\s*['\"]?[A-Z_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY)[A-Z_]*['\"]?\s*:",
    re.IGNORECASE,
)
BUILD_JOBS_UNSAFE_PATTERN = re.compile(
    r"(?:post_create_environment|post_install|pre_build|post_build)\s*:",
    re.IGNORECASE,
)
SUDO_APT_PATTERN = re.compile(
    r"^\s*-\s*sudo\s+",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)


@dataclass
class ReadTheDocsFinding:
    """A security or best-practice issue in a Read the Docs configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ReadTheDocsInfo:
    """Parsed metadata about a Read the Docs configuration file."""

    path: str
    lines: int = 0
    version: int | None = None
    build_os: str | None = None
    python_version: str | None = None
    has_submodules: bool = False
    has_build_jobs: bool = False


@dataclass
class ReadTheDocsStats:
    """Aggregate Read the Docs analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_readthedocs_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class ReadTheDocsAnalyzer:
    """Audit Read the Docs configuration for build security and hygiene risks.

    Scans .readthedocs.yaml/.readthedocs.yml for hardcoded secrets, pipe-to-shell
    build steps, git credentials in pip installs, untrusted package URLs, and
    overly broad submodule inclusion.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ReadTheDocsFinding] | None = None
        self._stats: ReadTheDocsStats | None = None
        self._infos: list[ReadTheDocsInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Read the Docs configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_readthedocs_file(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ReadTheDocsFinding],
        info: ReadTheDocsInfo,
        section: str,
        in_jobs: bool,
    ) -> tuple[str, bool]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section, in_jobs

        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if key in ("build", "python", "sphinx", "submodules", "conda", "formats"):
                section = key
            elif key == "jobs":
                in_jobs = True
                info.has_build_jobs = True
            elif key in (
                "post_create_environment",
                "post_install",
                "pre_build",
                "post_build",
            ):
                in_jobs = True
                info.has_build_jobs = True
            else:
                section = key

        if stripped.startswith("version:"):
            try:
                info.version = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass

        if section == "build" and "os:" in stripped:
            info.build_os = stripped.split(":", 1)[1].strip().strip("'\"")

        if "python:" in stripped and section == "build":
            info.python_version = stripped.split(":", 1)[1].strip().strip("'\"")

        if section == "submodules":
            info.has_submodules = True

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Read the Docs config — use RTD dashboard secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Read the Docs config — rotate and use RTD secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Read the Docs config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CREDENTIAL_IN_URL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="credential_in_url",
                    severity="high",
                    message="credentials embedded in git/pip URL — remove user:pass@ from install URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PIPE_TO_SHELL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="pipe_to_shell",
                    severity="high",
                    message="curl/wget piped to shell in build step — use pinned packages or trusted scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_INSTALL_CREDENTIAL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="git_install_credentials",
                    severity="high",
                    message="pip install with embedded git credentials — use deploy keys or RTD tokens",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PIP_UNTRUSTED_URL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="pip_untrusted_url",
                    severity="high",
                    message="pip install from insecure HTTP index — use HTTPS package indexes only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section == "submodules" and SUBMODULES_ALL_PATTERN.search(stripped):
            findings.append(
                ReadTheDocsFinding(
                    kind="submodules_all",
                    severity="medium",
                    message="submodules include: all — restrict to required submodules only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_SECRET_PATTERN.search(stripped):
            findings.append(
                ReadTheDocsFinding(
                    kind="env_secret_inline",
                    severity="high",
                    message="secret defined inline in build environment — use RTD dashboard environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_jobs and SUDO_APT_PATTERN.search(stripped):
            findings.append(
                ReadTheDocsFinding(
                    kind="sudo_in_build",
                    severity="medium",
                    message="sudo in build job — avoid elevated commands in documentation builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_jobs and EVAL_EXEC_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="eval_exec_in_build",
                    severity="high",
                    message="eval/exec in build job — avoid dynamic code execution in CI builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BUILD_JOBS_UNSAFE_PATTERN.search(stripped) and PIPE_TO_SHELL_PATTERN.search(line):
            pass  # already caught above

        return section, in_jobs

    def _analyze_file(self, path: Path) -> tuple[list[ReadTheDocsFinding], ReadTheDocsInfo]:
        findings: list[ReadTheDocsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ReadTheDocsInfo(path=rel)

        info = ReadTheDocsInfo(path=rel, lines=len(raw_lines))
        section = ""
        in_jobs = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section, in_jobs = self._scan_line(
                line, lineno, rel, findings, info, section, in_jobs
            )

        return findings, info

    def analyze(self) -> list[ReadTheDocsFinding]:
        """Scan Read the Docs configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ReadTheDocsFinding] = []
        infos: list[ReadTheDocsInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = ReadTheDocsStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ReadTheDocsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ReadTheDocsInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold a hardened Read the Docs configuration template."""
        return """\
# Generated by DevAI ReadTheDocsAnalyzer
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.12"

python:
  install:
    - requirements: docs/requirements.txt

sphinx:
  configuration: docs/conf.py

# Restrict submodules to only what documentation needs
submodules:
  include: []

# Use Read the Docs dashboard for secrets — never commit tokens here
# build:
#   jobs:
#     post_install: []
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Read the Docs configs: none found"
        return (
            f"Read the Docs configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Read the Docs analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
