"""ReadTheDocsAnalyzer — audit .readthedocs.yaml for documentation build security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".readthedocs.yaml",
    ".readthedocs.yml",
    "readthedocs.yaml",
    "readthedocs.yml",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|ssh_key)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
CURL_PIPE_BASH_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh)\b",
    re.IGNORECASE,
)
PIP_UNTRUSTED_URL_PATTERN = re.compile(
    r"pip\s+install\s+[^\n]*(?:--index-url|--extra-index-url)\s+http://",
    re.IGNORECASE,
)
PIP_GIT_HTTP_PATTERN = re.compile(
    r"pip\s+install\s+[^\n]*git\+http://",
    re.IGNORECASE,
)
PIP_NO_HASH_PATTERN = re.compile(
    r"pip\s+install\s+[^\n]*--no-deps\b",
    re.IGNORECASE,
)
ARBITRARY_COMMAND_PATTERN = re.compile(
    r"^\s*-\s*(?:curl|wget|bash|sh|eval|exec)\s+",
    re.IGNORECASE,
)
LATEST_PYTHON_PATTERN = re.compile(
    r"python\s*:\s*['\"]?(?:latest|3)\b",
    re.IGNORECASE,
)
PIP_PRE_RELEASE_PATTERN = re.compile(
    r"pip\s+install\s+[^\n]*--pre\b",
    re.IGNORECASE,
)
SSH_KEY_PATTERN = re.compile(
    r"(?:BEGIN (?:RSA |OPENSSH )?PRIVATE KEY|ssh-rsa AAAA)",
    re.IGNORECASE,
)
BUILD_IMAGE_UNPINNED_PATTERN = re.compile(
    r"(?:image|build_image)\s*:\s*['\"]?[^'\":\s]+:latest['\"]?",
    re.IGNORECASE,
)
SUDO_COMMAND_PATTERN = re.compile(
    r"^\s*-\s*sudo\s+",
    re.IGNORECASE,
)
REQUIREMENTS_PARENT_PATTERN = re.compile(
    r"(?:requirements|path)\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)


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
    python_version: str | None = None
    has_build_commands: bool = False
    has_sphinx: bool = False
    has_mkdocs: bool = False


@dataclass
class ReadTheDocsStats:
    """Aggregate Read the Docs analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_rtd_config(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class ReadTheDocsAnalyzer:
    """Audit Read the Docs configuration for documentation build security risks.

    Scans .readthedocs.yaml for hardcoded secrets, arbitrary build commands,
  insecure pip installs, curl|bash patterns, unpinned Python versions, and SSH keys.
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
            if path.is_file() and _is_rtd_config(path) and path not in found:
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
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if key in ("build", "python", "sphinx", "mkdocs", "commands", "jobs", "install"):
                section = key
            else:
                section = key

        if stripped.startswith("version:"):
            try:
                info.version = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass

        if "python:" in stripped and section == "build":
            match = re.search(r"python\s*:\s*['\"]?([^'\"#\s]+)", stripped)
            if match:
                info.python_version = match.group(1)

        if section in ("commands", "jobs", "post_install", "pre_install"):
            info.has_build_commands = True

        if section == "sphinx" or stripped.startswith("sphinx:"):
            info.has_sphinx = True

        if section == "mkdocs" or stripped.startswith("mkdocs:"):
            info.has_mkdocs = True

        checks = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in RTD config — use RTD dashboard secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in RTD config — rotate and use dashboard secrets"),
            (SSH_KEY_PATTERN, "ssh_private_key", "high", "private SSH key in RTD config — never commit keys; use deploy keys in dashboard"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in RTD config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL — remove user:pass@"),
            (CURL_PIPE_BASH_PATTERN, "curl_pipe_bash", "high", "curl|bash pattern in build commands — avoid piping remote scripts to shell"),
            (ARBITRARY_COMMAND_PATTERN, "arbitrary_command", "high", "arbitrary shell command in build — restrict to trusted package installs"),
            (PIP_UNTRUSTED_URL_PATTERN, "pip_untrusted_index", "high", "pip install from insecure HTTP index — use HTTPS package indexes"),
            (PIP_GIT_HTTP_PATTERN, "pip_git_http", "high", "pip install from git+http — use git+https or pinned tags"),
            (PIP_PRE_RELEASE_PATTERN, "pip_pre_release", "medium", "pip --pre installs pre-release packages — pin exact versions for reproducibility"),
            (PIP_NO_HASH_PATTERN, "pip_no_deps", "low", "pip --no-deps skips dependency resolution — verify supply chain"),
            (LATEST_PYTHON_PATTERN, "unpinned_python", "low", "unpinned Python version — pin a specific minor version"),
            (BUILD_IMAGE_UNPINNED_PATTERN, "unpinned_image", "medium", "Docker image uses :latest tag — pin to a specific digest or version"),
            (SUDO_COMMAND_PATTERN, "sudo_command", "high", "sudo in build commands — RTD builds should not require elevated privileges"),
            (REQUIREMENTS_PARENT_PATTERN, "requirements_parent_path", "medium", "requirements path escapes project — use paths within the repo"),
        ]
        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    ReadTheDocsFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[ReadTheDocsFinding], ReadTheDocsInfo]:
        findings: list[ReadTheDocsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ReadTheDocsInfo(path=rel)

        info = ReadTheDocsInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

        if info.version is not None and info.version < 2:
            findings.append(
                ReadTheDocsFinding(
                    kind="legacy_config_version",
                    severity="low",
                    message="config version < 2 is legacy — migrate to version 2 for reproducible builds",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
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

formats: []
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
