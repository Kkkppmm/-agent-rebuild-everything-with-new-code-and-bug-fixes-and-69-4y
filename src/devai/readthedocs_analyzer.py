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
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"curl\s+[^\n|]*\|\s*(?:ba)?sh",
    re.IGNORECASE,
)
TRUSTED_HOST_PATTERN = re.compile(
    r"pip\s+install[^\n]*--trusted-host",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
FAIL_ON_WARNING_FALSE_PATTERN = re.compile(
    r"^\s*fail_on_warning\s*:\s*false\b",
    re.IGNORECASE,
)
SUBMODULES_INCLUDE_PATTERN = re.compile(
    r"^\s*submodules\s*:\s*(?:include|true)\b",
    re.IGNORECASE,
)
FORMATS_ALL_PATTERN = re.compile(
    r"^\s*formats\s*:\s*(?:all|\[.*pdf.*epub.*\])",
    re.IGNORECASE,
)
UNPINNED_PYTHON_PATTERN = re.compile(
    r"^\s*python\s*:\s*[\"']?(?:latest|3|3\.x)[\"']?\s*$",
    re.IGNORECASE,
)
BUILD_COMMANDS_SECTION = re.compile(r"^\s*(?:commands|pre_install|post_install)\s*:", re.IGNORECASE)
ENV_SECTION_PATTERN = re.compile(r"^\s*(?:build\.env|environment)\s*:\s*$", re.IGNORECASE)


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
    version: str | None = None
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
    """Audit Read the Docs configuration for documentation build security risks.

    Scans .readthedocs.yaml for hardcoded secrets, curl-pipe-to-shell, unpinned
    tool versions, insecure pip flags, submodule inclusion, and relaxed warnings.
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
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if re.match(r"^\s*version\s*:\s*\d+", stripped, re.IGNORECASE):
            info.version = stripped.split(":", 1)[1].strip().strip("\"'")

        if BUILD_COMMANDS_SECTION.match(stripped):
            section = "commands"
            info.has_build_jobs = True
            return section
        if ENV_SECTION_PATTERN.match(stripped):
            section = "env"
            return section
        if stripped.startswith("- ") and section == "commands":
            pass
        elif stripped and not stripped.startswith("-") and ":" in stripped and not line.startswith(" "):
            section = stripped.split(":", 1)[0].strip().lower()

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="Hardcoded secret in Read the Docs config — use RTD dashboard secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl-pipe-to-shell in build commands — vendor scripts or pin checksums",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRUSTED_HOST_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="pip_trusted_host",
                    severity="high",
                    message="pip --trusted-host disables TLS verification — use HTTPS index URLs",
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
                    message="Insecure HTTP URL — prefer HTTPS for package indexes and repos",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FAIL_ON_WARNING_FALSE_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="fail_on_warning_false",
                    severity="medium",
                    message="fail_on_warning disabled — broken docs may publish silently",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUBMODULES_INCLUDE_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="submodules_include",
                    severity="medium",
                    message="Git submodules included — pin submodule commits and audit sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORMATS_ALL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="formats_all",
                    severity="low",
                    message="All output formats enabled — enable only formats you need",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_PYTHON_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="unpinned_python",
                    severity="low",
                    message="Unpinned Python version — pin a specific minor version for reproducible builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section in ("commands", "env") and re.search(
            r"(?:export|RTD_|READTHEDOCS_)\w+\s*=\s*[\"'][^\"'\s${}][^\"']*[\"']",
            line,
            re.IGNORECASE,
        ):
            findings.append(
                ReadTheDocsFinding(
                    kind="env_literal",
                    severity="medium",
                    message="Literal environment variable in build config — use RTD dashboard secrets",
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

sphinx:
  configuration: docs/conf.py
  fail_on_warning: true

formats: []

python:
  install:
    - method: pip
      path: .
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
