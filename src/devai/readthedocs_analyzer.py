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
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
FAIL_ON_WARNING_FALSE_PATTERN = re.compile(
    r"^\s*fail_on_warning\s*:\s*false\b",
    re.IGNORECASE,
)
SYSTEM_PACKAGES_TRUE_PATTERN = re.compile(
    r"^\s*system_packages\s*:\s*true\b",
    re.IGNORECASE,
)
PIP_GIT_INSTALL_PATTERN = re.compile(
    r"(?:git\+|git://|ssh://)[^\s\"']+",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"\b(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh|zsh)\b",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
PIP_EXTRA_INDEX_PATTERN = re.compile(
    r"(?:extra_index_url|index_url)\s*[=:]\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
CONDA_INSECURE_CHANNEL_PATTERN = re.compile(
    r"(?:channel|channels)\s*:\s*[^\n]*http://",
    re.IGNORECASE,
)
SUBMODULE_HTTP_PATTERN = re.compile(
    r"(?:url|repo)\s*:\s*['\"]?http://",
    re.IGNORECASE,
)
BUILD_COMMAND_PATTERN = re.compile(
    r"^\s*-\s*(?:command|pre_install|post_install|pre_create_environment|"
    r"create_environment|install|build|post_build)\s*:",
    re.IGNORECASE,
)
UNPINNED_PYTHON_PATTERN = re.compile(
    r"^\s*python\s*:\s*['\"]?(?:latest|3\.x|3)['\"]?\s*$",
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
    build_os: str | None = None
    python_version: str | None = None
    has_build_jobs: bool = False
    has_custom_commands: bool = False


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

    Scans .readthedocs.yaml for hardcoded secrets, unsafe build commands,
    system package installs, insecure URLs, and relaxed warning policies.
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

        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if key in ("build", "python", "sphinx", "submodules", "conda", "jobs"):
                section = key
            elif key == "tools":
                section = "tools"
            else:
                section = key

        if stripped.startswith("version:"):
            raw = stripped.split(":", 1)[1].strip().strip("'\"")
            if raw.isdigit():
                info.version = int(raw)

        if section == "build" and stripped.startswith("os:"):
            info.build_os = stripped.split(":", 1)[1].strip().strip("'\"")

        if section == "tools" and stripped.startswith("python:"):
            info.python_version = stripped.split(":", 1)[1].strip().strip("'\"")

        if section == "build" and stripped.startswith("jobs:"):
            info.has_build_jobs = True

        if section == "build" and stripped.startswith("commands:"):
            info.has_custom_commands = True

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
                    message="credentials embedded in URL — remove user:pass@ and use RTD secrets",
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
                    message="fail_on_warning: false hides Sphinx build warnings — keep enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SYSTEM_PACKAGES_TRUE_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="system_packages_enabled",
                    severity="medium",
                    message="system_packages: true installs OS packages — prefer pip/conda only",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PIP_GIT_INSTALL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="pip_git_install",
                    severity="medium",
                    message="pip install from git URL — pin commit SHA and verify repository trust",
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
                    message="curl/wget piped to shell in build command — avoid remote script execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_EXEC_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="eval_exec",
                    severity="high",
                    message="eval/exec in build command — avoid dynamic code execution in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PIP_EXTRA_INDEX_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="pip_index_credentials",
                    severity="high",
                    message="credentials in pip index URL — use RTD secrets or token auth",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CONDA_INSECURE_CHANNEL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="conda_insecure_channel",
                    severity="medium",
                    message="conda channel uses HTTP — use HTTPS package indexes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUBMODULE_HTTP_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="submodule_http",
                    severity="medium",
                    message="submodule uses HTTP URL — use HTTPS git submodules",
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
                    message="unpinned Python version — pin an explicit minor version for reproducible builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BUILD_COMMAND_PATTERN.search(stripped) and (
            "curl " in line.lower()
            or "wget " in line.lower()
            or "sudo " in line.lower()
            or "chmod 777" in line.lower()
        ):
            findings.append(
                ReadTheDocsFinding(
                    kind="unsafe_build_command",
                    severity="high",
                    message="build job runs potentially unsafe shell command — review and restrict",
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

python:
  install:
    - method: pip
      path: .
      extra_requirements:
        - docs
  system_packages: false

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
