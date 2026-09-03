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
    r"(?:url|repo|path|requirements)\s*:\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
GIT_HTTP_PATTERN = re.compile(
    r"git\+?http://[^\s\"']+",
    re.IGNORECASE,
)
CURL_PIPE_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh|python)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\s+(?:apt|yum|apk|dnf)\b", re.IGNORECASE)
PIP_URL_INSTALL_PATTERN = re.compile(
    r"(?:pip|uv)\s+install\s+https?://",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"^\s*(?:SECRET|TOKEN|PASSWORD|API_KEY|AWS_)[A-Z0-9_]*\s*:\s*[^\s${}][^\s]*",
    re.IGNORECASE,
)
SHELL_TRUE_PATTERN = re.compile(
    r"(?:bash|sh)\s+-c\s+['\"]",
    re.IGNORECASE,
)
OLD_PYTHON_PATTERN = re.compile(
    r"^\s*python\s*:\s*['\"]?(?:2\.|3\.[0-9](?![0-9.]))",
    re.IGNORECASE,
)
APT_PACKAGES_PATTERN = re.compile(r"^\s*apt_packages\s*:", re.IGNORECASE)
JOBS_SECTION_PATTERN = re.compile(r"^\s*jobs\s*:\s*$", re.IGNORECASE)


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
    has_jobs: bool = False
    has_apt_packages: bool = False
    python_version: str | None = None


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

    Scans .readthedocs.yaml for hardcoded secrets, insecure git installs,
    curl|bash pipelines, sudo in build jobs, and outdated Python runtimes.
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
            if key in ("build", "jobs", "python", "submodules", "conda", "formats"):
                section = key
            else:
                section = key

        if stripped.startswith("version:"):
            try:
                info.version = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass

        if JOBS_SECTION_PATTERN.search(stripped):
            info.has_jobs = True
            section = "jobs"

        if APT_PACKAGES_PATTERN.search(stripped):
            info.has_apt_packages = True

        if re.search(r"^\s*python\s*:\s*", stripped, re.IGNORECASE):
            info.python_version = stripped.split(":", 1)[1].strip().strip("'\"")

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Read the Docs config — use RTD admin secrets",
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
                    message="AWS access key in Read the Docs config — rotate and use env vars",
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
                    message="credentials embedded in URL — remove user:pass@ from install sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="git_http_install",
                    severity="high",
                    message="git+http URL in Read the Docs config — use HTTPS or SSH git URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in build job — pin scripts and verify checksums",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUDO_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="sudo_in_build",
                    severity="high",
                    message="sudo in Read the Docs build job — use apt_packages instead of sudo apt",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PIP_URL_INSTALL_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="pip_url_install",
                    severity="medium",
                    message="pip install from URL — pin version and verify package integrity",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ENV_SECRET_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="env_secret",
                    severity="high",
                    message="secret value in environment block — use Read the Docs admin secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHELL_TRUE_PATTERN.search(line):
            findings.append(
                ReadTheDocsFinding(
                    kind="shell_command",
                    severity="medium",
                    message="shell -c in build job — prefer explicit commands over shell wrappers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if OLD_PYTHON_PATTERN.search(stripped):
            findings.append(
                ReadTheDocsFinding(
                    kind="old_python_version",
                    severity="low",
                    message="outdated Python version in Read the Docs config — upgrade to 3.10+",
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

        if info.has_apt_packages:
            findings.append(
                ReadTheDocsFinding(
                    kind="apt_packages",
                    severity="low",
                    message="apt_packages declared — review packages and pin versions where possible",
                    path=rel,
                    lineno=1,
                    line="apt_packages:",
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

sphinx:
  configuration: docs/conf.py

python:
  install:
    - requirements: docs/requirements.txt

# Use Read the Docs admin panel for secrets — never commit tokens here
# build.jobs:
#   pre_build:
#     - echo "Add trusted pre-build steps here"
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
