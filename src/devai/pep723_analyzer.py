"""Pep723Analyzer — audit PEP 723 inline script metadata blocks for supply-chain risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PEP723_START_PATTERN = re.compile(r"^\s*#\s*///\s*script\s*$", re.IGNORECASE)
PEP723_END_PATTERN = re.compile(r"^\s*#\s*///\s*$")

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
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s\"']+#egg=)",
    re.IGNORECASE,
)
UNPINNED_DEP_PATTERN = re.compile(
    r"^\s*[\"']([a-zA-Z0-9_.-]+)[\"']\s*,?\s*$",
)
WILDCARD_VERSION_PATTERN = re.compile(
    r"[\"'][^\"']*(?:==\s*\*|>=\s*\*|~\=\s*\*|!=\s*\*)[^\"']*[\"']",
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)
BROAD_PYTHON_REQ_PATTERN = re.compile(
    r"requires-python\s*=\s*[\"'](?:\*|>=?\s*2\.|>=?\s*3(?:\s|$))[\"']",
    re.IGNORECASE,
)
DEPENDENCIES_KEY_PATTERN = re.compile(r"^\s*dependencies\s*=", re.IGNORECASE)
REQUIRES_PYTHON_KEY_PATTERN = re.compile(r"^\s*requires-python\s*=", re.IGNORECASE)

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
}


@dataclass
class Pep723Finding:
    """A security or best-practice issue in a PEP 723 inline script block."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class Pep723Info:
    """Parsed metadata about a PEP 723 inline script block."""

    path: str
    start_line: int
    end_line: int = 0
    requires_python: str = ""
    dependencies: list[str] = field(default_factory=list)
    unpinned_dependencies: list[str] = field(default_factory=list)


@dataclass
class Pep723Stats:
    """Aggregate PEP 723 analysis statistics."""

    script_blocks: int = 0
    python_files_scanned: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class Pep723Analyzer:
    """Audit PEP 723 inline script metadata blocks for supply-chain and security risks.

    Scans Python files for ``# /// script`` comment blocks and flags unpinned
    dependencies, insecure HTTP/git URLs, hardcoded secrets, wildcard versions,
    overly broad requires-python constraints, and dangerous shell patterns.
    """

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or DEFAULT_IGNORE_DIRS
        self._findings: list[Pep723Finding] | None = None
        self._stats: Pep723Stats | None = None
        self._infos: list[Pep723Info] | None = None

    def python_files(self) -> list[Path]:
        """Return Python files scanned for PEP 723 blocks."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*.py")):
            if any(part in self.ignore_dirs for part in path.parts):
                continue
            found.append(path)
        return found

    def _strip_comment(self, line: str) -> str:
        stripped = line.strip()
        if not stripped.startswith("#"):
            return ""
        content = stripped[1:].strip()
        return content

    def _scan_block_line(
        self,
        content: str,
        lineno: int,
        rel: str,
        findings: list[Pep723Finding],
        info: Pep723Info,
        in_dependencies: bool,
    ) -> bool:
        if not content or content == "///":
            return in_dependencies

        if REQUIRES_PYTHON_KEY_PATTERN.match(content):
            match = re.search(r"requires-python\s*=\s*[\"']([^\"']+)[\"']", content, re.IGNORECASE)
            if match:
                info.requires_python = match.group(1)
            if BROAD_PYTHON_REQ_PATTERN.search(content):
                findings.append(
                    Pep723Finding(
                        kind="broad_requires_python",
                        severity="low",
                        message="overly broad requires-python — pin a minimum supported version",
                        path=rel,
                        lineno=lineno,
                        line=content,
                    )
                )

        if DEPENDENCIES_KEY_PATTERN.match(content):
            in_dependencies = True
            inline_deps = re.findall(r"[\"']([^\"']+)[\"']", content)
            for dep in inline_deps:
                info.dependencies.append(dep)
                if not re.search(r"[<>=!~]=|[@=]\d", dep):
                    info.unpinned_dependencies.append(dep)
                    findings.append(
                        Pep723Finding(
                            kind="unpinned_dependency",
                            severity="medium",
                            message=f"unpinned dependency '{dep}' — pin versions for reproducible script runs",
                            path=rel,
                            lineno=lineno,
                            line=content,
                        )
                    )
            return in_dependencies

        if in_dependencies:
            dep_match = UNPINNED_DEP_PATTERN.match(content)
            if dep_match:
                dep = dep_match.group(1)
                info.dependencies.append(dep)
                info.unpinned_dependencies.append(dep)
                findings.append(
                    Pep723Finding(
                        kind="unpinned_dependency",
                        severity="medium",
                        message=f"unpinned dependency '{dep}' — pin versions for reproducible script runs",
                        path=rel,
                        lineno=lineno,
                        line=content,
                    )
                )
            elif re.search(r"[\"'][^\"']+[\"']", content):
                for dep in re.findall(r"[\"']([^\"']+)[\"']", content):
                    info.dependencies.append(dep)
                    if not re.search(r"[<>=!~]=|[@=]\d", dep):
                        info.unpinned_dependencies.append(dep)
                        findings.append(
                            Pep723Finding(
                                kind="unpinned_dependency",
                                severity="medium",
                                message=f"unpinned dependency '{dep}' — pin versions for reproducible script runs",
                                path=rel,
                                lineno=lineno,
                                line=content,
                            )
                        )

        if WILDCARD_VERSION_PATTERN.search(content):
            findings.append(
                Pep723Finding(
                    kind="wildcard_version",
                    severity="high",
                    message="wildcard version constraint in PEP 723 dependencies — pin exact versions",
                    path=rel,
                    lineno=lineno,
                    line=content,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(content):
            findings.append(
                Pep723Finding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in PEP 723 metadata — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=content,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(content):
            findings.append(
                Pep723Finding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in PEP 723 metadata — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=content,
                )
            )

        if INSECURE_HTTP_PATTERN.search(content):
            findings.append(
                Pep723Finding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in PEP 723 metadata — use HTTPS package indexes",
                    path=rel,
                    lineno=lineno,
                    line=content,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(content):
            findings.append(
                Pep723Finding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in PEP 723 block — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=content,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(content) or DANGEROUS_SHELL_PATTERN.search(content):
            findings.append(
                Pep723Finding(
                    kind="dangerous_command",
                    severity="high",
                    message="dangerous shell pattern in PEP 723 metadata — review script dependencies",
                    path=rel,
                    lineno=lineno,
                    line=content,
                )
            )

        return in_dependencies

    def _analyze_file(self, path: Path) -> tuple[list[Pep723Finding], list[Pep723Info]]:
        findings: list[Pep723Finding] = []
        infos: list[Pep723Info] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, infos

        in_block = False
        in_dependencies = False
        block_start = 0
        current_info: Pep723Info | None = None

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if PEP723_START_PATTERN.match(line):
                in_block = True
                in_dependencies = False
                block_start = lineno
                current_info = Pep723Info(path=rel, start_line=lineno)
                continue

            if not in_block:
                continue

            content = self._strip_comment(line)
            if PEP723_END_PATTERN.match(line) or content == "///":
                if current_info is not None:
                    current_info.end_line = lineno
                    infos.append(current_info)
                in_block = False
                in_dependencies = False
                current_info = None
                continue

            if current_info is not None:
                in_dependencies = self._scan_block_line(
                    content, lineno, rel, findings, current_info, in_dependencies
                )

        return findings, infos

    def analyze(self) -> list[Pep723Finding]:
        """Scan Python files for PEP 723 blocks and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[Pep723Finding] = []
        infos: list[Pep723Info] = []
        py_files = self.python_files()

        for path in py_files:
            file_findings, file_infos = self._analyze_file(path)
            findings.extend(file_findings)
            infos.extend(file_infos)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = Pep723Stats(
            script_blocks=len(infos),
            python_files_scanned=len(py_files),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> Pep723Stats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[Pep723Info]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.script_blocks == 0:
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
        """Scaffold a hardened PEP 723 inline script metadata block."""
        return """\
# Generated by DevAI Pep723Analyzer
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "httpx==0.28.1",
#   "pydantic==2.10.6",
# ]
# ///
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.script_blocks == 0:
            return f"PEP 723 blocks: none found ({stats.python_files_scanned} Python files scanned)"
        return (
            f"PEP 723 blocks: {stats.script_blocks} block(s) in "
            f"{stats.python_files_scanned} file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "PEP 723 inline script analysis:",
            f"  python files scanned: {stats.python_files_scanned}",
            f"  script blocks: {stats.script_blocks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies) or "none"
            lines.append(
                f"  - {info.path}:{info.start_line}: requires-python={info.requires_python or 'unspecified'}, "
                f"dependencies=[{deps}]"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
