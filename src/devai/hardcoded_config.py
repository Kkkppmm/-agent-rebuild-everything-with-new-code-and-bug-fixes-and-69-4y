"""HardcodedConfigAnalyzer — detect hardcoded URLs, IPs, DB URLs, and env defaults."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_URL_PATTERN = re.compile(
    r"https?://[^\s'\"<>]+",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_DB_URL_PATTERN = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|oracle)://[^\s'\"]+"
)
_SQLITE_PATH_PATTERN = re.compile(
    r"""sqlite(?:3)?:///(?:[A-Za-z]:)?[/\\][^\s'"]+"""
)

_LOCALHOST_MARKERS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})
_PLACEHOLDER_MARKERS = re.compile(
    r"(?i)\b(example\.com|placeholder|changeme|your[_-]?host|xxx+|dummy|test|sample|fake)\b"
)
_PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
)


@dataclass
class HardcodedConfigFinding:
    """A hardcoded configuration value found in source code."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    snippet: str = ""
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class HardcodedConfigStats:
    """Aggregate hardcoded configuration analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_IP_PREFIXES)


def _url_severity(url: str) -> str:
    lowered = url.lower()
    if any(marker in lowered for marker in _LOCALHOST_MARKERS):
        return "low"
    if _PLACEHOLDER_MARKERS.search(url):
        return "low"
    return "medium"


def _ip_severity(ip: str) -> str:
    if ip in {"127.0.0.1", "0.0.0.0"}:
        return "low"
    if _is_private_ip(ip):
        return "medium"
    return "high"


def _scan_line(
    line: str,
    path: str,
    lineno: int,
    *,
    function: str = "",
) -> list[HardcodedConfigFinding]:
    findings: list[HardcodedConfigFinding] = []
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return findings
    if _PLACEHOLDER_MARKERS.search(line):
        return findings

    for match in _DB_URL_PATTERN.finditer(line):
        findings.append(
            HardcodedConfigFinding(
                path=path,
                lineno=lineno,
                pattern="database_url",
                severity="high",
                message="Hardcoded database connection string — use environment variables",
                snippet=stripped[:80],
                function=function,
            )
        )

    for match in _SQLITE_PATH_PATTERN.finditer(line):
        findings.append(
            HardcodedConfigFinding(
                path=path,
                lineno=lineno,
                pattern="sqlite_path",
                severity="medium",
                message="Hardcoded SQLite file path — prefer configurable data directory",
                snippet=stripped[:80],
                function=function,
            )
        )

    for match in _URL_PATTERN.finditer(line):
        url = match.group(0)
        findings.append(
            HardcodedConfigFinding(
                path=path,
                lineno=lineno,
                pattern="hardcoded_url",
                severity=_url_severity(url),
                message="Hardcoded URL — move to configuration or environment",
                snippet=stripped[:80],
                function=function,
            )
        )

    for match in _IP_PATTERN.finditer(line):
        ip = match.group(0)
        findings.append(
            HardcodedConfigFinding(
                path=path,
                lineno=lineno,
                pattern="hardcoded_ip",
                severity=_ip_severity(ip),
                message="Hardcoded IP address — use configuration for host values",
                snippet=stripped[:80],
                function=function,
            )
        )

    return findings


class _HardcodedConfigVisitor(ast.NodeVisitor):
    """Walk a module AST and collect hardcoded env defaults."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HardcodedConfigFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "getenv":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                default = node.args[1].value
                if isinstance(default, str) and default and not _PLACEHOLDER_MARKERS.search(default):
                    key = ""
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        key = node.args[0].value
                    self.findings.append(
                        HardcodedConfigFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="env_default",
                            severity="medium",
                            message=f"os.getenv('{key}', ...) uses a hardcoded default — load from config instead",
                            snippet=f"default={default!r}"[:80],
                            function=self._current_function(),
                        )
                    )
        if isinstance(func, ast.Attribute) and func.attr == "get" and isinstance(func.value, ast.Attribute):
            if func.value.attr == "environ" and node.args and isinstance(node.args[0], ast.Constant):
                key = node.args[0].value
                if isinstance(key, str):
                    self.findings.append(
                        HardcodedConfigFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="environ_access",
                            severity="low",
                            message=f"Direct os.environ access for '{key}' — prefer os.getenv with validation",
                            snippet=f"os.environ.get({key!r})"[:80],
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class HardcodedConfigAnalyzer:
    """Detect hardcoded URLs, IPs, database URLs, and environment defaults.

    Flags configuration values that should live in environment variables,
    secret stores, or external config files instead of source code.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HardcodedConfigFinding] = []
        self._stats: HardcodedConfigStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix not in {".py", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}

    def analyze(self) -> list[HardcodedConfigFinding]:
        """Analyze the project and return hardcoded configuration findings."""
        if self._findings:
            return self._findings

        findings: list[HardcodedConfigFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))

            if path.suffix == ".py":
                try:
                    tree = ast.parse(source, filename=str(path))
                except SyntaxError:
                    tree = None
                if tree is not None:
                    visitor = _HardcodedConfigVisitor(rel)
                    visitor.visit(tree)
                    if visitor.findings:
                        files_with_findings.add(rel)
                    findings.extend(visitor.findings)

            for lineno, line in enumerate(source.splitlines(), 1):
                line_findings = _scan_line(line, rel, lineno)
                if line_findings:
                    files_with_findings.add(rel)
                findings.extend(line_findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = HardcodedConfigStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HardcodedConfigStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[HardcodedConfigFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no hardcoded configuration)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 20.0 + medium * 8.0 + low * 2.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Hardcoded configuration: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing hardcoded configuration findings."""
        self.analyze()
        lines = [
            "Hardcoded configuration analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No hardcoded configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
