"""HardcodedConfigAnalyzer — detect hardcoded URLs, IPs, DB URLs, and env access."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_URL_RE = re.compile(
    r"""https?://[^\s'"]+|"""
    r"""ftp://[^\s'"]+""",
    re.IGNORECASE,
)
_IP_RE = re.compile(
    r"""\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"""
)
_DB_URL_RE = re.compile(
    r"""(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite|mssql|oracle)"""
    r"""(?:://|\+)[^\s'"]+""",
    re.IGNORECASE,
)
_ENV_ACCESS_ATTRS = frozenset({"getenv", "environ", "get"})
_ENV_MODULES = frozenset({"os", "dotenv"})


@dataclass
class HardcodedConfigFinding:
    """A hardcoded configuration value or risky env access."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    value: str = ""
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        preview = f" ({self.value[:40]}...)" if len(self.value) > 40 else (f" ({self.value})" if self.value else "")
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}{preview}"


@dataclass
class HardcodedConfigStats:
    """Aggregate hardcoded configuration statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _classify_string_literal(value: str) -> tuple[str, str, str] | None:
    if _DB_URL_RE.search(value):
        return ("hardcoded_db_url", "high", "Hardcoded database connection string — use environment variables")
    if _URL_RE.search(value):
        return ("hardcoded_url", "medium", "Hardcoded URL — prefer configuration or environment variables")
    if _IP_RE.search(value) and not value.startswith("127.0.0.1") and value != "0.0.0.0":
        return ("hardcoded_ip", "medium", "Hardcoded IP address — use configuration or service discovery")
    return None


def _classify_env_access(call: ast.Call) -> tuple[str, str, str] | None:
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None

    module = None
    if isinstance(func.value, ast.Name):
        module = func.value.id
    elif isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
        module = func.value.value.id

    if module not in _ENV_MODULES:
        return None

    if func.attr == "getenv" and call.args:
        key = _string_value(call.args[0])
        if key and key.isupper():
            return None
        if key:
            return (
                "env_getenv_lowercase",
                "low",
                f"os.getenv('{key}') uses lowercase key — prefer UPPER_SNAKE_CASE env vars",
            )

    if func.attr == "get" and module == "os" and call.args:
        key = _string_value(call.args[0])
        if key and not key.isupper():
            return (
                "env_environ_lowercase",
                "low",
                f"os.environ access with lowercase key '{key}' — prefer UPPER_SNAKE_CASE",
            )

    return None


class _HardcodedConfigVisitor(ast.NodeVisitor):
    """Walk a module AST and collect hardcoded configuration issues."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HardcodedConfigFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str, value: str = "") -> None:
        self.findings.append(
            HardcodedConfigFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                value=value,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        value = _string_value(node.value)
        if value:
            result = _classify_string_literal(value)
            if result:
                pattern, severity, message = result
                self._add(node, pattern, severity, message, value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        result = _classify_env_access(node)
        if result:
            pattern, severity, message = result
            self._add(node, pattern, severity, message)
        self.generic_visit(node)


class HardcodedConfigAnalyzer:
    """Detect hardcoded URLs, IPs, database URLs, and risky environment access.

    Helps teams move configuration to environment variables and secret stores.
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
        return path.suffix != ".py"

    def analyze(self) -> list[HardcodedConfigFinding]:
        """Analyze the project and return hardcoded configuration findings."""
        if self._findings:
            return self._findings

        findings: list[HardcodedConfigFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _HardcodedConfigVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

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
        """Return a 0-100 health score (100 = no hardcoded config issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 20.0 + medium * 8.0 + low * 3.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Hardcoded config: {stats.total_findings} findings in "
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
