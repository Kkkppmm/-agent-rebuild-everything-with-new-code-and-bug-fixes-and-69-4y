"""SSRFAnalyzer — detect user-controlled outbound HTTP requests."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|param|query|url|uri|link|href|redirect|callback|"
    r"webhook|endpoint|host|domain|target|fetch|proxy|forward|src|dest)",
    re.IGNORECASE,
)

_HTTP_ATTRS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "request", "fetch", "urlopen", "open"}
)
_HTTP_MODULES = frozenset({"requests", "httpx", "urllib", "aiohttp", "urllib3", "http"})


@dataclass
class SSRFFinding:
    """A potentially unsafe server-side request pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class SSRFStats:
    """Aggregate SSRF analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _looks_like_user_input(node.func)
    return False


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _looks_like_user_input(v) for v in node.values if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _looks_like_user_input(node.left) or _looks_like_user_input(node.right)
    return _looks_like_user_input(node)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _is_http_call(name: str) -> bool:
    parts = name.split(".")
    if not parts:
        return False
    short = parts[-1]
    if short not in _HTTP_ATTRS:
        return False
    if len(parts) >= 2 and parts[0] in _HTTP_MODULES:
        return True
    # urllib.request.urlopen, etc.
    if "urllib" in name or "request" in name:
        return True
    return short in {"urlopen", "fetch"}


class _SSRFVisitor(ast.NodeVisitor):
    """Walk a module AST and collect SSRF risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SSRFFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            SSRFFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
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

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)

        if _is_http_call(name) and node.args:
            url_arg = node.args[0]
            if _is_dynamic_string(url_arg):
                self._add(
                    node,
                    "dynamic_url",
                    "high",
                    "HTTP request URL built from user input — validate against allowlist",
                )

        for kw in node.keywords:
            if kw.arg == "url" and _is_dynamic_string(kw.value):
                self._add(
                    node,
                    "dynamic_url_kwarg",
                    "high",
                    "HTTP request url= built from user input — restrict to trusted hosts",
                )

        self.generic_visit(node)


class SSRFAnalyzer:
    """Detect user-controlled outbound HTTP requests (SSRF risks).

    Flags ``requests.get()``, ``httpx`` calls, and ``urllib`` usage where
    the URL is built from request parameters or other untrusted input.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[SSRFFinding] = []
        self._stats: SSRFStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[SSRFFinding]:
        """Analyze the project and return SSRF findings."""
        if self._findings:
            return self._findings

        findings: list[SSRFFinding] = []
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
            visitor = _SSRFVisitor(rel)
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

        self._stats = SSRFStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> SSRFStats:
        """Return aggregate SSRF statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def by_pattern(self, pattern: str) -> list[SSRFFinding]:
        """Return findings for a specific pattern."""
        return [f for f in self.analyze() if f.pattern == pattern]

    def high_severity(self) -> list[SSRFFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no SSRF risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"SSRF: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing SSRF findings."""
        self.analyze()
        lines = [
            "SSRF analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No SSRF risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
