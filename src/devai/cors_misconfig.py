"""CorsMisconfigAnalyzer — detect overly permissive CORS configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WILDCARD_ORIGIN_RE = re.compile(
    r"(?i)(allow_origins|origins|CORS_ORIGIN_ALLOW_ALL|Access-Control-Allow-Origin)"
    r".*(\*|True|\"\\*\"|'\\*'|\"\\*\"|'\\*')"
)
_CORS_SETTINGS = frozenset(
    {
        "CORS_ORIGIN_ALLOW_ALL",
        "CORS_ALLOW_ALL_ORIGINS",
        "CORS_ORIGINS",
        "CORS_ALLOWED_ORIGINS",
    }
)


@dataclass
class CorsMisconfigFinding:
    """A potentially unsafe CORS configuration."""

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
class CorsMisconfigStats:
    """Aggregate CORS misconfiguration analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_wildcard(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant):
        return value.value in ("*", True)
    if isinstance(value, ast.List) and any(_is_wildcard(elt) for elt in value.elts):
        return True
    if isinstance(value, ast.Tuple) and any(_is_wildcard(elt) for elt in value.elts):
        return True
    return False


def _classify_cors_call(node: ast.Call) -> tuple[str, str, str] | None:
    func = node.func
    name = ""
    if isinstance(func, ast.Name) and func.id == "CORS":
        name = "CORS"
    elif isinstance(func, ast.Attribute) and func.attr == "CORS":
        name = "CORS"
    if not name:
        return None

    for kw in node.keywords:
        if kw.arg in {"origins", "allow_origins"} and _is_wildcard(kw.value):
            return (
                "wildcard_origins",
                "high",
                "CORS allows all origins (*) — restrict to trusted domains",
            )
    for arg in node.args:
        if _is_wildcard(arg):
            return (
                "wildcard_origins",
                "high",
                "CORS allows all origins (*) — restrict to trusted domains",
            )
    return None


def _classify_cors_middleware(node: ast.Call) -> tuple[str, str, str] | None:
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == "add_middleware"):
        return None
    if not node.args:
        return None
    middleware = node.args[0]
    middleware_name = ""
    if isinstance(middleware, ast.Name):
        middleware_name = middleware.id
    elif isinstance(middleware, ast.Attribute):
        middleware_name = middleware.attr
    if middleware_name != "CORSMiddleware":
        return None

    for kw in node.keywords:
        if kw.arg == "allow_origins" and _is_wildcard(kw.value):
            return (
                "fastapi_wildcard",
                "high",
                "CORSMiddleware allow_origins=['*'] — use explicit origin list",
            )
    return None


def _classify_assignment(node: ast.Assign) -> tuple[str, str, str] | None:
    if len(node.targets) != 1:
        return None
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id not in _CORS_SETTINGS:
        return None
    if target.id in {"CORS_ORIGIN_ALLOW_ALL", "CORS_ALLOW_ALL_ORIGINS"}:
        if isinstance(node.value, ast.Constant) and node.value.value is True:
            return (
                "django_allow_all",
                "high",
                "CORS_ORIGIN_ALLOW_ALL=True permits any origin — disable in production",
            )
    if target.id in {"CORS_ORIGINS", "CORS_ALLOWED_ORIGINS"} and _is_wildcard(node.value):
        return (
            "django_wildcard",
            "high",
            "CORS allows wildcard origins — restrict to trusted domains",
        )
    return None


class _CorsVisitor(ast.NodeVisitor):
    """Walk a module AST and collect CORS misconfiguration patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CorsMisconfigFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, lineno: int, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            CorsMisconfigFinding(
                path=self.path,
                lineno=lineno,
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
        for classifier in (_classify_cors_call, _classify_cors_middleware):
            result = classifier(node)
            if result:
                pattern, severity, message = result
                self._add(node.lineno, pattern, severity, message)
                break
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        result = _classify_assignment(node)
        if result:
            pattern, severity, message = result
            self._add(node.lineno, pattern, severity, message)
        self.generic_visit(node)


class CorsMisconfigAnalyzer:
    """Detect overly permissive CORS configuration in web projects.

    Flags Flask-CORS ``origins='*'``, FastAPI ``allow_origins=['*']``,
    Django ``CORS_ORIGIN_ALLOW_ALL``, and wildcard origin headers.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[CorsMisconfigFinding] = []
        self._stats: CorsMisconfigStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix not in {".py", ".cfg", ".ini", ".env", ".yaml", ".yml"}

    def _scan_line(self, line: str, path: str, lineno: int) -> list[CorsMisconfigFinding]:
        if not _WILDCARD_ORIGIN_RE.search(line):
            return []
        if "example" in line.lower() or "placeholder" in line.lower():
            return []
        return [
            CorsMisconfigFinding(
                path=path,
                lineno=lineno,
                pattern="wildcard_header",
                severity="high",
                message="Wildcard CORS origin detected — restrict to trusted domains",
            )
        ]

    def analyze(self) -> list[CorsMisconfigFinding]:
        """Analyze the project and return CORS misconfiguration findings."""
        if self._findings:
            return self._findings

        findings: list[CorsMisconfigFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            rel = str(path.relative_to(self.root))
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            if path.suffix == ".py":
                try:
                    tree = ast.parse(source, filename=str(path))
                except SyntaxError:
                    continue
                visitor = _CorsVisitor(rel)
                visitor.visit(tree)
                if visitor.findings:
                    files_with_findings.add(rel)
                findings.extend(visitor.findings)
            else:
                for lineno, line in enumerate(source.splitlines(), start=1):
                    line_findings = self._scan_line(line, rel, lineno)
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

        self._stats = CorsMisconfigStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> CorsMisconfigStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[CorsMisconfigFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no CORS misconfigurations)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 30.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"CORS misconfigurations: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing CORS misconfiguration findings."""
        self.analyze()
        lines = [
            "CORS misconfiguration analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No CORS misconfiguration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
