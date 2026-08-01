"""CORSMisconfigAnalyzer — detect permissive CORS configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_CORS_HEADER_RE = re.compile(
    r"access-control-allow-origin",
    re.IGNORECASE,
)
_WILDCARD_RE = re.compile(r'["\']?\*["\']?')


@dataclass
class CORSMisconfigFinding:
    """A detected permissive CORS configuration."""

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
class CORSMisconfigStats:
    """Aggregate CORS misconfiguration statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_wildcard(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List):
        return any(_is_wildcard(elt) for elt in node.elts)
    if isinstance(node, ast.Tuple):
        return any(_is_wildcard(elt) for elt in node.elts)
    return False


def _has_credentials_true(keywords: list[ast.keyword]) -> bool:
    for kw in keywords:
        if kw.arg in {"allow_credentials", "supports_credentials"}:
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
    return False


def _is_cors_middleware_call(node: ast.Call) -> bool:
    name = ""
    func = node.func
    if isinstance(func, ast.Name):
        name = func.id
    elif isinstance(func, ast.Attribute):
        name = func.attr
    return name in {"CORSMiddleware", "CORS"}


def _cors_config_from_call(node: ast.Call) -> tuple[ast.Call | None, list[ast.keyword]]:
    """Extract CORS middleware call and its keyword args from direct or add_middleware usage."""
    if _is_cors_middleware_call(node):
        return node, list(node.keywords)

    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "add_middleware":
        if node.args and isinstance(node.args[0], ast.Name):
            if node.args[0].id in {"CORSMiddleware", "CORS"}:
                return node, list(node.keywords)
    return None, []


class _CORSMisconfigVisitor(ast.NodeVisitor):
    """Walk a module AST and collect CORS misconfigurations."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[CORSMisconfigFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            CORSMisconfigFinding(
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
        cors_call, keywords = _cors_config_from_call(node)
        if cors_call is not None:
            for kw in keywords:
                if kw.arg in {"allow_origins", "origins"} and _is_wildcard(kw.value):
                    severity = "high" if _has_credentials_true(keywords) else "medium"
                    message = (
                        "Wildcard CORS origin with credentials enabled — any site can make authenticated requests"
                        if severity == "high"
                        else "Wildcard CORS origin allows any site to read responses"
                    )
                    self._add(
                        node,
                        pattern="wildcard_origin",
                        severity=severity,
                        message=message,
                    )
                elif kw.arg == "origins" and isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                    self._add(
                        node,
                        pattern="wildcard_origin",
                        severity="medium",
                        message="Wildcard CORS origin allows any site to read responses",
                    )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and node.value.value == "*":
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    key = target.slice
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if _CORS_HEADER_RE.search(key.value):
                            self._add(
                                node,
                                pattern="wildcard_header",
                                severity="medium",
                                message="Access-Control-Allow-Origin set to * — restrict to trusted origins",
                            )
        self.generic_visit(node)


class CORSMisconfigAnalyzer:
    """Detect permissive CORS configuration in web applications.

    Flags wildcard ``Access-Control-Allow-Origin`` headers and
    ``allow_origins=["*"]`` in CORS middleware with optional credentials.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[CORSMisconfigFinding] = []
        self._stats: CORSMisconfigStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[CORSMisconfigFinding]:
        """Analyze the project and return CORS misconfiguration findings."""
        if self._findings:
            return self._findings

        findings: list[CORSMisconfigFinding] = []
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
            visitor = _CORSMisconfigVisitor(rel)
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

        self._stats = CORSMisconfigStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> CORSMisconfigStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[CORSMisconfigFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no CORS misconfigurations)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
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
            lines.append("No permissive CORS configuration found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
