"""CorsMisconfigAnalyzer — detect overly permissive CORS configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_WILDCARD_ORIGIN_RE = re.compile(
    r"(origins|allow_origin|allowed_origins|cors_origins|CORS_ORIGINS)\s*[=:]\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
_ALLOW_ALL_ORIGINS_RE = re.compile(r"Access-Control-Allow-Origin\s*:\s*\*", re.IGNORECASE)


@dataclass
class CorsMisconfigFinding:
    """A detected CORS misconfiguration."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class CorsMisconfigStats:
    """Aggregate CORS misconfiguration analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_wildcard(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, ast.List) and len(node.elts) == 1:
        return isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "*"
    return False


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


_CORS_KEYWORDS = frozenset(
    {"origins", "allow_origin", "allowed_origins", "cors_origins", "resources"}
)


class _CorsVisitor(ast.NodeVisitor):
    """Walk a module AST and collect CORS misconfigurations."""

    def __init__(self, path: str, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.findings: list[CorsMisconfigFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        severity: str,
        message: str,
        call: str = "",
        lineno: int | None = None,
    ) -> None:
        self.findings.append(
            CorsMisconfigFinding(
                path=self.path,
                lineno=lineno or getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
                call=call,
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
        for target in node.targets:
            if isinstance(target, ast.Name):
                if any(kw in target.id.lower() for kw in ("cors", "origin")):
                    if _is_wildcard(node.value):
                        self._add(
                            node,
                            "wildcard_cors_origin",
                            "high",
                            f"CORS origin set to wildcard (*) in {target.id}",
                        )
            if isinstance(target, ast.Attribute) and target.attr in _CORS_KEYWORDS:
                if _is_wildcard(node.value):
                    self._add(
                        node,
                        "wildcard_cors_origin",
                        "high",
                        f"CORS {target.attr} set to wildcard (*)",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if "cors" in name.lower():
            for kw in node.keywords:
                if kw.arg in _CORS_KEYWORDS and _is_wildcard(kw.value):
                    self._add(
                        node,
                        "wildcard_cors_config",
                        "high",
                        f"CORS {kw.arg}='*' allows any origin — use an allowlist",
                        call=name,
                    )
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        for i, line in enumerate(self.source_lines, start=1):
            if _WILDCARD_ORIGIN_RE.search(line) or _ALLOW_ALL_ORIGINS_RE.search(line):
                self._add(
                    node,
                    "wildcard_cors_origin",
                    "high",
                    "Wildcard CORS origin allows any domain to access resources",
                    lineno=i,
                )
        self.generic_visit(node)


class CorsMisconfigAnalyzer:
    """Detect overly permissive CORS configuration in web applications.

    Flags wildcard origins (*), Access-Control-Allow-Origin: *, and
    Flask-CORS / django-cors-headers configurations that allow all origins.
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
        return path.suffix != ".py"

    def analyze(self) -> list[CorsMisconfigFinding]:
        """Analyze the project and return CORS misconfiguration findings."""
        if self._findings:
            return self._findings

        findings: list[CorsMisconfigFinding] = []
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
            source_lines = source.splitlines()
            visitor = _CorsVisitor(rel, source_lines)
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
        """Build LLM-ready context describing CORS misconfigurations."""
        self.analyze()
        lines = [
            "CORS misconfiguration analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No wildcard CORS origins found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
