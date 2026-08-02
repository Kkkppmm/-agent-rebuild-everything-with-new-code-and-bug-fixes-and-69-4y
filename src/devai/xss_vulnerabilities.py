"""XssVulnerabilityAnalyzer — detect cross-site scripting risks in web templates."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_MARK_SAFE_RE = re.compile(r"mark_safe\s*\(|Markup\s*\(|\.mark_safe\s*\(")
_SAFE_FILTER_RE = re.compile(r"\|\s*safe\b")
_AUTOESCAPE_FALSE_RE = re.compile(r"autoescape\s*=\s*False|autoescape\s+off", re.IGNORECASE)
_INNERHTML_RE = re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML", re.IGNORECASE)


@dataclass
class XssFinding:
    """A detected cross-site scripting risk."""

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
class XssStats:
    """Aggregate XSS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


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


class _XssVisitor(ast.NodeVisitor):
    """Walk a module AST and collect XSS risks."""

    def __init__(self, path: str, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.findings: list[XssFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, lineno: int, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            XssFinding(
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
        name = _call_name(node)
        short = name.split(".")[-1] if name else ""

        if short in {"mark_safe", "Markup"}:
            self._add(
                node.lineno,
                "mark_safe",
                "high",
                f"{short}() disables HTML escaping — sanitize user input first",
            )

        self.generic_visit(node)

    def scan_lines(self) -> None:
        """Scan source lines for regex-based XSS anti-patterns."""
        for lineno, line in enumerate(self.source_lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _SAFE_FILTER_RE.search(line):
                if not any(f.lineno == lineno for f in self.findings):
                    self._add(
                        lineno,
                        "safe_filter",
                        "high",
                        "|safe filter disables auto-escaping in templates",
                    )
            if _AUTOESCAPE_FALSE_RE.search(line):
                if not any(f.lineno == lineno for f in self.findings):
                    self._add(
                        lineno,
                        "autoescape_off",
                        "medium",
                        "autoescape=False disables template HTML escaping",
                    )
            if _INNERHTML_RE.search(line):
                if not any(f.lineno == lineno for f in self.findings):
                    self._add(
                        lineno,
                        "inner_html",
                        "high",
                        "Direct innerHTML assignment can lead to XSS",
                    )


class XssVulnerabilityAnalyzer:
    """Detect cross-site scripting risks in web applications.

    Flags ``mark_safe()``, ``|safe`` template filters, ``autoescape=False``,
    and direct innerHTML assignments.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[XssFinding] = []
        self._stats: XssStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix not in {".py", ".html", ".jinja", ".jinja2", ".htm"}

    def analyze(self) -> list[XssFinding]:
        """Analyze the project and return XSS findings."""
        if self._findings:
            return self._findings

        findings: list[XssFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                lines = source.splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))

            if path.suffix == ".py":
                try:
                    tree = ast.parse(source, filename=str(path))
                except SyntaxError:
                    continue
                visitor = _XssVisitor(rel, lines)
                visitor.visit(tree)
                visitor.scan_lines()
                if visitor.findings:
                    files_with_findings.add(rel)
                findings.extend(visitor.findings)
            else:
                file_findings: list[XssFinding] = []
                for lineno, line in enumerate(lines, start=1):
                    if _SAFE_FILTER_RE.search(line):
                        file_findings.append(
                            XssFinding(
                                path=rel,
                                lineno=lineno,
                                pattern="safe_filter",
                                severity="high",
                                message="|safe filter disables auto-escaping in templates",
                            )
                        )
                    if _AUTOESCAPE_FALSE_RE.search(line):
                        file_findings.append(
                            XssFinding(
                                path=rel,
                                lineno=lineno,
                                pattern="autoescape_off",
                                severity="medium",
                                message="autoescape disabled in template",
                            )
                        )
                if file_findings:
                    files_with_findings.add(rel)
                findings.extend(file_findings)

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

        self._stats = XssStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> XssStats:
        """Return aggregate XSS statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[XssFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no XSS risks)."""
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
            f"XSS: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing XSS findings."""
        self.analyze()
        lines = [
            "XSS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No XSS risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
