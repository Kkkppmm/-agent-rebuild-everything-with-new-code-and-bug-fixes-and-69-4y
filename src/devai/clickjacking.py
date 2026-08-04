"""ClickjackingAnalyzer — detect missing clickjacking protections."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_FRAME_OPTIONS = re.compile(r"X-Frame-Options|x-frame-options", re.IGNORECASE)
_CSP_FRAME = re.compile(r"frame-ancestors|Content-Security-Policy", re.IGNORECASE)
_FRAME_DENY_VALUES = frozenset({"DENY", "SAMEORIGIN", "deny", "sameorigin"})


@dataclass
class ClickjackingFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class ClickjackingStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


class _ClickjackingVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ClickjackingFinding] = []
        self._has_frame_options = False
        self._has_csp_frame = False
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
        if isinstance(func, ast.Attribute) and func.attr in {"set_header", "add_header", "header"}:
            if node.args and isinstance(node.args[0], ast.Constant):
                header_name = str(node.args[0].value).lower()
                if "x-frame-options" in header_name:
                    self._has_frame_options = True
                if "content-security-policy" in header_name and len(node.args) > 1:
                    if isinstance(node.args[1], ast.Constant) and "frame-ancestors" in str(node.args[1].value):
                        self._has_csp_frame = True
        self.generic_visit(node)

    def finalize(self) -> None:
        if not self._has_frame_options and not self._has_csp_frame:
            self.findings.append(
                ClickjackingFinding(
                    path=self.path,
                    lineno=1,
                    pattern="missing_frame_protection",
                    severity="medium",
                    message="No X-Frame-Options or CSP frame-ancestors header detected",
                )
            )


class ClickjackingAnalyzer:
    """Detect missing clickjacking protection headers in web applications."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ClickjackingFinding] = []
        self._stats: ClickjackingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _is_web_app_file(self, path: Path, source: str) -> bool:
        web_indicators = ("flask", "django", "fastapi", "starlette", "tornado", "aiohttp", "bottle")
        return any(ind in source for ind in web_indicators)

    def analyze(self) -> list[ClickjackingFinding]:
        if self._findings:
            return self._findings

        findings: list[ClickjackingFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()
        project_has_frame_protection = False

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            if not self._is_web_app_file(path, source):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))

            if _FRAME_OPTIONS.search(source) or _CSP_FRAME.search(source):
                project_has_frame_protection = True

            visitor = _ClickjackingVisitor(rel)
            visitor.visit(tree)
            if visitor._has_frame_options or visitor._has_csp_frame:
                project_has_frame_protection = True

        if files_scanned > 0 and not project_has_frame_protection:
            findings.append(
                ClickjackingFinding(
                    path="(project)",
                    lineno=0,
                    pattern="missing_frame_protection",
                    severity="medium",
                    message="Web app detected without X-Frame-Options or CSP frame-ancestors protection",
                )
            )
            files_with_findings.add("(project)")

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / max(files_scanned, 1), 1)
        self._stats = ClickjackingStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ClickjackingStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        if self._findings:
            return round(max(0.0, 100.0 - len(self._findings) * 20.0), 1)
        return 100.0

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Clickjacking risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} web files scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Clickjacking analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No clickjacking risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
