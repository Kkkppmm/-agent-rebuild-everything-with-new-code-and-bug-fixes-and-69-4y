"""TemplateAutoescapeAnalyzer — detect Jinja2 environments without autoescape."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS


@dataclass
class TemplateAutoescapeFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    class_name: str = ""

    def format(self) -> str:
        cls = f" ({self.class_name})" if self.class_name else ""
        return f"{self.path}:{self.lineno}{cls} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class TemplateAutoescapeStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_environment_call(node: ast.Call) -> tuple[str, bool] | None:
    """Return (class_name, autoescape_disabled) if this is a Jinja2 Environment call."""
    func = node.func
    class_name = ""
    if isinstance(func, ast.Name) and func.id == "Environment":
        class_name = "Environment"
    elif isinstance(func, ast.Attribute) and func.attr == "Environment":
        if isinstance(func.value, ast.Name):
            class_name = f"{func.value.id}.Environment"
        else:
            class_name = "Environment"
    else:
        return None

    autoescape_kw = None
    for kw in node.keywords:
        if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant):
            autoescape_kw = kw.value.value

    if autoescape_kw is False:
        return class_name, True
    if autoescape_kw is None:
        return class_name, False
    return None


class _TemplateAutoescapeVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[TemplateAutoescapeFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        result = _is_environment_call(node)
        if result:
            class_name, disabled = result
            if disabled:
                self.findings.append(
                    TemplateAutoescapeFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="autoescape_disabled",
                        severity="high",
                        message="Jinja2 Environment with autoescape=False enables XSS via templates",
                        class_name=class_name,
                    )
                )
            else:
                self.findings.append(
                    TemplateAutoescapeFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="autoescape_missing",
                        severity="medium",
                        message="Jinja2 Environment without autoescape may allow XSS — set autoescape=True",
                        class_name=class_name,
                    )
                )
        self.generic_visit(node)


class TemplateAutoescapeAnalyzer:
    """Detect Jinja2 Environment instances missing or disabling autoescape."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[TemplateAutoescapeFinding] = []
        self._stats: TemplateAutoescapeStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[TemplateAutoescapeFinding]:
        if self._findings:
            return self._findings

        findings: list[TemplateAutoescapeFinding] = []
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
            visitor = _TemplateAutoescapeVisitor(rel)
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = TemplateAutoescapeStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> TemplateAutoescapeStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Template autoescape risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Template autoescape analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No Jinja2 autoescape issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
