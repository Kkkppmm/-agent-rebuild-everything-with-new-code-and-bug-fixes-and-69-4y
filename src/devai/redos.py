"""ReDoSAnalyzer — detect regex patterns vulnerable to catastrophic backtracking."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# Nested quantifiers and overlapping alternation patterns that often cause ReDoS.
_REDOS_PATTERNS = [
    re.compile(r"\([^)]*[+*][^)]*\)[+*?]"),  # (a+)+ style
    re.compile(r"\(\.\*\)[+*]"),  # (.*)+ or (.*)*
    re.compile(r"\(\.\+\)[+*]"),  # (.+)+ or (.+)*
    re.compile(r"\([^|)]+\|[^)]+\)[+*]"),  # (a|aa)+ style
    re.compile(r"\[[^\]]*[+*][^\]]*\][+*]"),  # nested char-class quantifiers
]

_RE_MODULE_CALLS = frozenset(
    {
        "compile",
        "search",
        "match",
        "fullmatch",
        "findall",
        "finditer",
        "sub",
        "split",
    }
)


@dataclass
class ReDoSFinding:
    """A potentially catastrophic-backtracking regex pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    context: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        ctx = f" ({self.context})" if self.context else ""
        preview = self.pattern[:60] + ("..." if len(self.pattern) > 60 else "")
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {preview}{ctx}: "
            f"{self.message}"
        )


@dataclass
class ReDoSStats:
    """Aggregate ReDoS analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_redos_pattern(pattern: str) -> bool:
    return any(rx.search(pattern) for rx in _REDOS_PATTERNS)


def _extract_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _ReDoSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect risky regex patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ReDoSFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        context: str = "",
    ) -> None:
        self.findings.append(
            ReDoSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        call_name = ""
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "re" and func.attr in _RE_MODULE_CALLS:
                call_name = f"re.{func.attr}"
        elif isinstance(func, ast.Name) and func.id == "compile":
            call_name = "compile"

        if call_name and node.args:
            pattern = _extract_string(node.args[0])
            if pattern and _is_redos_pattern(pattern):
                self._add(
                    node,
                    pattern,
                    severity="high",
                    message="Nested quantifiers may cause catastrophic backtracking (ReDoS)",
                    context=call_name,
                )

        if isinstance(func, ast.Attribute) and func.attr == "compile":
            if isinstance(func.value, ast.Name) and func.value.id == "re" and node.args:
                pattern = _extract_string(node.args[0])
                if pattern and _is_redos_pattern(pattern):
                    self._add(
                        node,
                        pattern,
                        severity="high",
                        message="Nested quantifiers may cause catastrophic backtracking (ReDoS)",
                        context="re.compile",
                    )

        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regex patterns that may cause catastrophic backtracking.

    Flags nested quantifiers like ``(a+)+`` and ``(.*)*`` in ``re.compile``,
    ``re.search``, and related calls.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[ReDoSFinding] = []
        self._stats: ReDoSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[ReDoSFinding]:
        """Analyze the project and return ReDoS findings."""
        if self._findings:
            return self._findings

        findings: list[ReDoSFinding] = []
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
            visitor = _ReDoSVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = ReDoSStats(
            total_findings=len(findings),
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ReDoSStats:
        """Return aggregate ReDoS statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[ReDoSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no ReDoS patterns)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 20.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"ReDoS patterns: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing ReDoS findings."""
        self.analyze()
        lines = [
            "ReDoS pattern analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No catastrophic-backtracking regex patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
