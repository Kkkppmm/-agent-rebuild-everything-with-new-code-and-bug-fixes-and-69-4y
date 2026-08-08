"""ReDoSAnalyzer — detect catastrophic backtracking regex patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# Patterns known to cause catastrophic backtracking
_REDOS_PATTERNS = [
    re.compile(r"\(\.\*\)\+"),
    re.compile(r"\(\.\+\)\+"),
    re.compile(r"\(\.\*\)\*"),
    re.compile(r"\(\.\+\)\*"),
    re.compile(r"\(\[.*?\]\+\)\+"),
    re.compile(r"\(\w\+\)\+"),
    re.compile(r"\(\w\*\)\+"),
    re.compile(r"\(\.\{0,\}\)\+"),
]


@dataclass
class ReDoSFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    regex: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        regex_hint = f" ({self.regex!r})" if self.regex else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{regex_hint}: {self.message}"


@dataclass
class ReDoSStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _check_regex_string(pattern: str) -> tuple[str, str, str] | None:
    for redos_pat in _REDOS_PATTERNS:
        if redos_pat.search(pattern):
            return (
                "nested_quantifier",
                "medium",
                "Regex has nested quantifiers that may cause catastrophic backtracking",
            )
    if len(pattern) > 200:
        return ("long_pattern", "low", "Very long regex — review for ReDoS risk")
    return None


def _extract_regex(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _ReDoSVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[ReDoSFinding] = []
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
        is_regex_call = False
        if isinstance(func, ast.Attribute) and func.attr in {"compile", "match", "search", "findall", "sub"}:
            is_regex_call = True
        if isinstance(func, ast.Name) and func.id == "re":
            is_regex_call = True

        if is_regex_call and node.args:
            pattern_str = _extract_regex(node.args[0])
            if pattern_str:
                result = _check_regex_string(pattern_str)
                if result:
                    pat, severity, message = result
                    self.findings.append(
                        ReDoSFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern=pat,
                            severity=severity,
                            message=message,
                            function=self._current_function(),
                            regex=pattern_str[:60],
                        )
                    )
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regex patterns vulnerable to catastrophic backtracking (ReDoS)."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
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
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = ReDoSStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> ReDoSStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = medium * 10.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"ReDoS risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["ReDoS analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No ReDoS-vulnerable regex patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
