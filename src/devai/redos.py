"""ReDoSAnalyzer — detect regex patterns vulnerable to catastrophic backtracking."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

# Patterns known to cause catastrophic backtracking
_REDOS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\(\.\*\)\+"), "nested_quantifier", "Nested quantifiers like (.*)+ cause exponential backtracking"),
    (re.compile(r"\(\.\+\)\+"), "nested_quantifier", "Nested quantifiers like (.+)+ cause exponential backtracking"),
    (re.compile(r"\([^)]*\+[^)]*\)\+"), "nested_quantifier", "Nested + quantifiers cause catastrophic backtracking"),
    (re.compile(r"\([^)]*\*[^)]*\)\*"), "nested_quantifier", "Nested * quantifiers cause catastrophic backtracking"),
    (re.compile(r"\([^)]*\{[^}]*\}[^)]*\)\{"), "nested_quantifier", "Nested bounded quantifiers can cause ReDoS"),
    (re.compile(r"\(\?:[^)]*\)\+[^)]*\)\+"), "nested_group_quantifier", "Nested group quantifiers cause ReDoS"),
    (re.compile(r"\(\[?\^?[^\]]*\]\+\)\+"), "char_class_quantifier", "Quantified character classes with nested + cause ReDoS"),
    (re.compile(r"\.\*\.\*"), "overlapping_wildcards", "Overlapping .* wildcards cause polynomial backtracking"),
    (re.compile(r"\(\.\*\)\{2,\}"), "repeated_wildcard", "Repeated wildcard groups cause exponential backtracking"),
]


@dataclass
class ReDoSFinding:
    """A regex pattern potentially vulnerable to ReDoS."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    regex: str = ""
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        regex_hint = f" regex={self.regex!r}" if self.regex else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}:{regex_hint} {self.message}"


@dataclass
class ReDoSStats:
    """Aggregate ReDoS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _extract_regex_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _check_regex_pattern(regex_str: str) -> list[tuple[str, str, str]]:
    """Return list of (pattern_name, severity, message) for risky regex."""
    findings: list[tuple[str, str, str]] = []
    for compiled, pattern_name, message in _REDOS_PATTERNS:
        if compiled.search(regex_str):
            severity = "high" if "exponential" in message else "medium"
            findings.append((pattern_name, severity, message))
    return findings


class _ReDoSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect ReDoS risks."""

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

    def _check_call(self, node: ast.Call) -> None:
        func = node.func
        is_re_call = False
        if isinstance(func, ast.Attribute) and func.attr in {"compile", "match", "search", "findall", "sub", "split"}:
            module = ""
            if isinstance(func.value, ast.Name):
                module = func.value.id
            if module in {"re", ""} or func.attr == "compile":
                is_re_call = True
        elif isinstance(func, ast.Name) and func.id == "compile":
            is_re_call = True

        if not is_re_call or not node.args:
            return

        regex_str = _extract_regex_string(node.args[0])
        if not regex_str:
            return

        for pattern_name, severity, message in _check_regex_pattern(regex_str):
            self.findings.append(
                ReDoSFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern_name,
                    severity=severity,
                    message=message,
                    regex=regex_str[:60],
                    function=self._current_function(),
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regex patterns vulnerable to Regular Expression Denial of Service.

    Flags nested quantifiers, overlapping wildcards, and other patterns
    that can cause catastrophic backtracking on crafted input.
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

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no ReDoS risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"ReDoS: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing ReDoS findings."""
        self.analyze()
        lines = [
            "ReDoS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No ReDoS vulnerability patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
