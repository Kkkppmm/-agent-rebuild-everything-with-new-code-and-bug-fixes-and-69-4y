"""ReDoSAnalyzer — detect regular expression denial-of-service risks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_NESTED_QUANTIFIER_RE = re.compile(
    r"""(?:\([^)]*[+*]\)[+*?{]|[+*]\)[+*?{]|\([^)]*\|[^)]*\)[+*])"""
)
_CATASTROPHIC_PATTERNS = (
  r"(a+)+",
  r"(a|a)+",
  r"(.*a){10,}",
  r"(\w+\s*)+",
)
_RE_MODULE_NAMES = frozenset({"re", "regex"})


@dataclass
class ReDoSFinding:
    """A potentially vulnerable regular expression pattern."""

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
        preview = f" ({self.regex[:50]}...)" if len(self.regex) > 50 else (f" ({self.regex})" if self.regex else "")
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}{preview}"


@dataclass
class ReDoSStats:
    """Aggregate ReDoS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in {"user_input", "text", "data", "value", "pattern", "input", "query", "content"}
    if isinstance(node, ast.Attribute):
        attr = node.attr.lower()
        return attr in {"text", "data", "value", "input", "content", "body", "query", "pattern"}
    return False


def _regex_pattern_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_nested_quantifier(pattern: str) -> bool:
    if _NESTED_QUANTIFIER_RE.search(pattern):
        return True
    for catastrophic in _CATASTROPHIC_PATTERNS:
        if catastrophic in pattern:
            return True
    return False


def _is_re_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute):
        base = func.value
        if isinstance(base, ast.Name) and base.id in _RE_MODULE_NAMES:
            return func.attr in {"match", "search", "fullmatch", "findall", "finditer", "sub", "split", "compile"}
    if isinstance(func, ast.Name) and func.id == "compile":
        return True
    return False


def _classify_regex_call(call: ast.Call) -> tuple[str, str, str, str] | None:
    if not _is_re_call(call):
        return None

    pattern_node = call.args[0] if call.args else None
    if pattern_node is None:
        return None

    if _looks_like_user_input(pattern_node):
        regex = _regex_pattern_value(pattern_node) or "<dynamic>"
        return (
            "dynamic_regex",
            "high",
            "Regex built from user input — validate and limit pattern complexity",
            regex,
        )

    regex = _regex_pattern_value(pattern_node)
    if regex and _has_nested_quantifier(regex):
        return (
            "nested_quantifier",
            "medium",
            "Regex has nested quantifiers that may cause catastrophic backtracking",
            regex,
        )

    return None


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

    def visit_Call(self, node: ast.Call) -> None:
        result = _classify_regex_call(node)
        if result:
            pattern, severity, message, regex = result
            self.findings.append(
                ReDoSFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    regex=regex,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regular expression denial-of-service (ReDoS) risks.

    Flags nested quantifiers, catastrophic backtracking patterns, and
  regex operations that use user-controlled input as the pattern.
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

    def high_severity(self) -> list[ReDoSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no ReDoS risks)."""
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
            f"ReDoS risks: {stats.total_findings} findings in "
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
            lines.append("No ReDoS patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
