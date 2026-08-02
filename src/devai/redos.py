"""ReDoSAnalyzer — detect regular expression denial-of-service patterns."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_RE_FUNCS = frozenset(
    {"compile", "search", "match", "fullmatch", "sub", "subn", "findall", "finditer", "split"}
)
_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.args",
        "request.form",
        "request.values",
        "request.GET",
        "request.POST",
        "request.query_params",
        "request.path_params",
        "request.data",
        "request.json",
    }
)
_KNOWN_BAD_PATTERNS = (
    "(.+)+",
    "(.*)+",
    "(.+)*",
    "(.*)*",
    "(\\w+)+",
    "(\\d+)+",
    "(?:.+)+",
    "(?:.*)+",
)


@dataclass
class ReDoSFinding:
    """A potentially catastrophic backtracking regex pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    regex_preview: str = ""
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        preview = f" — `{self.regex_preview}`" if self.regex_preview else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}{preview}"


@dataclass
class ReDoSStats:
    """Aggregate ReDoS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _inner_has_quantifier(text: str) -> bool:
    """Return True if text contains an unescaped regex quantifier."""
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] in "+*?{":
            return True
        i += 1
    return False


def _has_nested_quantifiers(pattern: str) -> bool:
    """Detect nested quantifiers that can cause catastrophic backtracking."""
    for bad in _KNOWN_BAD_PATTERNS:
        if bad in pattern:
            return True

    depth = 0
    group_start = 0
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "(":
            depth += 1
            group_start = i
        elif ch == ")":
            if depth > 0:
                inner = pattern[group_start + 1 : i]
                if _inner_has_quantifier(inner):
                    j = i + 1
                    while j < len(pattern) and pattern[j] in " \t":
                        j += 1
                    if j < len(pattern) and pattern[j] in "+*?{":
                        return True
            depth = max(0, depth - 1)
        i += 1
    return False


def _extract_string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_re_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _RE_FUNCS:
        base = func.value
        if isinstance(base, ast.Name) and base.id == "re":
            return True
        if isinstance(base, ast.Attribute) and base.attr == "re":
            return True
    return False


def _is_request_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base and node.attr in {
            "args",
            "form",
            "values",
            "GET",
            "POST",
            "query_params",
            "path_params",
            "data",
            "json",
        }:
            return True
    if isinstance(node, ast.Subscript):
        return _is_request_access(node.value)
    return _request_source(node) == "request"


def _request_source(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id == "request":
        return "request"
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_user_controlled(node: ast.AST) -> bool:
    if _is_request_access(node):
        return True
    if isinstance(node, ast.Subscript) and _is_request_access(node.value):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "pop", "getlist"} and _is_request_access(func.value):
                return True
    if isinstance(node, ast.Name):
        return node.id in {"pattern", "regex", "rule", "expression", "user_input", "user_pattern"}
    return False


def _preview_pattern(pattern: str, max_len: int = 60) -> str:
    if len(pattern) <= max_len:
        return pattern
    return pattern[: max_len - 3] + "..."


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
        if _is_re_call(node) and node.args:
            pattern_arg = node.args[0]
            literal = _extract_string_literal(pattern_arg)
            if literal and _has_nested_quantifiers(literal):
                self.findings.append(
                    ReDoSFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="nested_quantifier",
                        severity="high",
                        message="Regex has nested quantifiers that may cause catastrophic backtracking",
                        regex_preview=_preview_pattern(literal),
                        function=self._current_function(),
                    )
                )
            elif _is_user_controlled(pattern_arg):
                self.findings.append(
                    ReDoSFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="user_controlled_regex",
                        severity="high",
                        message="Regex pattern built from user input — validate or sandbox patterns",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        literal = _extract_string_literal(node.value)
        if literal and _has_nested_quantifiers(literal):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.findings.append(
                        ReDoSFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="risky_pattern_literal",
                            severity="medium",
                            message=f"Variable `{target.id}` holds a regex with nested quantifiers",
                            regex_preview=_preview_pattern(literal),
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class ReDoSAnalyzer:
    """Detect regex patterns vulnerable to ReDoS (regular expression denial of service).

    Flags nested quantifiers like ``(.+)+`` and user-controlled patterns passed to
    ``re.compile``, ``re.search``, and related functions.
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
            lines.append("No catastrophic backtracking regex patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
