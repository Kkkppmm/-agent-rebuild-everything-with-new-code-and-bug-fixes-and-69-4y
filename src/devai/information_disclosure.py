"""InformationDisclosureAnalyzer — detect sensitive data exposure in responses and logs."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_NAMES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "auth",
        "authorization",
        "ssn",
        "credit_card",
    }
)
_RESPONSE_ATTRS = frozenset({"json", "jsonify", "Response", "make_response", "send", "render"})
_ENV_PATTERNS = (
    re.compile(r"os\.environ\s*\["),
    re.compile(r"os\.getenv\s*\("),
    re.compile(r"environ\.get\s*\("),
)


@dataclass
class InformationDisclosureFinding:
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
class InformationDisclosureStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _name_is_sensitive(name: str) -> bool:
    lower = name.lower()
    return any(s in lower for s in _SENSITIVE_NAMES)


class _InformationDisclosureVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.findings: list[InformationDisclosureFinding] = []
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
        if isinstance(func, ast.Attribute):
            if func.attr in {"format_exc", "print_exc"}:
                self._add(
                    node.lineno,
                    "traceback_in_response",
                    "Exposing traceback in responses leaks internal paths and code",
                    "high",
                )
            if func.attr == "jsonify" or (func.attr == "json" and isinstance(func.value, ast.Name)):
                for arg in node.args:
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                        if arg.func.id in {"vars", "locals", "dir"}:
                            self._add(
                                node.lineno,
                                "introspection_in_json",
                                "Returning introspection data in JSON responses leaks internals",
                                "high",
                            )
            if func.attr in {"error", "exception", "abort"}:
                for arg in node.args:
                    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                        if arg.func.id in {"str", "repr"} and len(arg.args) == 1:
                            inner = arg.args[0]
                            if isinstance(inner, ast.Name) and inner.id in {"e", "exc", "error", "err"}:
                                self._add(
                                    node.lineno,
                                    "exception_string_response",
                                    "Returning raw exception text may disclose stack details",
                                    "medium",
                                )
        if isinstance(func, ast.Attribute) and func.attr in {"info", "debug", "warning", "error"}:
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    for val in arg.values:
                        if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                            if _name_is_sensitive(val.value.id):
                                self._add(
                                    node.lineno,
                                    "sensitive_data_logged",
                                    f"Logging sensitive variable '{val.value.id}' may expose secrets",
                                    "high",
                                )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value and isinstance(node.value, ast.Dict):
            for key in node.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if _name_is_sensitive(key.value):
                        self._add(
                            node.lineno,
                            "sensitive_field_in_response",
                            f"Response dict includes sensitive field '{key.value}'",
                            "medium",
                        )
        self.generic_visit(node)

    def _add(self, lineno: int, pattern: str, message: str, severity: str) -> None:
        self.findings.append(
            InformationDisclosureFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )


class InformationDisclosureAnalyzer:
    """Detect information disclosure via responses, logs, and error handling."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InformationDisclosureFinding] = []
        self._stats: InformationDisclosureStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, lines: list[str], findings: list[InformationDisclosureFinding]) -> None:
        for lineno, line in enumerate(lines, start=1):
            for pattern in _ENV_PATTERNS:
                if pattern.search(line) and any(tok in line for tok in ("return", "json", "Response", "render")):
                    findings.append(
                        InformationDisclosureFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="env_in_response",
                            severity="high",
                            message="Environment variables referenced near response construction may leak secrets",
                        )
                    )
                    break

    def analyze(self) -> list[InformationDisclosureFinding]:
        if self._findings:
            return self._findings

        findings: list[InformationDisclosureFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                lines = source.splitlines()
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _InformationDisclosureVisitor(rel, lines)
            visitor.visit(tree)
            self._scan_line_patterns(rel, lines, visitor.findings)
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
        self._stats = InformationDisclosureStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InformationDisclosureStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 15.0 + medium * 8.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Information disclosure risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Information disclosure analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No information disclosure patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
