"""InformationDisclosureAnalyzer — detect sensitive data exposure in responses."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_EXPOSURE_PATTERNS = (
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"sys\.exc_info\s*\("),
    re.compile(r"pprint\.pprint\s*\("),
    re.compile(r"__dict__"),
)
_SENSITIVE_ATTRS = frozenset(
    {"password", "secret", "token", "api_key", "private_key", "credentials", "ssn"}
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


class _InfoDisclosureVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
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

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            if isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Attribute) and func.attr in {"format_exc", "exc_info"}:
                    self.findings.append(
                        InformationDisclosureFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="exception_in_response",
                            severity="high",
                            message="Returning exception details may leak internal information",
                            function=self._current_function(),
                        )
                    )
            if isinstance(node.value, ast.JoinedStr):
                for val in node.value.values:
                    if isinstance(val, ast.FormattedValue):
                        if isinstance(val.value, ast.Name) and val.value.id in {"e", "exc", "error"}:
                            self.findings.append(
                                InformationDisclosureFinding(
                                    path=self.path,
                                    lineno=node.lineno,
                                    pattern="error_in_response",
                                    severity="medium",
                                    message="Exception message in f-string response may leak internals",
                                    function=self._current_function(),
                                )
                            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "jsonify" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Dict):
                    for key, val in zip(arg.keys, arg.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            if key.value in {"error", "exception", "traceback", "stack"}:
                                self.findings.append(
                                    InformationDisclosureFinding(
                                        path=self.path,
                                        lineno=node.lineno,
                                        pattern="error_json_response",
                                        severity="medium",
                                        message=f"jsonify with '{key.value}' key may expose internal errors",
                                        function=self._current_function(),
                                    )
                                )
            if func.attr in {"__dict__", "vars"}:
                self.findings.append(
                    InformationDisclosureFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="object_dump",
                        severity="medium",
                        message="Dumping object __dict__ may expose sensitive attributes",
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class InformationDisclosureAnalyzer:
    """Detect information disclosure risks in application responses."""

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

    def _scan_line_patterns(self, rel: str, source: str) -> list[InformationDisclosureFinding]:
        findings: list[InformationDisclosureFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _EXPOSURE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        InformationDisclosureFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="traceback_exposure",
                            severity="high",
                            message="Traceback or debug output may be exposed to users",
                        )
                    )
                    break
            for attr in _SENSITIVE_ATTRS:
                if f".{attr}" in line and "return" in line:
                    findings.append(
                        InformationDisclosureFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="sensitive_attr_exposure",
                            severity="high",
                            message=f"Sensitive attribute '{attr}' may be returned in response",
                        )
                    )
                    break
        return findings

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
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _InfoDisclosureVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            all_findings = visitor.findings + line_findings
            if all_findings:
                files_with_findings.add(rel)
            findings.extend(all_findings)

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
