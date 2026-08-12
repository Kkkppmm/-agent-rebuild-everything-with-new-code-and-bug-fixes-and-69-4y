"""InformationDisclosureAnalyzer — detect sensitive data exposure in responses and logs."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SENSITIVE_ATTRS = frozenset(
    {
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "private_key",
        "access_token",
        "refresh_token",
        "ssn",
        "credit_card",
    }
)
_EXPOSURE_PATTERNS = (
    re.compile(r"jsonify\s*\(\s*\{[^}]*password"),
    re.compile(r"return\s+\{[^}]*['\"]password['\"]"),
    re.compile(r"HttpResponse\s*\(\s*str\s*\(\s*e\s*\)"),
    re.compile(r"Response\s*\(\s*traceback"),
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


class _InformationDisclosureVisitor(ast.NodeVisitor):
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

    def visit_Dict(self, node: ast.Dict) -> None:
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value.lower() in _SENSITIVE_ATTRS or any(
                    s in key.value.lower() for s in _SENSITIVE_ATTRS
                ):
                    self.findings.append(
                        InformationDisclosureFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="sensitive_in_response",
                            severity="high",
                            message=f"Sensitive field '{key.value}' may be exposed in response",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"jsonify", "to_dict"}:
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    self.visit_Dict(arg)
        self.generic_visit(node)


class InformationDisclosureAnalyzer:
    """Detect sensitive data and error details exposed in HTTP responses."""

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
                            pattern="error_detail_exposure",
                            severity="medium",
                            message="Exception or traceback may be exposed to users",
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
            visitor = _InformationDisclosureVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            combined = visitor.findings + line_findings
            if combined:
                files_with_findings.add(rel)
            findings.extend(combined)

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
        penalty = high * 25.0 + medium * 10.0
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
            lines.append("No information disclosure risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
