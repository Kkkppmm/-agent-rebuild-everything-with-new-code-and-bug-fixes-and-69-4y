"""InformationDisclosureAnalyzer — detect sensitive data exposure in logs and responses."""

from __future__ import annotations

import ast
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
        "private_key",
        "credential",
        "auth",
        "session_id",
        "ssn",
        "credit_card",
    }
)
_EXPOSURE_FUNCS = frozenset(
    {"print", "pprint", "traceback", "format_exc", "print_exc", "dump", "dumps"}
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


def _is_sensitive_name(name: str) -> bool:
    lower = name.lower()
    return any(s in lower for s in _SENSITIVE_NAMES)


def _contains_sensitive(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and _is_sensitive_name(node.id):
        return True
    if isinstance(node, ast.Attribute) and _is_sensitive_name(node.attr):
        return True
    if isinstance(node, ast.Subscript):
        return _contains_sensitive(node.value)
    if isinstance(node, ast.Call):
        return any(_contains_sensitive(a) for a in node.args)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _contains_sensitive(v.value) for v in node.values
        )
    return False


class _InfoDisclosureVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InformationDisclosureFinding] = []
        self._current_fn = "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._current_fn = node.name
        self.generic_visit(node)
        self._current_fn = "<module>"

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in _EXPOSURE_FUNCS:
            for arg in node.args:
                if _contains_sensitive(arg):
                    self.findings.append(
                        InformationDisclosureFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="sensitive_in_output",
                            severity="high",
                            message=f"Sensitive data passed to {name}()",
                            function=self._current_fn,
                        )
                    )
                    break

        if isinstance(func, ast.Attribute) and func.attr in {"jsonify", "send_file", "Response"}:
            for arg in node.args:
                if _contains_sensitive(arg):
                    self.findings.append(
                        InformationDisclosureFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="sensitive_in_response",
                            severity="high",
                            message="Sensitive data may be exposed in HTTP response",
                            function=self._current_fn,
                        )
                    )
                    break

        self.generic_visit(node)


class InformationDisclosureAnalyzer:
    """Detect logging or returning sensitive data like passwords and tokens."""

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
        penalty = high * 15.0
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
                lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
