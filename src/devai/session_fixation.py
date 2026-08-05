"""SessionFixationAnalyzer — detect session fixation vulnerabilities on authentication."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_LOGIN_NAMES = frozenset({"login", "signin", "sign_in", "authenticate", "auth"})
_SESSION_ATTRS = frozenset({"session", "session_id", "sid", "jsessionid"})
_REGENERATE_ATTRS = frozenset({"regenerate", "cycle_key", "flush", "clear", "invalidate"})


@dataclass
class SessionFixationFinding:
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
class SessionFixationStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_session_from_request(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _SESSION_ATTRS:
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return True
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
            if val.value.id == "request" and val.attr in {"cookies", "COOKIES"}:
                return True
    return False


class _SessionFixationVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SessionFixationFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        if node.name.lower() in _LOGIN_NAMES or any(
            n in node.name.lower() for n in ("login", "signin", "authenticate")
        ):
            self._check_login_handler(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        if node.name.lower() in _LOGIN_NAMES or any(
            n in node.name.lower() for n in ("login", "signin", "authenticate")
        ):
            self._check_login_handler(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def _check_login_handler(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        has_session_from_request = False
        has_regenerate = False

        for child in ast.walk(node):
            if _is_session_from_request(child):
                has_session_from_request = True
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Attribute) and func.attr in _REGENERATE_ATTRS:
                    has_regenerate = True

        if has_session_from_request and not has_regenerate:
            self.findings.append(
                SessionFixationFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="session_from_request",
                    severity="high",
                    message=f"Login handler '{node.name}' uses request session without regeneration",
                    function=node.name,
                )
            )
        elif not has_regenerate:
            self.findings.append(
                SessionFixationFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="missing_session_regeneration",
                    severity="medium",
                    message=f"Login handler '{node.name}' may not regenerate session ID after auth",
                    function=node.name,
                )
            )


class SessionFixationAnalyzer:
    """Detect session fixation risks in authentication handlers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[SessionFixationFinding] = []
        self._stats: SessionFixationStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[SessionFixationFinding]:
        if self._findings:
            return self._findings

        findings: list[SessionFixationFinding] = []
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
            visitor = _SessionFixationVisitor(rel)
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
        self._stats = SessionFixationStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> SessionFixationStats:
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
            f"Session fixation risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Session fixation analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No session fixation risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
