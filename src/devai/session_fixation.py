"""SessionFixationAnalyzer — detect session fixation vulnerabilities."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SESSION_ATTRS = frozenset({"session", "sessions"})
_LOGIN_INDICATORS = frozenset({"login", "authenticate", "signin", "sign_in", "auth"})
_REGENERATE_METHODS = frozenset(
    {
        "regenerate",
        "cycle_key",
        "flush",
        "clear",
        "new",
        "rotate",
    }
)


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


class _SessionFixationVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SessionFixationFinding] = []
        self._function_stack: list[str] = []
        self._in_login_function = False
        self._session_regenerated = False

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        was_login = self._in_login_function
        self._in_login_function = any(ind in node.name.lower() for ind in _LOGIN_INDICATORS)
        self._session_regenerated = False
        self._function_stack.append(node.name)
        self.generic_visit(node)
        if self._in_login_function and not self._session_regenerated:
            self.findings.append(
                SessionFixationFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="no_session_regeneration",
                    severity="high",
                    message=f"Login function '{node.name}' does not regenerate session ID",
                    function=node.name,
                )
            )
        self._function_stack.pop()
        self._in_login_function = was_login

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        was_login = self._in_login_function
        self._in_login_function = any(ind in node.name.lower() for ind in _LOGIN_INDICATORS)
        self._session_regenerated = False
        self._function_stack.append(node.name)
        self.generic_visit(node)
        if self._in_login_function and not self._session_regenerated:
            self.findings.append(
                SessionFixationFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="no_session_regeneration",
                    severity="high",
                    message=f"Login function '{node.name}' does not regenerate session ID",
                    function=node.name,
                )
            )
        self._function_stack.pop()
        self._in_login_function = was_login

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Name) and target.value.id == "session":
                    if self._is_from_request(node.value):
                        self.findings.append(
                            SessionFixationFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="session_from_request",
                                severity="high",
                                message="Session ID set from request enables session fixation",
                                function=self._current_function(),
                            )
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "session":
                if func.attr in _REGENERATE_METHODS:
                    self._session_regenerated = True
                if func.attr == "update" and node.args and self._is_from_request(node.args[0]):
                    self.findings.append(
                        SessionFixationFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="session_from_request",
                            severity="high",
                            message="session.update() with request data may preserve attacker session",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)

    def _is_from_request(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute):
            if node.attr in {"cookies", "args", "form", "GET", "POST", "headers"}:
                return True
            return self._is_from_request(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_from_request(node.value)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "get":
                if isinstance(func.value, ast.Attribute) and func.value.attr == "cookies":
                    return True
        if isinstance(node, ast.Name) and node.id == "request":
            return True
        return False


class SessionFixationAnalyzer:
    """Detect session fixation vulnerabilities in authentication code."""

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
        penalty = high * 15.0
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
            lines.append("No session fixation patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
