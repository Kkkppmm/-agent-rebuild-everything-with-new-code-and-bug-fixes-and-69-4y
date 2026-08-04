"""SessionFixationAnalyzer — detect session fixation vulnerabilities."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SESSION_ID_PARAMS = frozenset({"sessionid", "session_id", "sid", "jsessionid", "PHPSESSID"})
_LOGIN_NAMES = frozenset({"login", "signin", "sign_in", "authenticate", "auth"})
_REGENERATE_ATTRS = frozenset({"clear", "flush", "regenerate", "cycle_key", "invalidate"})


@dataclass
class SessionFixationFinding:
    """A potential session fixation vulnerability."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class SessionFixationStats:
    """Aggregate session-fixation analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_attr(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _is_session_access(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id == "session":
        return True
    if isinstance(node, ast.Attribute) and node.attr == "session":
        return True
    return False


def _param_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return None


class _SessionFixationVisitor(ast.NodeVisitor):
    """Walk a module AST and collect session fixation risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SessionFixationFinding] = []
        self._function_stack: list[str] = []
        self._in_login_handler = False
        self._login_has_regenerate = False

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _is_login_function(self, name: str) -> bool:
        lower = name.lower()
        return any(token in lower for token in _LOGIN_NAMES)

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            SessionFixationFinding(
                path=self.path,
                lineno=node.lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        was_login = self._in_login_handler
        had_regenerate = self._login_has_regenerate
        self._function_stack.append(node.name)
        self._in_login_handler = self._is_login_function(node.name)
        self._login_has_regenerate = False
        self.generic_visit(node)
        if self._in_login_handler and not self._login_has_regenerate:
            self._add(
                node,
                "missing_session_regeneration",
                severity="medium",
                message="Login handler does not regenerate session ID — vulnerable to session fixation",
            )
        self._function_stack.pop()
        self._in_login_handler = was_login
        self._login_has_regenerate = had_regenerate

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        was_login = self._in_login_handler
        had_regenerate = self._login_has_regenerate
        self._function_stack.append(node.name)
        self._in_login_handler = self._is_login_function(node.name)
        self._login_has_regenerate = False
        self.generic_visit(node)
        if self._in_login_handler and not self._login_has_regenerate:
            self._add(
                node,
                "missing_session_regeneration",
                severity="medium",
                message="Login handler does not regenerate session ID — vulnerable to session fixation",
            )
        self._function_stack.pop()
        self._in_login_handler = was_login
        self._login_has_regenerate = had_regenerate

    def visit_Call(self, node: ast.Call) -> None:
        attr = _call_attr(node)
        if attr in _REGENERATE_ATTRS and node.func and isinstance(node.func, ast.Attribute):
            if _is_session_access(node.func.value):
                self._login_has_regenerate = True

        if attr in {"get", "getlist", "args", "form", "values"} or (
            attr and attr.lower() in _SESSION_ID_PARAMS
        ):
            for arg in node.args:
                name = _param_name(arg)
                if name and name in _SESSION_ID_PARAMS:
                    self._add(
                        node,
                        "session_id_in_url",
                        severity="high",
                        message="Session ID read from request parameter — use cookies only",
                    )

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "getlist"}:
            if node.args:
                name = _param_name(node.args[0])
                if name and name in _SESSION_ID_PARAMS:
                    self._add(
                        node,
                        "session_id_in_url",
                        severity="high",
                        message="Session ID read from request parameter — use cookies only",
                    )

        if isinstance(node.func, ast.Attribute) and node.func.attr == "__getitem__":
            if node.args:
                name = _param_name(node.args[0])
                if name and name in _SESSION_ID_PARAMS:
                    self._add(
                        node,
                        "session_id_in_url",
                        severity="high",
                        message="Session ID read from request parameter — use cookies only",
                    )

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        name = _param_name(node.slice)
        if name and name in _SESSION_ID_PARAMS:
            self._add(
                node,
                "session_id_in_url",
                severity="high",
                message="Session ID read from request parameter — use cookies only",
            )
        self.generic_visit(node)


class SessionFixationAnalyzer:
    """Detect session fixation vulnerabilities in web application code.

    Flags session IDs passed via URL parameters and login handlers that do not
    regenerate the session after authentication.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
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
        """Analyze the project and return session-fixation findings."""
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no session-fixation risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 12.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Session fixation risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing session-fixation findings."""
        self.analyze()
        lines = [
            "Session fixation analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No session-fixation patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
