"""SessionFixationAnalyzer — detect missing session regeneration after authentication."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_AUTH_FUNCS = frozenset(
    {
        "login",
        "authenticate",
        "sign_in",
        "signin",
        "log_in",
        "login_user",
        "authenticate_user",
    }
)
_SESSION_REGEN = frozenset(
    {
        "cycle_key",
        "regenerate",
        "flush",
        "clear",
        "invalidate",
        "new_session",
        "rotate_sid",
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


def _func_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _func_name(node.func)
    return None


class _SessionFixationVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SessionFixationFinding] = []
        self._in_auth_fn = False
        self._auth_fn_name = ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        is_auth = node.name in _AUTH_FUNCS or any(
            _func_name(d) in _AUTH_FUNCS for d in node.decorator_list
        )
        if is_auth:
            self._in_auth_fn = True
            self._auth_fn_name = node.name
            has_regen = self._check_session_regen(node)
            if not has_regen:
                self.findings.append(
                    SessionFixationFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="missing_session_regen",
                        severity="high",
                        message=f"Auth handler '{node.name}' does not regenerate session ID",
                        function=node.name,
                    )
                )
            self._in_auth_fn = False
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        is_auth = node.name in _AUTH_FUNCS or any(
            _func_name(d) in _AUTH_FUNCS for d in node.decorator_list
        )
        if is_auth:
            has_regen = self._check_session_regen(node)
            if not has_regen:
                self.findings.append(
                    SessionFixationFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="missing_session_regen",
                        severity="high",
                        message=f"Auth handler '{node.name}' does not regenerate session ID",
                        function=node.name,
                    )
                )
        self.generic_visit(node)

    def _check_session_regen(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _func_name(child.func)
                if name in _SESSION_REGEN:
                    return True
                if isinstance(child.func, ast.Attribute) and child.func.attr in _SESSION_REGEN:
                    return True
        return False


class SessionFixationAnalyzer:
    """Detect login handlers that fail to regenerate session identifiers."""

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
                lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
