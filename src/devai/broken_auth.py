"""BrokenAuthAnalyzer — detect broken authentication and authorization patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_AUTH_DECORATORS = frozenset(
    {
        "login_required",
        "requires_auth",
        "authenticated",
        "auth_required",
        "permission_required",
        "requires_login",
        "jwt_required",
        "token_required",
    }
)
_ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "delete", "patch", "api_route"})
_BYPASS_PATTERNS = (
    re.compile(r'if\s+\w+\s*==\s*["\'](?:admin|root|test|password)["\']'),
    re.compile(r'password\s*==\s*["\'][^"\']+["\']'),
    re.compile(r'authenticate\s*=\s*False'),
    re.compile(r'require_auth\s*=\s*False'),
    re.compile(r'login_required\s*=\s*False'),
    re.compile(r'session\[["\']authenticated["\']\]\s*=\s*True'),
)


@dataclass
class BrokenAuthFinding:
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
class BrokenAuthStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return None


class _BrokenAuthVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[BrokenAuthFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self._check_route_auth(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self._check_route_auth(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def _check_route_auth(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorator_names = [_decorator_name(d) for d in node.decorator_list]
        decorator_names = [n for n in decorator_names if n]
        has_route = any(n in _ROUTE_DECORATORS for n in decorator_names)
        has_auth = any(n in _AUTH_DECORATORS for n in decorator_names)
        if has_route and not has_auth:
            sensitive = any(
                token in node.name.lower()
                for token in ("admin", "delete", "update", "create", "secret", "private", "user")
            )
            if sensitive:
                self.findings.append(
                    BrokenAuthFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern="unprotected_route",
                        severity="medium",
                        message=f"Route handler '{node.name}' lacks an authentication decorator",
                        function=node.name,
                    )
                )

    def visit_Compare(self, node: ast.Compare) -> None:
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            left = node.left
            right = node.comparators[0] if node.comparators else None
            for side in (left, right):
                if isinstance(side, ast.Constant) and isinstance(side.value, str):
                    if side.value.lower() in {"admin", "root", "password", "test"}:
                        self.findings.append(
                            BrokenAuthFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="hardcoded_auth_bypass",
                                severity="critical",
                                message="Hardcoded credential or role comparison may allow auth bypass",
                                function=self._current_function(),
                            )
                        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and node.value.value is False:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "authenticate",
                    "require_auth",
                    "login_required",
                    "auth_required",
                }:
                    self.findings.append(
                        BrokenAuthFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="auth_disabled",
                            severity="high",
                            message=f"Authentication flag '{target.id}' set to False",
                            function=self._current_function(),
                        )
                    )
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                sub = target
                slice_node = sub.slice
                key = slice_node.value if isinstance(slice_node, ast.Constant) else None
                if (
                    isinstance(sub.value, ast.Name)
                    and sub.value.id == "session"
                    and key == "authenticated"
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is True
                ):
                    self.findings.append(
                        BrokenAuthFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="session_auth_shortcut",
                            severity="high",
                            message="Session marked authenticated without credential verification",
                            function=self._current_function(),
                        )
                    )
        self.generic_visit(node)


class BrokenAuthAnalyzer:
    """Detect broken authentication and authorization patterns in Python code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[BrokenAuthFinding] = []
        self._stats: BrokenAuthStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[BrokenAuthFinding]:
        findings: list[BrokenAuthFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _BYPASS_PATTERNS:
                if pattern.search(line):
                    name = pattern.pattern
                    if "authenticate" in name or "require_auth" in name:
                        ptype = "auth_disabled"
                        severity = "high"
                        message = "Authentication requirement explicitly disabled"
                    elif "session" in name:
                        ptype = "session_auth_shortcut"
                        severity = "high"
                        message = "Session marked authenticated without credential verification"
                    elif "password" in name or "admin" in name:
                        ptype = "hardcoded_auth_bypass"
                        severity = "critical"
                        message = "Hardcoded credential comparison may allow auth bypass"
                    else:
                        ptype = "hardcoded_auth_bypass"
                        severity = "critical"
                        message = "Potential authentication bypass pattern"
                    findings.append(
                        BrokenAuthFinding(
                            path=rel,
                            lineno=lineno,
                            pattern=ptype,
                            severity=severity,
                            message=message,
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[BrokenAuthFinding]:
        if self._findings:
            return self._findings

        findings: list[BrokenAuthFinding] = []
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
            visitor = _BrokenAuthVisitor(rel)
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
        self._stats = BrokenAuthStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> BrokenAuthStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Broken auth risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Broken auth analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No broken authentication patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
