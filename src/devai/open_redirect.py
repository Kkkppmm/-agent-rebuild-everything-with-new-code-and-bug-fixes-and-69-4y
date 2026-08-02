"""OpenRedirectAnalyzer — detect open redirect vulnerabilities in web frameworks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|url|uri|next|redirect|return|goto|target|"
    r"destination|continue|callback|link|href|location|forward|"
    r"param|query|args|form|get|post|path|route|referer|referrer)",
    re.IGNORECASE,
)

_REDIRECT_FUNCS = frozenset({
    "redirect",
    "HttpResponseRedirect",
    "HttpResponsePermanentRedirect",
    "RedirectResponse",
    "Redirect",
    "redirect_to",
    "safe_redirect",
})

_REDIRECT_MODULES = frozenset({
    "flask",
    "django",
    "fastapi",
    "starlette",
    "werkzeug",
})


@dataclass
class OpenRedirectFinding:
    """A potentially unsafe redirect pattern."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""
    framework: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        fw = f" [{self.framework}]" if self.framework else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call}{fw} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class OpenRedirectStats:
    """Aggregate open-redirect analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_framework: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _looks_like_user_input(node.func)
    return False


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _looks_like_user_input(v.value)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _looks_like_user_input(node.left) or _looks_like_user_input(node.right)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "getlist", "get_json"}:
            return True
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return any(_looks_like_user_input(arg) for arg in node.args) or any(
                _looks_like_user_input(kw.value) for kw in node.keywords
            )
    return _looks_like_user_input(node)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _detect_framework(name: str) -> str:
    parts = name.split(".")
    for part in parts:
        if part in _REDIRECT_MODULES:
            return part
    if parts and parts[-1] in _REDIRECT_FUNCS:
        return "web"
    return ""


def _first_redirect_arg(node: ast.Call) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in {"url", "location", "to", "url_name"}:
            return kw.value
    return None


def _is_open_redirect(node: ast.Call) -> tuple[str, str, str, str] | None:
    """Return (pattern, severity, message, framework) for risky redirects."""
    name = _call_name(node)
    parts = name.split(".")
    method = parts[-1] if parts else name

    if method not in _REDIRECT_FUNCS and name not in _REDIRECT_FUNCS:
        return None

    url_arg = _first_redirect_arg(node)
    if url_arg is None:
        return None

    if not _is_dynamic_string(url_arg):
        return None

    framework = _detect_framework(name)
    if isinstance(url_arg, ast.Call):
        inner = _call_name(url_arg) if isinstance(url_arg, ast.Call) else ""
        if ".get" in inner or inner.endswith(".get"):
            return (
                "request_param_redirect",
                "high",
                "Redirect URL taken from request parameter — validate against an allowlist",
                framework or "web",
            )

    if framework == "flask" or name == "redirect":
        return (
            "flask_open_redirect",
            "high",
            "Flask redirect with user-controlled URL — use url_for() with fixed endpoints",
            "flask",
        )

    if framework in {"django"} or "HttpResponseRedirect" in name:
        return (
            "django_open_redirect",
            "high",
            "Django redirect with user-controlled URL — validate destination before redirecting",
            "django",
        )

    if framework in {"fastapi", "starlette"} or "RedirectResponse" in name:
        return (
            "fastapi_open_redirect",
            "high",
            "FastAPI/Starlette redirect with user-controlled URL — validate against an allowlist",
            framework or "fastapi",
        )

    return (
        "open_redirect",
        "high",
        "Redirect with user-controlled URL — validate destination before redirecting",
        framework or "web",
    )


class _OpenRedirectVisitor(ast.NodeVisitor):
    """Walk a module AST and collect open-redirect risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[OpenRedirectFinding] = []
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
        result = _is_open_redirect(node)
        if result:
            pattern, severity, message, framework = result
            self.findings.append(
                OpenRedirectFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    function=self._current_function(),
                    call=_call_name(node),
                    framework=framework,
                )
            )
        self.generic_visit(node)


class OpenRedirectAnalyzer:
    """Detect open redirect vulnerabilities in Flask, Django, and FastAPI apps.

    Flags ``redirect()``, ``HttpResponseRedirect``, and ``RedirectResponse``
    calls where the destination URL is built from request parameters or other
    untrusted input without validation.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[OpenRedirectFinding] = []
        self._stats: OpenRedirectStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[OpenRedirectFinding]:
        """Analyze the project and return open-redirect findings."""
        if self._findings:
            return self._findings

        findings: list[OpenRedirectFinding] = []
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
            visitor = _OpenRedirectVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_framework: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            if finding.framework:
                by_framework[finding.framework] = by_framework.get(finding.framework, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = OpenRedirectStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            by_framework=by_framework,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> OpenRedirectStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[OpenRedirectFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no open redirects)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Open redirects: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        if stats.by_framework:
            frameworks = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_framework.items()))
            lines.append(f"By framework: {frameworks}")
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing open-redirect findings."""
        self.analyze()
        lines = [
            "Open redirect analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No open redirect vulnerabilities found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
