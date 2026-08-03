"""OpenRedirectAnalyzer — detect open redirect vulnerabilities."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|url|uri|redirect|next|return|goto|target|dest|"
    r"callback|continue|forward|link|href|ref|referer|referrer|page|path)",
    re.IGNORECASE,
)

_REDIRECT_FUNCS = frozenset({
    "redirect",
    "RedirectResponse",
    "HttpResponseRedirect",
    "redirect_to",
    "safe_redirect",
})


@dataclass
class OpenRedirectFinding:
    """A redirect call with user-controlled destination."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        fn = f" in {self.function}" if self.function else ""
        return (
            f"{self.path}:{self.lineno}{fn} [{self.severity}] {self.pattern}: "
            f"{self.message}"
        )


@dataclass
class OpenRedirectStats:
    """Aggregate open-redirect analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    return False


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


class _OpenRedirectVisitor(ast.NodeVisitor):
    """Walk a module AST and collect open redirect risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[OpenRedirectFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        function: str = "",
    ) -> None:
        self.findings.append(
            OpenRedirectFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=function,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name in _REDIRECT_FUNCS and node.args:
            dest = node.args[0]
            if _looks_like_user_input(dest):
                self._add(
                    node,
                    "user_controlled_redirect",
                    severity="high",
                    message="Redirect destination from user input — validate against allowlist",
                    function=name,
                )
            if isinstance(dest, ast.JoinedStr):
                for val in dest.values:
                    if isinstance(val, ast.FormattedValue) and _looks_like_user_input(val.value):
                        self._add(
                            node,
                            "dynamic_redirect_url",
                            severity="high",
                            message="Dynamic redirect URL with user input — use url_has_allowed_host_and_scheme()",
                            function=name,
                        )
        self.generic_visit(node)


class OpenRedirectAnalyzer:
    """Detect open redirect vulnerabilities in web handlers.

    Flags ``redirect()``, ``RedirectResponse``, and similar calls that use
    user-controlled URLs without validation.
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
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = OpenRedirectStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> OpenRedirectStats:
        """Return aggregate open-redirect statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[OpenRedirectFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no open redirect risks)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Open redirect risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing open-redirect findings."""
        self.analyze()
        lines = ["Open redirect analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No open redirect risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
