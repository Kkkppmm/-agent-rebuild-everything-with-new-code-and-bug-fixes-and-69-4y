"""InsecureTLSAnalyzer — detect disabled SSL/TLS certificate verification."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_VERIFY_FALSE_RE = re.compile(
    r"(verify\s*=\s*False|ssl\s*=\s*False|check_hostname\s*=\s*False|"
    r"CERT_NONE|verify_mode\s*=\s*ssl\.CERT_NONE|"
    r"ssl\._create_unverified_context|create_default_context\(\)\.check_hostname\s*=\s*False)",
    re.IGNORECASE,
)

_INSECURE_CONTEXT_RE = re.compile(
    r"(ssl\._create_unverified_context|SSLContext\(ssl\.PROTOCOL_SSLv|"
    r"ssl\.PROTOCOL_TLSv1[^2]|ssl\.PROTOCOL_SSLv)",
    re.IGNORECASE,
)


@dataclass
class InsecureTLSFinding:
    """A detected insecure TLS/SSL configuration."""

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
class InsecureTLSStats:
    """Aggregate insecure TLS analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


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


class _InsecureTLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure TLS patterns."""

    def __init__(self, path: str, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.findings: list[InsecureTLSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, lineno: int, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            InsecureTLSFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(
                    node.lineno,
                    "verify_false",
                    "high",
                    "verify=False disables TLS certificate validation — use a proper CA bundle",
                )
            if kw.arg == "ssl" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(
                    node.lineno,
                    "ssl_false",
                    "high",
                    "ssl=False disables TLS — enable certificate verification",
                )

        name = _call_name(node)
        if "create_unverified_context" in name:
            self._add(
                node.lineno,
                "unverified_context",
                "high",
                "ssl._create_unverified_context() bypasses certificate validation",
            )

        self.generic_visit(node)

    def scan_lines(self) -> None:
        """Scan source lines for regex-based TLS anti-patterns."""
        for lineno, line in enumerate(self.source_lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _VERIFY_FALSE_RE.search(line):
                if not any(f.lineno == lineno for f in self.findings):
                    self._add(
                        lineno,
                        "verify_disabled",
                        "high",
                        "TLS certificate verification is disabled",
                    )
            if _INSECURE_CONTEXT_RE.search(line):
                if not any(f.lineno == lineno for f in self.findings):
                    self._add(
                        lineno,
                        "insecure_ssl_context",
                        "medium",
                        "Outdated or unverified SSL context detected",
                    )


class InsecureTLSAnalyzer:
    """Detect disabled SSL/TLS certificate verification.

    Flags ``verify=False``, ``ssl=False``, ``ssl._create_unverified_context()``,
    and ``CERT_NONE`` usage in HTTP clients and SSL configuration.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureTLSFinding] = []
        self._stats: InsecureTLSStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureTLSFinding]:
        """Analyze the project and return insecure TLS findings."""
        if self._findings:
            return self._findings

        findings: list[InsecureTLSFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                lines = source.splitlines()
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _InsecureTLSVisitor(rel, lines)
            visitor.visit(tree)
            visitor.scan_lines()
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

        self._stats = InsecureTLSStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureTLSStats:
        """Return aggregate insecure TLS statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InsecureTLSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure TLS)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Insecure TLS: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure TLS findings."""
        self.analyze()
        lines = [
            "Insecure TLS analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure TLS configurations found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
