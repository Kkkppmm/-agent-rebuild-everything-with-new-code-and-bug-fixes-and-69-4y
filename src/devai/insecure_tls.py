"""InsecureTLSAnalyzer — detect disabled TLS certificate verification."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_VERIFY_FALSE = re.compile(r"""verify\s*=\s*False\b""")
_SSL_FALSE = re.compile(r"""ssl\s*=\s*False\b""")
_UNVERIFIED_CONTEXT = re.compile(r"""_create_unverified_context\s*\(""")
_CERT_NONE = re.compile(r"""\bCERT_NONE\b""")
_CHECK_HOSTNAME_FALSE = re.compile(r"""check_hostname\s*=\s*False\b""")


@dataclass
class InsecureTLSFinding:
    """A potentially unsafe TLS/SSL configuration."""

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
    """Aggregate insecure TLS statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


class _InsecureTLSVisitor(ast.NodeVisitor):
    """Walk a module AST and collect disabled TLS verification."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTLSFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, node: ast.AST, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            InsecureTLSFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
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
        name = _attr_chain(node.func)

        for kw in node.keywords:
            if kw.arg == "verify" and _is_false(kw.value):
                self._add(
                    node,
                    "verify_false",
                    "high",
                    "HTTP client disables TLS certificate verification with verify=False",
                )
            if kw.arg == "ssl" and _is_false(kw.value):
                self._add(
                    node,
                    "ssl_false",
                    "high",
                    "Client disables TLS with ssl=False — use a proper SSL context instead",
                )
            if kw.arg == "check_hostname" and _is_false(kw.value):
                self._add(
                    node,
                    "check_hostname_false",
                    "high",
                    "SSL context disables hostname verification",
                )
            if kw.arg in {"cert_reqs", "verify_mode"}:
                if isinstance(kw.value, ast.Attribute) and kw.value.attr == "CERT_NONE":
                    self._add(
                        node,
                        "cert_none",
                        "high",
                        "SSL context sets cert_reqs/verify_mode to CERT_NONE",
                    )

        if name.endswith("_create_unverified_context"):
            self._add(
                node,
                "unverified_context",
                "high",
                "ssl._create_unverified_context() disables certificate validation",
            )

        if isinstance(node.func, ast.Attribute) and node.func.attr == "disable_warnings":
            module = _attr_chain(node.func.value)
            if "urllib3" in module or "requests" in module:
                self._add(
                    node,
                    "disable_ssl_warnings",
                    "medium",
                    "Disabling urllib3 SSL warnings often accompanies verify=False usage",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            name = _attr_chain(node.value.func)
            if name.endswith("_create_unverified_context"):
                self._add(
                    node,
                    "unverified_context",
                    "high",
                    "ssl._create_unverified_context() disables certificate validation",
                )

        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "check_hostname" and _is_false(node.value):
                    self._add(
                        node,
                        "check_hostname_false",
                        "high",
                        "SSL context disables hostname verification",
                    )
                if target.attr in {"verify_mode", "cert_reqs"}:
                    if isinstance(node.value, ast.Attribute) and node.value.attr == "CERT_NONE":
                        self._add(
                            node,
                            "cert_none",
                            "high",
                            "SSL context sets verify_mode/cert_reqs to CERT_NONE",
                        )
        self.generic_visit(node)


class InsecureTLSAnalyzer:
    """Detect disabled TLS certificate verification.

    Flags ``verify=False`` in requests/httpx, ``ssl=False`` in aiohttp,
    ``ssl._create_unverified_context()``, and ``ssl.CERT_NONE`` usage.
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
        if path.name in {".env", ".env.local", ".env.production"}:
            return False
        return path.suffix not in {".py", ".yaml", ".yml", ".toml", ".ini"}

    def _scan_text_file(self, path: Path, rel: str) -> list[InsecureTLSFinding]:
        findings: list[InsecureTLSFinding] = []
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return findings

        patterns = (
            (_VERIFY_FALSE, "verify_false", "high", "Configuration disables TLS verification"),
            (_SSL_FALSE, "ssl_false", "high", "Configuration disables TLS with ssl=False"),
            (
                _UNVERIFIED_CONTEXT,
                "unverified_context",
                "high",
                "Configuration uses unverified SSL context",
            ),
            (_CERT_NONE, "cert_none", "high", "Configuration sets CERT_NONE"),
            (
                _CHECK_HOSTNAME_FALSE,
                "check_hostname_false",
                "high",
                "Configuration disables hostname verification",
            ),
        )

        for lineno, line in enumerate(source.splitlines(), start=1):
            for regex, pattern, severity, message in patterns:
                if regex.search(line):
                    findings.append(
                        InsecureTLSFinding(
                            path=rel,
                            lineno=lineno,
                            pattern=pattern,
                            severity=severity,
                            message=message,
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[InsecureTLSFinding]:
        """Analyze the project and return insecure TLS findings."""
        if self._findings:
            return self._findings

        findings: list[InsecureTLSFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or self._should_skip(path):
                continue

            rel = str(path.relative_to(self.root))
            files_scanned += 1

            if path.suffix == ".py":
                try:
                    source = path.read_text(encoding="utf-8")
                    tree = ast.parse(source, filename=str(path))
                except (OSError, UnicodeDecodeError, SyntaxError):
                    continue
                visitor = _InsecureTLSVisitor(rel)
                visitor.visit(tree)
                file_findings = visitor.findings
            else:
                file_findings = self._scan_text_file(path, rel)

            if file_findings:
                files_with_findings.add(rel)
            findings.extend(file_findings)

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
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InsecureTLSFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure TLS patterns)."""
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
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
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
            lines.append("No insecure TLS patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
