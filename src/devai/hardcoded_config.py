"""HardcodedConfigAnalyzer — detect environment-specific configuration in source."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_DB_URL_RE = re.compile(
    r"(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|sqlite)://[^\s\"']+",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)

_SAFE_PATH_PARTS = frozenset({"tests", "test", "testing"})


def _is_test_path(path: Path) -> bool:
    parts = path.parts
    if any(part in _SAFE_PATH_PARTS for part in parts):
        return True
    name = path.name
    return name.startswith("test_") or name.endswith("_test.py")


@dataclass
class HardcodedConfigFinding:
    """A hardcoded configuration value that should usually be externalized."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    value: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        preview = self.value
        if len(preview) > 60:
            preview = preview[:57] + "..."
        value = f" ({preview})" if preview else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{value}: "
            f"{self.message}"
        )


@dataclass
class HardcodedConfigStats:
    """Aggregate hardcoded-config statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _host_from_url(value: str) -> str:
    match = re.match(r"https?://([^/?:#]+)", value, re.IGNORECASE)
    return match.group(1).lower() if match else value.lower()


def _is_safe_url(value: str) -> bool:
    host = _host_from_url(value)
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "testserver"}:
        return True
    safe_domains = (
        "example.com",
        "example.org",
        "example.net",
        "schemas.xmlsoap.org",
        "www.w3.org",
        "docs.python.org",
        "pypi.org",
        "github.com",
    )
    return any(host == domain or host.endswith(f".{domain}") for domain in safe_domains)


def _is_safe_ip(value: str) -> bool:
    return value in {"127.0.0.1", "0.0.0.0", "255.255.255.255"}


def _is_os_environ(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "environ":
        if isinstance(node.value, ast.Name) and node.value.id == "os":
            return True
    return False


class _HardcodedConfigVisitor(ast.NodeVisitor):
    """Walk a module AST and collect hardcoded configuration patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HardcodedConfigFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        value: str = "",
    ) -> None:
        self.findings.append(
            HardcodedConfigFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                value=value,
            )
        )

    def _check_string(self, node: ast.AST, value: str) -> None:
        if not value or len(value) < 8:
            return

        if _URL_RE.search(value) and not _is_safe_url(value):
            self._add(
                node,
                "hardcoded_url",
                severity="medium",
                message="Externalize URLs via environment variables or config files",
                value=value,
            )

        if _DB_URL_RE.search(value):
            self._add(
                node,
                "hardcoded_db_url",
                severity="high",
                message="Database connection strings should come from environment config",
                value=value,
            )

        for match in _IPV4_RE.findall(value):
            if not _is_safe_ip(match):
                self._add(
                    node,
                    "hardcoded_ip",
                    severity="medium",
                    message="Externalize host IP addresses for portability across environments",
                    value=match,
                )

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self._check_string(node, node.value)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _is_os_environ(node.value):
            self._add(
                node,
                "env_bracket_access",
                severity="low",
                message="Prefer os.environ.get() to avoid KeyError when a variable is unset",
            )
        self.generic_visit(node)


class HardcodedConfigAnalyzer:
    """Detect hardcoded URLs, IPs, database URLs, and brittle env access.

    Helps teams externalize environment-specific settings before deployment.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HardcodedConfigFinding] = []
        self._stats: HardcodedConfigStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if path.suffix != ".py":
            return True
        return _is_test_path(path)

    def analyze(self) -> list[HardcodedConfigFinding]:
        """Analyze the project and return hardcoded-config findings."""
        if self._findings:
            return self._findings

        findings: list[HardcodedConfigFinding] = []
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
            visitor = _HardcodedConfigVisitor(rel)
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

        self._stats = HardcodedConfigStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HardcodedConfigStats:
        """Return aggregate hardcoded-config statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[HardcodedConfigFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def by_pattern(self, pattern: str) -> list[HardcodedConfigFinding]:
        """Return findings for a specific pattern (e.g. hardcoded_url)."""
        return [f for f in self.analyze() if f.pattern == pattern]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no hardcoded config)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 20.0 + medium * 8.0 + low * 3.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Hardcoded config: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing hardcoded-config findings."""
        self.analyze()
        lines = [
            "Hardcoded configuration analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No hardcoded configuration values found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
