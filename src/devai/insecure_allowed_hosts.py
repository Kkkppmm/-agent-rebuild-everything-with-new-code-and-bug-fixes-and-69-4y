"""InsecureAllowedHostsAnalyzer — detect wildcard ALLOWED_HOSTS configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HOST_SETTING_NAMES = frozenset(
    {
        "ALLOWED_HOSTS",
        "allowed_hosts",
        "TRUSTED_HOSTS",
        "trusted_hosts",
    }
)
_WILDCARD_PATTERN = re.compile(
    r"(?:ALLOWED_HOSTS|allowed_hosts|TRUSTED_HOSTS|trusted_hosts)\s*=\s*\[?\s*['\"]\*['\"]"
)


@dataclass
class InsecureAllowedHostsFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""

    def format(self) -> str:
        setting = f" ({self.setting})" if self.setting else ""
        return f"{self.path}:{self.lineno}{setting} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureAllowedHostsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _contains_wildcard(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value == "*":
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_contains_wildcard(elt) for elt in node.elts)
    return False


class _InsecureAllowedHostsVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureAllowedHostsFinding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _HOST_SETTING_NAMES:
                if _contains_wildcard(node.value):
                    self.findings.append(
                        InsecureAllowedHostsFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="wildcard_allowed_hosts",
                            severity="high",
                            message=(
                                "Wildcard allowed hosts accepts any Host header — "
                                "enumerate trusted domains instead"
                            ),
                            setting=target.id,
                        )
                    )
        self.generic_visit(node)


class InsecureAllowedHostsAnalyzer:
    """Detect wildcard ALLOWED_HOSTS / allowed_hosts settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureAllowedHostsFinding] = []
        self._stats: InsecureAllowedHostsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureAllowedHostsFinding]:
        findings: list[InsecureAllowedHostsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureAllowedHostsVisitor(rel)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _WILDCARD_PATTERN.search(line):
                findings.append(
                    InsecureAllowedHostsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="wildcard_allowed_hosts",
                        severity="high",
                        message=(
                            "Wildcard allowed hosts accepts any Host header — "
                            "enumerate trusted domains instead"
                        ),
                    )
                )
        return findings

    def analyze(self) -> list[InsecureAllowedHostsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureAllowedHostsFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            file_findings = self._scan_source(rel, source)
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureAllowedHostsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureAllowedHostsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure allowed hosts: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure allowed hosts analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No wildcard allowed-hosts patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
