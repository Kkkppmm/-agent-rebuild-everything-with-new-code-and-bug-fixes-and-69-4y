"""InsecureGraphqlSettingsAnalyzer — detect insecure GraphQL configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_PROD_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "graphql.py",
        "schema.py",
    }
)
_INTROSPECTION_ENABLED_RE = re.compile(
    r"GRAPHQL_(INTROSPECTION|INTROSPECTION_ENABLED)\s*=\s*True",
    re.IGNORECASE,
)
_PLAYGROUND_ENABLED_RE = re.compile(
    r"GRAPHQL_(PLAYGROUND|GRAPHIQL)(_ENABLED)?\s*=\s*True",
    re.IGNORECASE,
)
_DEBUG_GRAPHQL_RE = re.compile(
    r"(strawberry|ariadne|graphene).*debug\s*=\s*True",
    re.IGNORECASE,
)
_GRAPHIQL_ENABLED_RE = re.compile(
    r"GRAPHIQL_ENABLED\s*=\s*True",
    re.IGNORECASE,
)


@dataclass
class InsecureGraphqlSettingsFinding:
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
class InsecureGraphqlSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


class _InsecureGraphqlSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureGraphqlSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureGraphqlSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id.upper()
            if name in {"GRAPHQL_INTROSPECTION", "GRAPHQL_INTROSPECTION_ENABLED"}:
                if _bool_value(node.value) is True:
                    self._add(
                        node.lineno,
                        "graphql_introspection_enabled",
                        "high",
                        "GraphQL introspection is enabled — disable in production to limit schema exposure",
                        setting=target.id,
                    )
            elif name in {"GRAPHQL_PLAYGROUND_ENABLED", "GRAPHQL_GRAPHIQL_ENABLED", "GRAPHIQL_ENABLED"}:
                if _bool_value(node.value) is True:
                    self._add(
                        node.lineno,
                        "graphql_playground_enabled",
                        "medium",
                        "GraphQL playground/GraphiQL is enabled — disable in production",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureGraphqlSettingsAnalyzer:
    """Detect insecure GraphQL configuration in Django, Strawberry, and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureGraphqlSettingsFinding] = []
        self._stats: InsecureGraphqlSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureGraphqlSettingsFinding]:
        findings: list[InsecureGraphqlSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureGraphqlSettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _INTROSPECTION_ENABLED_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="graphql_introspection_enabled",
                        severity="high",
                        message="GraphQL introspection is enabled — disable in production to limit schema exposure",
                        setting="GRAPHQL_INTROSPECTION",
                    )
                )
            if _PLAYGROUND_ENABLED_RE.search(line) or _GRAPHIQL_ENABLED_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="graphql_playground_enabled",
                        severity="medium",
                        message="GraphQL playground/GraphiQL is enabled — disable in production",
                        setting="GRAPHQL_PLAYGROUND_ENABLED",
                    )
                )
            if _DEBUG_GRAPHQL_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="graphql_debug_mode",
                        severity="high",
                        message="GraphQL debug mode is enabled — exposes stack traces and schema details",
                        setting="debug",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureGraphqlSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureGraphqlSettingsFinding] = []
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
            file_findings = self._scan_source(rel, source, path.name)
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
        self._stats = InsecureGraphqlSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureGraphqlSettingsStats:
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
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 35.0 + high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure GraphQL settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure GraphQL settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure GraphQL configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
