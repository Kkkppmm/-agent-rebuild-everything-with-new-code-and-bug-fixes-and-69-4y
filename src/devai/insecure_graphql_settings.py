"""InsecureGraphqlSettingsAnalyzer — detect insecure GraphQL server configuration."""

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
_GRAPHQL_SETTING_NAMES = frozenset(
    {
        "GRAPHENE_SCHEMA_INTROSPECTION",
        "GRAPHQL_INTROSPECTION",
        "GRAPHQL_PLAYGROUND",
        "GRAPHQL_DEBUG",
        "GRAPHQL_DEPTH_LIMIT",
        "GRAPHQL_MAX_DEPTH",
        "DISABLE_INTROSPECTION",
        "ENABLE_GRAPHQL_PLAYGROUND",
    }
)
_INTROSPECTION_ENABLED_RE = re.compile(
    r"(GRAPHENE_SCHEMA_INTROSPECTION|GRAPHQL_INTROSPECTION|DISABLE_INTROSPECTION)\s*=\s*(True|False)",
    re.IGNORECASE,
)
_PLAYGROUND_ENABLED_RE = re.compile(
    r"(GRAPHQL_PLAYGROUND|ENABLE_GRAPHQL_PLAYGROUND)\s*=\s*True",
    re.IGNORECASE,
)
_DEBUG_ENABLED_RE = re.compile(
    r"GRAPHQL_DEBUG\s*=\s*True",
    re.IGNORECASE,
)
_NO_DEPTH_LIMIT_RE = re.compile(
    r"(GRAPHQL_DEPTH_LIMIT|GRAPHQL_MAX_DEPTH)\s*=\s*(None|0)",
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
    return None


def _int_or_none(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant):
        if node.value is None:
            return -1
        if isinstance(node.value, int):
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
            if isinstance(target, ast.Name) and target.id in _GRAPHQL_SETTING_NAMES:
                self._check_setting(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _check_setting(self, name: str, value_node: ast.AST, lineno: int) -> None:
        if name in {"GRAPHENE_SCHEMA_INTROSPECTION", "GRAPHQL_INTROSPECTION"}:
            enabled = _bool_value(value_node)
            if enabled is True:
                self._add(
                    lineno,
                    "introspection_enabled",
                    "high",
                    "GraphQL introspection is enabled in production — disable to reduce attack surface",
                    setting=name,
                )
            return

        if name == "DISABLE_INTROSPECTION":
            disabled = _bool_value(value_node)
            if disabled is False:
                self._add(
                    lineno,
                    "introspection_enabled",
                    "high",
                    "GraphQL introspection is not disabled — set DISABLE_INTROSPECTION = True",
                    setting=name,
                )
            return

        if name in {"GRAPHQL_PLAYGROUND", "ENABLE_GRAPHQL_PLAYGROUND"}:
            enabled = _bool_value(value_node)
            if enabled is True:
                self._add(
                    lineno,
                    "playground_enabled",
                    "high",
                    "GraphQL playground is enabled in production — disable interactive explorer",
                    setting=name,
                )
            return

        if name == "GRAPHQL_DEBUG":
            enabled = _bool_value(value_node)
            if enabled is True:
                self._add(
                    lineno,
                    "graphql_debug_enabled",
                    "high",
                    "GraphQL debug mode is enabled — disable in production",
                    setting=name,
                )
            return

        if name in {"GRAPHQL_DEPTH_LIMIT", "GRAPHQL_MAX_DEPTH"}:
            limit = _int_or_none(value_node)
            if limit is not None and limit <= 0:
                self._add(
                    lineno,
                    "no_depth_limit",
                    "medium",
                    "GraphQL depth limit is disabled — set a reasonable max depth to prevent DoS",
                    setting=name,
                )


class InsecureGraphqlSettingsAnalyzer:
    """Detect insecure GraphQL configuration in Django and application settings."""

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
            match = _INTROSPECTION_ENABLED_RE.search(line)
            if match:
                value = match.group(2).lower()
                name = match.group(1)
                if name.upper() == "DISABLE_INTROSPECTION" and value == "false":
                    findings.append(
                        InsecureGraphqlSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="introspection_enabled",
                            severity="high",
                            message="GraphQL introspection is not disabled",
                            setting="DISABLE_INTROSPECTION",
                        )
                    )
                elif name.upper() != "DISABLE_INTROSPECTION" and value == "true":
                    findings.append(
                        InsecureGraphqlSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="introspection_enabled",
                            severity="high",
                            message="GraphQL introspection is enabled in production",
                            setting=name,
                        )
                    )
            if _PLAYGROUND_ENABLED_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="playground_enabled",
                        severity="high",
                        message="GraphQL playground is enabled in production",
                        setting="GRAPHQL_PLAYGROUND",
                    )
                )
            if _DEBUG_ENABLED_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="graphql_debug_enabled",
                        severity="high",
                        message="GraphQL debug mode is enabled",
                        setting="GRAPHQL_DEBUG",
                    )
                )
            if _NO_DEPTH_LIMIT_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="no_depth_limit",
                        severity="medium",
                        message="GraphQL depth limit is disabled",
                        setting="GRAPHQL_DEPTH_LIMIT",
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
