"""InsecureGraphqlSettingsAnalyzer — detect exposed GraphQL introspection and playgrounds."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SETTINGS_FILENAMES = frozenset(
    {
        "settings.py",
        "production.py",
        "prod.py",
        "config.py",
        "graphql.py",
        "schema.py",
    }
)
_URLS_FILENAMES = frozenset(
    {
        "urls.py",
        "api_urls.py",
        "router.py",
        "routing.py",
    }
)
_INTROSPECTION_ENABLED_RE = re.compile(
    r"(INTROSPECTION_ENABLED|ALLOW_INTROSPECTION|enable_introspection|"
    r"introspection_enabled)\s*[:=]\s*True",
    re.IGNORECASE,
)
_GRAPHIQL_ENABLED_RE = re.compile(
    r"(GRAPHIQL_ENABLED|GRAPHQL_PLAYGROUND|graphiql_enabled|playground_enabled|"
    r"graphql_ide)\s*[:=]\s*True",
    re.IGNORECASE,
)
_GRAPHQL_VIEW_RE = re.compile(
    r"GraphQLView|GraphiQLView|GraphQLApp|GraphQLRouter|"
    r"strawberry\.fastapi\.GraphQLRouter|ariadne\.contrib\.fastapi",
    re.IGNORECASE,
)
_GRAPHQL_DEBUG_RE = re.compile(
    r"(GRAPHQL_DEBUG|graphql_debug)\s*[:=]\s*True",
    re.IGNORECASE,
)
_PUBLIC_GRAPHQL_PERMISSION_RE = re.compile(
    r"permission_classes\s*=\s*\[\s*\]|permissions\.AllowAny|AllowAny",
    re.IGNORECASE,
)
_GRAPHQL_URL_RE = re.compile(
    r"['\"](graphql|graphiql|playground)['\"]",
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


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_empty_list(node: ast.AST) -> bool:
    return isinstance(node, ast.List) and len(node.elts) == 0


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
        if self.filename in _SETTINGS_FILENAMES:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    upper = name.upper()
                    if upper in {
                        "INTROSPECTION_ENABLED",
                        "ALLOW_INTROSPECTION",
                        "GRAPHQL_INTROSPECTION",
                    } and _is_true(node.value):
                        self._add(
                            node.lineno,
                            "introspection_enabled",
                            "high",
                            f"{name} exposes GraphQL introspection in production",
                            setting=name,
                        )
                    elif upper in {"GRAPHIQL_ENABLED", "GRAPHQL_PLAYGROUND"} and _is_true(node.value):
                        self._add(
                            node.lineno,
                            "graphiql_enabled",
                            "high",
                            f"{name} exposes GraphQL IDE/playground in production",
                            setting=name,
                        )
                    elif upper == "GRAPHENE" and isinstance(node.value, ast.Dict):
                        self._scan_graphene_dict(node.value)
                elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                    attr = target.attr.lower()
                    if attr in {"introspection_enabled", "graphiql_enabled", "playground_enabled"}:
                        if _is_true(node.value):
                            pattern = (
                                "introspection_enabled"
                                if "introspection" in attr
                                else "graphiql_enabled"
                            )
                            self._add(
                                node.lineno,
                                pattern,
                                "high",
                                f"{target.value.id}.{target.attr} exposes GraphQL debugging in production",
                                setting=f"{target.value.id}.{target.attr}",
                            )
        self.generic_visit(node)

    def _scan_graphene_dict(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values):
            key = _dict_string_value(key_node) if key_node else None
            if key is None:
                continue
            if key.upper() == "MIDDLEWARE" and _is_empty_list(value_node):
                self._add(
                    node.lineno,
                    "empty_graphql_middleware",
                    "medium",
                    "GRAPHENE MIDDLEWARE is empty — add authentication middleware for GraphQL",
                    setting="GRAPHENE['MIDDLEWARE']",
                )


class InsecureGraphqlSettingsAnalyzer:
    """Detect exposed GraphQL introspection, playgrounds, and unauthenticated views."""

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

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if filename in _SETTINGS_FILENAMES:
                if _INTROSPECTION_ENABLED_RE.search(line):
                    findings.append(
                        InsecureGraphqlSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="introspection_enabled",
                            severity="high",
                            message="GraphQL introspection is enabled — disable in production",
                        )
                    )
                if _GRAPHIQL_ENABLED_RE.search(line):
                    findings.append(
                        InsecureGraphqlSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="graphiql_enabled",
                            severity="high",
                            message="GraphQL IDE/playground is enabled — disable in production",
                        )
                    )
                if _GRAPHQL_DEBUG_RE.search(line):
                    findings.append(
                        InsecureGraphqlSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="graphql_debug",
                            severity="medium",
                            message="GraphQL debug mode is enabled in settings",
                        )
                    )

            if filename in _URLS_FILENAMES:
                if _GRAPHQL_VIEW_RE.search(line):
                    if _PUBLIC_GRAPHQL_PERMISSION_RE.search(line):
                        findings.append(
                            InsecureGraphqlSettingsFinding(
                                path=rel,
                                lineno=lineno,
                                pattern="public_graphql_view",
                                severity="high",
                                message="GraphQL view uses AllowAny — require authentication",
                            )
                        )
                    elif _GRAPHQL_URL_RE.search(line):
                        findings.append(
                            InsecureGraphqlSettingsFinding(
                                path=rel,
                                lineno=lineno,
                                pattern="exposed_graphql_route",
                                severity="medium",
                                message="GraphQL route may be publicly exposed — verify authentication",
                            )
                        )
                if "graphiql=True" in line or "graphql_ide=" in line.lower():
                    findings.append(
                        InsecureGraphqlSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="graphiql_enabled",
                            severity="high",
                            message="GraphiQL/IDE is enabled on GraphQL route",
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
