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
    r"GRAPHENE\s*=\s*\{[^}]*['\"]MIDDLEWARE['\"]\s*:\s*\[\s*\]",
    re.IGNORECASE | re.DOTALL,
)
_GRAPHENE_MIDDLEWARE_EMPTY_RE = re.compile(
    r"GRAPHENE\s*=\s*\{[^}]*['\"]MIDDLEWARE['\"]\s*:\s*\[\s*\]",
    re.IGNORECASE | re.DOTALL,
)
_GRAPHQL_PLAYGROUND_RE = re.compile(
    r"GRAPHQL_PLAYGROUND|GRAPHIQL|graphiql|playground\s*=\s*True",
    re.IGNORECASE,
)
_INTROSPECTION_TRUE_RE = re.compile(
    r"introspection\s*[=:]\s*True|INTROSPECTION\s*=\s*True",
    re.IGNORECASE,
)
_PUBLIC_GRAPHQL_VIEW_RE = re.compile(
    r"csrf_exempt.*graphql|GraphQLView|graphene_django\.views\.GraphQLView",
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


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_empty_list(node: ast.AST) -> bool:
    return isinstance(node, ast.List) and not node.elts


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
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if name == "GRAPHENE" and isinstance(node.value, ast.Dict):
                self._scan_graphene_dict(node)
            elif name in {"GRAPHQL_PLAYGROUND", "GRAPHIQL_ENABLED"} and _is_true(node.value):
                self._add(
                    node.lineno,
                    "graphql_playground_enabled",
                    "medium",
                    f"{name} is True — disable GraphiQL/playground in production",
                    setting=name,
                )
            elif name == "GRAPHQL_INTROSPECTION" and _is_true(node.value):
                self._add(
                    node.lineno,
                    "introspection_enabled",
                    "high",
                    "GRAPHQL_INTROSPECTION is True — disable schema introspection in production",
                    setting="GRAPHQL_INTROSPECTION",
                )
        self.generic_visit(node)

    def _scan_graphene_dict(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Dict):
            return
        for key, val in zip(node.value.keys, node.value.values):
            if not key or not isinstance(key, ast.Constant):
                continue
            key_str = str(key.value).upper()
            if key_str == "MIDDLEWARE" and _is_empty_list(val):
                self._add(
                    node.lineno,
                    "empty_graphene_middleware",
                    "high",
                    "GRAPHENE MIDDLEWARE is empty — introspection and depth limits are disabled",
                    setting="GRAPHENE",
                )
            if key_str in {"SCHEMA", "SCHEMA_INDENT"} and isinstance(val, ast.Constant):
                pass
            if key_str == "MIDDLEWARE" and isinstance(val, ast.List):
                for elt in val.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        if "introspection" in elt.value.lower() and "disable" not in elt.value.lower():
                            self._add(
                                node.lineno,
                                "introspection_middleware_missing",
                                "medium",
                                "GRAPHENE middleware may allow introspection — use DisableIntrospectionMiddleware",
                                setting="GRAPHENE",
                            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "csrf_exempt":
                if "graphql" in node.name.lower() or "graph" in node.name.lower():
                    self._add(
                        node.lineno,
                        "csrf_exempt_graphql_view",
                        "high",
                        f"GraphQL view {node.name} uses @csrf_exempt — use authenticated views",
                        setting="csrf_exempt",
                    )
        self.generic_visit(node)


class InsecureGraphqlSettingsAnalyzer:
    """Detect insecure GraphQL configuration in Django/Graphene and similar apps."""

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
            if _GRAPHQL_PLAYGROUND_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="graphql_playground_enabled",
                        severity="medium",
                        message="GraphiQL/playground is enabled — disable in production",
                        setting="GRAPHQL_PLAYGROUND",
                    )
                )
            if _INTROSPECTION_TRUE_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="introspection_enabled",
                        severity="high",
                        message="GraphQL introspection is enabled — disable in production",
                        setting="GRAPHQL_INTROSPECTION",
                    )
                )
            if _GRAPHENE_MIDDLEWARE_EMPTY_RE.search(line):
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="empty_graphene_middleware",
                        severity="high",
                        message="GRAPHENE MIDDLEWARE is empty — introspection and depth limits are disabled",
                        setting="GRAPHENE",
                    )
                )
            if _PUBLIC_GRAPHQL_VIEW_RE.search(line) and "csrf_exempt" in line.lower():
                findings.append(
                    InsecureGraphqlSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csrf_exempt_graphql_view",
                        severity="high",
                        message="Public GraphQL view without CSRF protection",
                        setting="csrf_exempt",
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
