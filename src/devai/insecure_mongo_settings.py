"""InsecureMongoSettingsAnalyzer — detect insecure MongoDB configuration."""

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
        "mongo.py",
        "database.py",
    }
)
_MONGO_NO_AUTH_RE = re.compile(
    r"mongodb://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_MONGO_HTTP_RE = re.compile(
    r"(MONGO_URI|MONGODB_URI|MONGO_URL|MONGODB_URL)\s*=\s*['\"]mongodb://",
    re.IGNORECASE,
)
_MONGO_HARDCODED_PASSWORD_RE = re.compile(
    r"(MONGO_PASSWORD|MONGODB_PASSWORD)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
_MONGO_TLS_FALSE_RE = re.compile(
    r"(MONGO_TLS|MONGODB_TLS|TLS)\s*=\s*False",
    re.IGNORECASE,
)


@dataclass
class InsecureMongoSettingsFinding:
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
class InsecureMongoSettingsStats:
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


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _mongo_url_insecure(value: str) -> bool:
    lower = value.lower()
    if lower.startswith("mongodb+srv://"):
        return False
    if not lower.startswith("mongodb://"):
        return False
    return bool(_MONGO_NO_AUTH_RE.search(value))


class _InsecureMongoSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureMongoSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureMongoSettingsFinding(
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
            if name in {"MONGO_URI", "MONGODB_URI", "MONGO_URL", "MONGODB_URL", "MONGO_HOST"}:
                value = _string_value(node.value)
                if value and _mongo_url_insecure(value):
                    self._add(
                        node.lineno,
                        "mongo_no_auth",
                        "critical",
                        f"{target.id} has no authentication — use credentials and TLS",
                        setting=target.id,
                    )
            elif name in {"MONGO_TLS", "MONGODB_TLS", "TLS"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "mongo_tls_disabled",
                        "high",
                        f"{target.id} is False — enable TLS for MongoDB connections",
                        setting=target.id,
                    )
            elif name in {"MONGO_PASSWORD", "MONGODB_PASSWORD"}:
                value = _string_value(node.value)
                if value is not None and len(value) >= 4:
                    self._add(
                        node.lineno,
                        "hardcoded_mongo_password",
                        "critical",
                        f"{target.id} is hardcoded — load MongoDB credentials from environment",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureMongoSettingsAnalyzer:
    """Detect insecure MongoDB configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureMongoSettingsFinding] = []
        self._stats: InsecureMongoSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureMongoSettingsFinding]:
        findings: list[InsecureMongoSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureMongoSettingsVisitor(rel, filename)
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
            if _MONGO_NO_AUTH_RE.search(line):
                findings.append(
                    InsecureMongoSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="mongo_no_auth",
                        severity="critical",
                        message="MongoDB URL has no authentication — use credentials and TLS",
                        setting="MONGO_URI",
                    )
                )
            if _MONGO_TLS_FALSE_RE.search(line):
                findings.append(
                    InsecureMongoSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="mongo_tls_disabled",
                        severity="high",
                        message="MongoDB TLS is disabled",
                        setting="MONGO_TLS",
                    )
                )
            if _MONGO_HARDCODED_PASSWORD_RE.search(line):
                findings.append(
                    InsecureMongoSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_mongo_password",
                        severity="critical",
                        message="MongoDB password is hardcoded — load from environment variables",
                        setting="MONGO_PASSWORD",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureMongoSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureMongoSettingsFinding] = []
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
        self._stats = InsecureMongoSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureMongoSettingsStats:
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
            f"Insecure MongoDB settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure MongoDB settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure MongoDB configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
