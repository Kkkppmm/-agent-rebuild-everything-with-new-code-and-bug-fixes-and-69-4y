"""InsecureSentrySettingsAnalyzer — detect insecure Sentry SDK configuration."""

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
        "sentry.py",
        "wsgi.py",
        "asgi.py",
    }
)
_SENTRY_DSN_RE = re.compile(
    r"https?://[a-f0-9]+@[a-z0-9.-]*sentry\.io/\d+",
    re.IGNORECASE,
)
_SEND_DEFAULT_PII_RE = re.compile(
    r"send_default_pii\s*=\s*True",
    re.IGNORECASE,
)
_SENTRY_DEBUG_RE = re.compile(
    r"(sentry_sdk\.init|sentry\.init)\([^)]*debug\s*=\s*True",
    re.IGNORECASE,
)
_FULL_SAMPLE_RATE_RE = re.compile(
    r"(traces_sample_rate|profiles_sample_rate)\s*=\s*1(?:\.0+)?\b",
    re.IGNORECASE,
)
_SENTRY_INIT_RE = re.compile(r"sentry_sdk\.init|sentry\.init", re.IGNORECASE)


@dataclass
class InsecureSentrySettingsFinding:
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
class InsecureSentrySettingsStats:
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


def _is_full_sample_rate(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value) >= 1.0
    return False


class _InsecureSentrySettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureSentrySettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureSentrySettingsFinding(
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
            if isinstance(target, ast.Name) and target.id in {"SENTRY_DSN", "dsn"}:
                value = _dict_string_value(node.value)
                if value and _SENTRY_DSN_RE.search(value):
                    self._add(
                        node.lineno,
                        "hardcoded_sentry_dsn",
                        "high",
                        "Sentry DSN is hardcoded in source — use environment variables",
                        setting="SENTRY_DSN",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name != "init":
            self.generic_visit(node)
            return

        module = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
        if module not in {"sentry_sdk", "sentry"} and func_name == "init":
            if not (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "sdk"
            ):
                self.generic_visit(node)
                return

        for keyword in node.keywords:
            if keyword.arg == "send_default_pii" and _is_true(keyword.value):
                self._add(
                    node.lineno,
                    "send_default_pii_enabled",
                    "high",
                    "send_default_pii=True sends user PII to Sentry — disable in production",
                    setting="send_default_pii",
                )
            elif keyword.arg == "debug" and _is_true(keyword.value):
                self._add(
                    node.lineno,
                    "sentry_debug_enabled",
                    "medium",
                    "Sentry debug mode is enabled — disable in production",
                    setting="debug",
                )
            elif keyword.arg in {"traces_sample_rate", "profiles_sample_rate"} and _is_full_sample_rate(
                keyword.value
            ):
                self._add(
                    node.lineno,
                    "full_sentry_sample_rate",
                    "medium",
                    f"{keyword.arg}=1.0 captures all transactions — lower the rate in production",
                    setting=keyword.arg or "",
                )
            elif keyword.arg == "dsn":
                value = _dict_string_value(keyword.value)
                if value and _SENTRY_DSN_RE.search(value):
                    self._add(
                        node.lineno,
                        "hardcoded_sentry_dsn",
                        "high",
                        "Sentry DSN is hardcoded in sentry_sdk.init — use environment variables",
                        setting="dsn",
                    )

        self.generic_visit(node)


class InsecureSentrySettingsAnalyzer:
    """Detect insecure Sentry SDK configuration in production settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureSentrySettingsFinding] = []
        self._stats: InsecureSentrySettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureSentrySettingsFinding]:
        findings: list[InsecureSentrySettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureSentrySettingsVisitor(rel, filename)
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
            if _SENTRY_DSN_RE.search(line) and (
                "SENTRY_DSN" in line or "dsn=" in line.lower()
            ):
                findings.append(
                    InsecureSentrySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_sentry_dsn",
                        severity="high",
                        message="Sentry DSN is hardcoded in source — use environment variables",
                        setting="SENTRY_DSN",
                    )
                )
            if _SEND_DEFAULT_PII_RE.search(line):
                findings.append(
                    InsecureSentrySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="send_default_pii_enabled",
                        severity="high",
                        message="send_default_pii=True sends user PII to Sentry",
                        setting="send_default_pii",
                    )
                )
            if _SENTRY_DEBUG_RE.search(line):
                findings.append(
                    InsecureSentrySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="sentry_debug_enabled",
                        severity="medium",
                        message="Sentry debug mode is enabled in production settings",
                        setting="debug",
                    )
                )
            if _FULL_SAMPLE_RATE_RE.search(line) and _SENTRY_INIT_RE.search(source):
                findings.append(
                    InsecureSentrySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="full_sentry_sample_rate",
                        severity="medium",
                        message="Full Sentry trace/profile sampling may expose sensitive request data",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureSentrySettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureSentrySettingsFinding] = []
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
        self._stats = InsecureSentrySettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureSentrySettingsStats:
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
            f"Insecure Sentry settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Sentry settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Sentry configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
