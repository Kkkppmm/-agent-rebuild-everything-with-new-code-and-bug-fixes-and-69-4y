"""InsecureSentrySettingsAnalyzer — detect insecure Sentry error tracking configuration."""

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
        "monitoring.py",
    }
)
_SENTRY_DSN_RE = re.compile(
    r"(SENTRY_DSN|sentry_sdk\.init)\s*[=(:]\s*['\"]https?://[^'\"]+@[^'\"]+['\"]",
    re.IGNORECASE,
)
_HARDCODED_DSN_RE = re.compile(
    r"SENTRY_DSN\s*=\s*['\"]https?://[^'\"]+@[^'\"]+['\"]",
    re.IGNORECASE,
)


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


def _float_value(node: ast.AST) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    return None


def _is_sentry_dsn(value: str) -> bool:
    return "@" in value and ("sentry.io" in value or value.startswith("https://"))


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
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id.upper()
            if name == "SENTRY_DSN":
                value = _string_value(node.value)
                if value is not None and _is_sentry_dsn(value):
                    self._add(
                        node.lineno,
                        "hardcoded_sentry_dsn",
                        "critical",
                        f"{target.id} is hardcoded — load Sentry DSN from environment variables",
                        setting=target.id,
                    )
            elif name == "SENTRY_ENVIRONMENT":
                value = _string_value(node.value)
                if value is not None and value.lower() in {"development", "dev", "local"}:
                    self._add(
                        node.lineno,
                        "sentry_dev_environment",
                        "medium",
                        f"{target.id} is '{value}' in production settings — use 'production'",
                        setting=target.id,
                    )
            elif name in {"SENTRY_SEND_DEFAULT_PII", "SEND_DEFAULT_PII"}:
                if _bool_value(node.value) is True:
                    self._add(
                        node.lineno,
                        "sentry_pii_enabled",
                        "high",
                        f"{target.id} is True — disable PII collection to protect user privacy",
                        setting=target.id,
                    )
            elif name == "SENTRY_TRACES_SAMPLE_RATE":
                rate = _float_value(node.value)
                if rate is not None and rate >= 1.0:
                    self._add(
                        node.lineno,
                        "sentry_full_tracing",
                        "medium",
                        f"{target.id} is {rate} — reduce sample rate to control cost and data volume",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureSentrySettingsAnalyzer:
    """Detect insecure Sentry error tracking configuration."""

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
            if _HARDCODED_DSN_RE.search(line):
                findings.append(
                    InsecureSentrySettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_sentry_dsn",
                        severity="critical",
                        message="Sentry DSN is hardcoded — load from environment variables",
                        setting="SENTRY_DSN",
                    )
                )
            if _SENTRY_DSN_RE.search(line) and "os.environ" not in line:
                if not any(f.lineno == lineno for f in findings):
                    findings.append(
                        InsecureSentrySettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="hardcoded_sentry_dsn",
                            severity="critical",
                            message="Sentry DSN appears hardcoded — use environment variables",
                            setting="SENTRY_DSN",
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
