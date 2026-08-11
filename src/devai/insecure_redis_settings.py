"""InsecureRedisSettingsAnalyzer — detect insecure Redis configuration."""

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
        "redis.py",
        "cache.py",
        "celery.py",
    }
)
_REDIS_NO_AUTH_RE = re.compile(
    r"redis://(?!.*:.*@)[^\s\"']+",
    re.IGNORECASE,
)
_REDIS_HTTP_RE = re.compile(
    r"(REDIS_URL|CELERY_BROKER_URL|BROKER_URL)\s*=\s*['\"]redis://",
    re.IGNORECASE,
)
_REDIS_SSL_FALSE_RE = re.compile(
    r"(REDIS_SSL|REDIS_USE_SSL|REDIS_SSL_CERT_REQS)\s*=\s*(False|None|['\"]none['\"])",
    re.IGNORECASE,
)
_REDIS_HARDCODED_PASSWORD_RE = re.compile(
    r"(REDIS_PASSWORD|REDIS_PASS)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)


@dataclass
class InsecureRedisSettingsFinding:
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
class InsecureRedisSettingsStats:
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


def _redis_url_insecure(value: str) -> bool:
    lower = value.lower()
    if not lower.startswith("redis://") and not lower.startswith("rediss://"):
        return False
    if lower.startswith("rediss://"):
        return False
    return bool(_REDIS_NO_AUTH_RE.search(value))


class _InsecureRedisSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureRedisSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureRedisSettingsFinding(
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
            if name in {"REDIS_URL", "CELERY_BROKER_URL", "BROKER_URL", "REDIS_HOST"}:
                value = _string_value(node.value)
                if value and _redis_url_insecure(value):
                    self._add(
                        node.lineno,
                        "redis_no_auth",
                        "critical",
                        f"{target.id} has no authentication — use a password and TLS (rediss://)",
                        setting=target.id,
                    )
            elif name in {"REDIS_SSL", "REDIS_USE_SSL"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "redis_ssl_disabled",
                        "high",
                        f"{target.id} is False — enable TLS for Redis connections",
                        setting=target.id,
                    )
            elif name == "REDIS_SSL_CERT_REQS":
                value = _string_value(node.value)
                if value is not None and value.lower() in {"none", "optional", "optional_ca"}:
                    self._add(
                        node.lineno,
                        "redis_ssl_verify_disabled",
                        "high",
                        f"{target.id} weakens TLS verification — use 'required'",
                        setting=target.id,
                    )
            elif name in {"REDIS_PASSWORD", "REDIS_PASS"}:
                value = _string_value(node.value)
                if value is not None and len(value) >= 4:
                    self._add(
                        node.lineno,
                        "hardcoded_redis_password",
                        "critical",
                        f"{target.id} is hardcoded — load Redis credentials from environment",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureRedisSettingsAnalyzer:
    """Detect insecure Redis configuration in Django, Celery, and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureRedisSettingsFinding] = []
        self._stats: InsecureRedisSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureRedisSettingsFinding]:
        findings: list[InsecureRedisSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureRedisSettingsVisitor(rel, filename)
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
            if _REDIS_NO_AUTH_RE.search(line):
                findings.append(
                    InsecureRedisSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="redis_no_auth",
                        severity="critical",
                        message="Redis URL has no authentication — use a password and TLS",
                        setting="REDIS_URL",
                    )
                )
            if _REDIS_SSL_FALSE_RE.search(line):
                findings.append(
                    InsecureRedisSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="redis_ssl_disabled",
                        severity="high",
                        message="Redis TLS is disabled or verification weakened",
                        setting="REDIS_SSL",
                    )
                )
            if _REDIS_HARDCODED_PASSWORD_RE.search(line):
                findings.append(
                    InsecureRedisSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_redis_password",
                        severity="critical",
                        message="Redis password is hardcoded — load from environment variables",
                        setting="REDIS_PASSWORD",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureRedisSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureRedisSettingsFinding] = []
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
        self._stats = InsecureRedisSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureRedisSettingsStats:
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
            f"Insecure Redis settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Redis settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Redis configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
