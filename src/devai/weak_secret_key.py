"""WeakSecretKeyAnalyzer — detect hardcoded and weak SECRET_KEY values."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SECRET_KEY_NAMES = frozenset(
    {
        "SECRET_KEY",
        "secret_key",
        "DJANGO_SECRET_KEY",
        "django_secret_key",
        "APP_SECRET",
        "app_secret",
        "SIGNING_KEY",
        "signing_key",
        "SESSION_SECRET",
        "session_secret",
    }
)
_WEAK_LITERALS = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "change_me",
        "secret",
        "password",
        "passwd",
        "test",
        "testing",
        "dev",
        "development",
        "localhost",
        "default",
        "12345",
        "123456",
        "admin",
        "root",
        "django-insecure",
    }
)
_ENV_ATTRS = frozenset({"get", "getenv", "environ"})
_HARDCODED_PATTERN = re.compile(
    r"(?:SECRET_KEY|secret_key|DJANGO_SECRET_KEY|APP_SECRET|signing_key)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)


@dataclass
class WeakSecretKeyFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    setting: str = ""
    value: str = ""

    def format(self) -> str:
        setting = f" ({self.setting})" if self.setting else ""
        preview = ""
        if self.value:
            preview = f" ({self.value[:20]!r}{'...' if len(self.value) > 20 else ''})"
        return f"{self.path}:{self.lineno}{setting} [{self.severity}] {self.pattern}{preview}: {self.message}"


@dataclass
class WeakSecretKeyStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_env_lookup(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _ENV_ATTRS:
            return True
        if isinstance(func, ast.Name) and func.id == "getenv":
            return True
    if isinstance(node, ast.Subscript):
        value = node.value
        if isinstance(value, ast.Attribute) and value.attr == "environ":
            return True
    return False


def _classify_secret_value(value: str) -> tuple[str, str, str] | None:
    stripped = value.strip()
    lower = stripped.lower()
    if not stripped:
        return ("empty_secret_key", "critical", "Empty secret key — use a cryptographically random value")
    if lower in _WEAK_LITERALS or lower.startswith("django-insecure"):
        return (
            "weak_secret_literal",
            "critical",
            "Known weak secret key — generate a random key and store in environment",
        )
    if len(stripped) < 32:
        return (
            "short_secret_key",
            "high",
            "Secret key is too short — use at least 32 random characters",
        )
    if re.fullmatch(r"[a-zA-Z0-9_-]+", stripped) and len(set(stripped)) < 8:
        return (
            "low_entropy_secret",
            "high",
            "Secret key has low entropy — use secrets.token_urlsafe() or similar",
        )
    return None


class _WeakSecretKeyVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakSecretKeyFinding] = []

    def _add_finding(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
        value: str = "",
    ) -> None:
        self.findings.append(
            WeakSecretKeyFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                setting=setting,
                value=value,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _SECRET_KEY_NAMES:
                if _is_env_lookup(node.value):
                    self.generic_visit(node)
                    continue
                value = _string_value(node.value)
                if value is not None:
                    classified = _classify_secret_value(value)
                    if classified:
                        pattern, severity, message = classified
                        self._add_finding(
                            node.lineno,
                            pattern,
                            severity,
                            message,
                            setting=target.id,
                            value=value,
                        )
                    else:
                        self._add_finding(
                            node.lineno,
                            "hardcoded_secret_key",
                            "high",
                            "Hardcoded secret key — load from environment variable",
                            setting=target.id,
                            value=value,
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _ENV_ATTRS:
            if node.args:
                default = _string_value(node.args[-1]) if len(node.args) >= 2 else None
                if default is None and node.keywords:
                    for kw in node.keywords:
                        if kw.arg == "default":
                            default = _string_value(kw.value)
                if default is not None:
                    key_name = ""
                    first = node.args[0] if node.args else None
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        key_name = first.value
                    if any(name.lower() in key_name.lower() for name in _SECRET_KEY_NAMES) or "secret" in key_name.lower():
                        classified = _classify_secret_value(default)
                        if classified:
                            pattern, severity, message = classified
                            self._add_finding(
                                node.lineno,
                                f"weak_env_default_{pattern}",
                                severity,
                                f"Weak default for secret env var: {message}",
                                setting=key_name,
                                value=default,
                            )
        self.generic_visit(node)


class WeakSecretKeyAnalyzer:
    """Detect hardcoded and weak SECRET_KEY / signing key configuration."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[WeakSecretKeyFinding] = []
        self._stats: WeakSecretKeyStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[WeakSecretKeyFinding]:
        findings: list[WeakSecretKeyFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _WeakSecretKeyVisitor(rel)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _HARDCODED_PATTERN.search(line):
                if not any(f.lineno == lineno for f in findings):
                    findings.append(
                        WeakSecretKeyFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="hardcoded_secret_key",
                            severity="high",
                            message="Hardcoded secret key — load from environment variable",
                        )
                    )
        return findings

    def analyze(self) -> list[WeakSecretKeyFinding]:
        if self._findings:
            return self._findings

        findings: list[WeakSecretKeyFinding] = []
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
        self._stats = WeakSecretKeyStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> WeakSecretKeyStats:
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
            f"Weak secret keys: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Weak secret key analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No hardcoded or weak secret keys found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
