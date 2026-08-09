"""WeakSecretKeyAnalyzer — detect hardcoded or weak application secret keys."""

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
        "APP_SECRET_KEY",
        "app_secret_key",
        "JWT_SECRET",
        "jwt_secret",
        "SIGNING_KEY",
        "signing_key",
    }
)
_WEAK_VALUE_RE = re.compile(
    r"(?i)(?:django-insecure|changeme|change[-_]?me|dev[-_]?secret|"
    r"test[-_]?secret|your[-_]?secret|super[-_]?secret|not[-_]?secure|"
    r"insecure|placeholder|example|sample|dummy|fake|todo|fixme|"
    r"^secret$|^password$|^12345)"
)
_MIN_SECRET_LENGTH = 32
_SECRET_KEY_ASSIGN_RE = re.compile(
    r"(?:SECRET_KEY|secret_key|APP_SECRET_KEY|JWT_SECRET|SIGNING_KEY)\s*=\s*['\"]([^'\"]+)['\"]"
)


@dataclass
class WeakSecretKeyFinding:
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


def _is_weak_secret(value: str) -> tuple[bool, str, str]:
    if not value:
        return True, "empty_secret_key", "high"
    if _WEAK_VALUE_RE.search(value):
        return True, "weak_secret_key_value", "high"
    if len(value) < _MIN_SECRET_LENGTH:
        return True, "short_secret_key", "high"
    if value.isascii() and value.isalnum() and len(value) < 48:
        return True, "low_entropy_secret_key", "medium"
    return False, "", ""


class _WeakSecretKeyVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[WeakSecretKeyFinding] = []

    def _check_assignment(self, name: str, value_node: ast.AST, lineno: int) -> None:
        if name not in _SECRET_KEY_NAMES:
            return
        value = _string_value(value_node)
        if value is None:
            return
        is_weak, pattern, severity = _is_weak_secret(value)
        if not is_weak:
            return
        messages = {
            "empty_secret_key": "Empty secret key — load from environment variables",
            "short_secret_key": (
                f"Secret key is shorter than {_MIN_SECRET_LENGTH} characters — "
                "use a cryptographically random value"
            ),
            "weak_secret_key_value": (
                "Secret key uses a known weak or placeholder value — "
                "generate a random key and store it in environment variables"
            ),
            "low_entropy_secret_key": (
                "Secret key appears low-entropy — use secrets.token_urlsafe(32) or similar"
            ),
        }
        self.findings.append(
            WeakSecretKeyFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=messages[pattern],
                setting=name,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._check_assignment(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._check_assignment(node.target.id, node.value, node.lineno)
        self.generic_visit(node)


class WeakSecretKeyAnalyzer:
    """Detect hardcoded or weak SECRET_KEY / secret_key settings."""

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
            match = _SECRET_KEY_ASSIGN_RE.search(line)
            if not match:
                continue
            value = match.group(1)
            is_weak, pattern, severity = _is_weak_secret(value)
            if not is_weak:
                continue
            messages = {
                "empty_secret_key": "Empty secret key — load from environment variables",
                "short_secret_key": (
                    f"Secret key is shorter than {_MIN_SECRET_LENGTH} characters — "
                    "use a cryptographically random value"
                ),
                "weak_secret_key_value": (
                    "Secret key uses a known weak or placeholder value — "
                    "generate a random key and store it in environment variables"
                ),
                "low_entropy_secret_key": (
                    "Secret key appears low-entropy — use secrets.token_urlsafe(32) or similar"
                ),
            }
            findings.append(
                WeakSecretKeyFinding(
                    path=rel,
                    lineno=lineno,
                    pattern=pattern,
                    severity=severity,
                    message=messages[pattern],
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
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
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
            lines.append("No weak or hardcoded secret keys found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
