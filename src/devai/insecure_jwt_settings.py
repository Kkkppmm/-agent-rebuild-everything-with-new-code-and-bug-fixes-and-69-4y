"""InsecureJwtSettingsAnalyzer — detect insecure JWT configuration in settings files."""

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
        "jwt.py",
        "auth.py",
    }
)
_JWT_SETTING_NAMES = frozenset(
    {
        "JWT_SECRET_KEY",
        "JWT_SIGNING_KEY",
        "SIGNING_KEY",
        "SIMPLE_JWT",
        "JWT_ALGORITHM",
        "JWT_VERIFY",
        "JWT_DECODE_VERIFY_SIGNATURE",
        "JWT_VERIFY_SIGNATURE",
        "JWT_EXPIRATION_DELTA",
        "ACCESS_TOKEN_LIFETIME",
        "REFRESH_TOKEN_LIFETIME",
    }
)
_NONE_ALGORITHM_RE = re.compile(
    r"(JWT_ALGORITHM|algorithm)\s*=\s*['\"]none['\"]",
    re.IGNORECASE,
)
_VERIFY_DISABLED_RE = re.compile(
    r"(JWT_VERIFY|JWT_DECODE_VERIFY_SIGNATURE|JWT_VERIFY_SIGNATURE|verify_signature)\s*=\s*False",
    re.IGNORECASE,
)
_HARDCODED_SECRET_RE = re.compile(
    r"(JWT_SECRET_KEY|JWT_SIGNING_KEY|SIGNING_KEY)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_LONG_LIFETIME_RE = re.compile(
    r"(ACCESS_TOKEN_LIFETIME|REFRESH_TOKEN_LIFETIME|JWT_EXPIRATION_DELTA)\s*=\s*timedelta\(\s*days\s*=\s*(\d+)",
    re.IGNORECASE,
)


@dataclass
class InsecureJwtSettingsFinding:
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
class InsecureJwtSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _timedelta_days(node: ast.AST) -> int | None:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name) and func.id == "timedelta":
        for kw in node.keywords:
            if kw.arg == "days" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                return kw.value.value
    return None


class _InsecureJwtSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureJwtSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureJwtSettingsFinding(
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
            if isinstance(target, ast.Name) and target.id in _JWT_SETTING_NAMES:
                self._check_setting(target.id, node.value, node.lineno)
        self.generic_visit(node)

    def _check_setting(self, name: str, value_node: ast.AST, lineno: int) -> None:
        if name in {"JWT_ALGORITHM"}:
            algorithm = _dict_string_value(value_node)
            if algorithm and algorithm.lower() == "none":
                self._add(
                    lineno,
                    "jwt_algorithm_none",
                    "critical",
                    "JWT algorithm 'none' disables signature verification — use HS256 or RS256",
                    setting=name,
                )
            return

        if name in {"JWT_VERIFY", "JWT_DECODE_VERIFY_SIGNATURE", "JWT_VERIFY_SIGNATURE"}:
            verify = _bool_value(value_node)
            if verify is False:
                self._add(
                    lineno,
                    "jwt_verify_disabled",
                    "critical",
                    "JWT signature verification is disabled — always verify signatures",
                    setting=name,
                )
            return

        if name in {"JWT_SECRET_KEY", "JWT_SIGNING_KEY", "SIGNING_KEY"}:
            secret = _dict_string_value(value_node)
            if secret and len(secret) >= 8 and not secret.startswith("os.environ"):
                self._add(
                    lineno,
                    "hardcoded_jwt_secret",
                    "critical",
                    "Hardcoded JWT secret in settings — use environment variables",
                    setting=name,
                )
            return

        if name in {"ACCESS_TOKEN_LIFETIME", "REFRESH_TOKEN_LIFETIME", "JWT_EXPIRATION_DELTA"}:
            days = _timedelta_days(value_node)
            if days is not None and days > 30:
                self._add(
                    lineno,
                    "jwt_long_expiration",
                    "medium",
                    f"JWT token lifetime of {days} days is excessive — use shorter expirations",
                    setting=name,
                )


class InsecureJwtSettingsAnalyzer:
    """Detect insecure JWT configuration in Django and application settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureJwtSettingsFinding] = []
        self._stats: InsecureJwtSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureJwtSettingsFinding]:
        findings: list[InsecureJwtSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureJwtSettingsVisitor(rel, filename)
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
            if _NONE_ALGORITHM_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_algorithm_none",
                        severity="critical",
                        message="JWT algorithm 'none' disables signature verification — use HS256 or RS256",
                        setting="JWT_ALGORITHM",
                    )
                )
            if _VERIFY_DISABLED_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_verify_disabled",
                        severity="critical",
                        message="JWT signature verification is disabled — always verify signatures",
                        setting="JWT_VERIFY",
                    )
                )
            if _HARDCODED_SECRET_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_jwt_secret",
                        severity="critical",
                        message="Hardcoded JWT secret in settings — use environment variables",
                        setting="JWT_SECRET_KEY",
                    )
                )
            match = _LONG_LIFETIME_RE.search(line)
            if match and int(match.group(2)) > 30:
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_long_expiration",
                        severity="medium",
                        message=f"JWT token lifetime of {match.group(2)} days is excessive",
                        setting=match.group(1),
                    )
                )
        return findings

    def analyze(self) -> list[InsecureJwtSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureJwtSettingsFinding] = []
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
        self._stats = InsecureJwtSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureJwtSettingsStats:
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
            f"Insecure JWT settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure JWT settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure JWT configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
