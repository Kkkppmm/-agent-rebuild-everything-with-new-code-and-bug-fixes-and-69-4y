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
        "auth.py",
        "jwt.py",
    }
)
_HARDCODED_JWT_SECRET_RE = re.compile(
    r"(?:JWT_SECRET(?:_KEY)?|SIGNING_KEY)\s*=\s*['\"][^'\"]{8,}['\"]|"
    r"SIMPLE_JWT\s*=\s*\{[^}]*['\"]SIGNING_KEY['\"]\s*:\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE | re.DOTALL,
)
_NONE_ALGORITHM_RE = re.compile(
    r"['\"]alg['\"]\s*:\s*['\"]none['\"]|algorithm\s*=\s*['\"]none['\"]|ALGORITHMS\s*=\s*\[[^\]]*['\"]none['\"]",
    re.IGNORECASE,
)
_VERIFY_DISABLED_RE = re.compile(
    r"(JWT_VERIFY|VERIFY_SIGNATURE|verify_signature)\s*=\s*False|"
    r"['\"]verify_signature['\"]\s*:\s*False",
    re.IGNORECASE,
)
_LONG_EXPIRY_RE = re.compile(
    r"(JWT_EXPIRATION|ACCESS_TOKEN_LIFETIME|JWT_ACCESS_TOKEN_EXPIRES)\s*=\s*(timedelta\([^)]*\d{3,}|"
    r"\d{6,}|86400\s*\*\s*\d{2,})",
    re.IGNORECASE,
)
_QUERY_STRING_TOKEN_RE = re.compile(
    r"request\.GET\.get\(['\"]token['\"]\)|request\.args\.get\(['\"]token['\"]\)|"
    r"request\.query_params\.get\(['\"]token['\"]\)|\?token=|token\s*=\s*request\.GET",
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


_JWT_SECRET_NAMES = frozenset(
    {
        "JWT_SECRET",
        "JWT_SECRET_KEY",
        "JWT_SIGNING_KEY",
        "SIGNING_KEY",
    }
)
_VERIFY_NAMES = frozenset({"JWT_VERIFY", "VERIFY_SIGNATURE", "verify_signature"})


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_hardcoded_secret(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) >= 8 and not node.value.startswith("${")
    return False


def _contains_none_algorithm(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower() == "none"
    if isinstance(node, ast.List):
        return any(
            isinstance(elt, ast.Constant) and isinstance(elt.value, str) and elt.value.lower() == "none"
            for elt in node.elts
        )
    if isinstance(node, ast.Dict):
        for key, val in zip(node.keys, node.values):
            if (
                key
                and isinstance(key, ast.Constant)
                and str(key.value).lower() == "alg"
                and isinstance(val, ast.Constant)
                and isinstance(val.value, str)
                and val.value.lower() == "none"
            ):
                return True
    return False


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
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            upper = name.upper()
            if upper in _JWT_SECRET_NAMES and _is_hardcoded_secret(node.value):
                self._add(
                    node.lineno,
                    "hardcoded_jwt_secret",
                    "critical",
                    f"{name} is hardcoded — load JWT signing key from environment",
                    setting=name,
                )
            if upper in _VERIFY_NAMES and _is_false(node.value):
                self._add(
                    node.lineno,
                    "jwt_verify_disabled",
                    "critical",
                    f"{name} is False — JWT signature verification is disabled",
                    setting=name,
                )
            if upper in {"JWT_ALGORITHM", "ALGORITHM"} and _contains_none_algorithm(node.value):
                self._add(
                    node.lineno,
                    "none_jwt_algorithm",
                    "critical",
                    f"{name} allows 'none' algorithm — reject unsigned tokens",
                    setting=name,
                )
            if upper == "SIMPLE_JWT" and isinstance(node.value, ast.Dict):
                self._scan_simple_jwt(node)
        self.generic_visit(node)

    def _scan_simple_jwt(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Dict):
            return
        for key, val in zip(node.value.keys, node.value.values):
            if not key or not isinstance(key, ast.Constant):
                continue
            key_str = str(key.value).upper()
            if key_str == "SIGNING_KEY" and _is_hardcoded_secret(val):
                self._add(
                    node.lineno,
                    "hardcoded_jwt_secret",
                    "critical",
                    "SIMPLE_JWT SIGNING_KEY is hardcoded — load from environment",
                    setting="SIMPLE_JWT",
                )
            if key_str == "ALGORITHM" and _contains_none_algorithm(val):
                self._add(
                    node.lineno,
                    "none_jwt_algorithm",
                    "critical",
                    "SIMPLE_JWT ALGORITHM allows 'none' — use HS256 or RS256",
                    setting="SIMPLE_JWT",
                )
            if key_str in {"VERIFY", "VERIFY_SIGNATURE"} and _is_false(val):
                self._add(
                    node.lineno,
                    "jwt_verify_disabled",
                    "critical",
                    "SIMPLE_JWT signature verification is disabled",
                    setting="SIMPLE_JWT",
                )

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name):
            if node.value.value.id in {"request", "req"} and isinstance(node.slice, ast.Constant):
                key = node.slice.value
                if isinstance(key, str) and key.lower() in {"token", "jwt", "access_token"}:
                    self._add(
                        node.lineno,
                        "jwt_in_query_string",
                        "high",
                        "JWT token read from query string — use Authorization header instead",
                        setting="query_string",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            if isinstance(node.func.value, ast.Attribute):
                base = node.func.value
                if (
                    isinstance(base.value, ast.Name)
                    and base.value.id in {"request", "req"}
                    and base.attr in {"GET", "args", "query_params"}
                ):
                    if node.args and isinstance(node.args[0], ast.Constant):
                        arg = node.args[0].value
                        if isinstance(arg, str) and arg.lower() in {"token", "jwt", "access_token"}:
                            self._add(
                                node.lineno,
                                "jwt_in_query_string",
                                "high",
                                "JWT token read from query string — use Authorization header",
                                setting="query_string",
                            )
        self.generic_visit(node)


class InsecureJwtSettingsAnalyzer:
    """Detect insecure JWT configuration in Django REST/SimpleJWT and similar apps."""

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

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _HARDCODED_JWT_SECRET_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_jwt_secret",
                        severity="critical",
                        message="JWT signing key is hardcoded — load from environment",
                        setting="JWT_SECRET",
                    )
                )
            if _NONE_ALGORITHM_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="none_jwt_algorithm",
                        severity="critical",
                        message="JWT 'none' algorithm allowed — reject unsigned tokens",
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
                        message="JWT signature verification is disabled",
                        setting="JWT_VERIFY",
                    )
                )
            if _LONG_EXPIRY_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="long_jwt_expiry",
                        severity="medium",
                        message="JWT access token expiry is excessively long — use short-lived tokens",
                        setting="JWT_EXPIRATION",
                    )
                )
            if _QUERY_STRING_TOKEN_RE.search(line):
                findings.append(
                    InsecureJwtSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="jwt_in_query_string",
                        severity="high",
                        message="JWT token passed in query string — use Authorization header",
                        setting="query_string",
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
