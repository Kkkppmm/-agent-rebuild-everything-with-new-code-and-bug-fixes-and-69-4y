"""InsecureJwtSettingsAnalyzer — detect insecure JWT configuration and usage."""

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
        "jwt.py",
        "auth.py",
        "authentication.py",
    }
)
_AUTH_FILENAMES = frozenset(
    {
        "views.py",
        "auth.py",
        "authentication.py",
        "middleware.py",
        "tokens.py",
        "utils.py",
    }
)
_HARDCODED_SECRET_RE = re.compile(
    r"(JWT_SECRET|JWT_SIGNING_KEY|JWT_PRIVATE_KEY|JWT_KEY|"
    r"SIMPLE_JWT.*SIGNING_KEY|ACCESS_TOKEN_SECRET|REFRESH_TOKEN_SECRET)\s*"
    r"[:=]\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_NONE_ALGORITHM_RE = re.compile(
    r"(JWT_ALGORITHM|ALGORITHM|algorithms)\s*[:=]\s*['\"]none['\"]|"
    r"algorithms\s*=\s*\[\s*['\"]none['\"]",
    re.IGNORECASE,
)
_SKIP_VERIFY_RE = re.compile(
    r"(verify\s*=\s*False|verify_signature\s*=\s*False|"
    r"['\"]verify_signature['\"]\s*:\s*False|options\s*=\s*\{[^}]*verify[^}]*False)",
    re.IGNORECASE,
)
_LONG_EXPIRY_RE = re.compile(
    r"(ACCESS_TOKEN_LIFETIME|JWT_EXPIRATION|TOKEN_LIFETIME)\s*[:=].*"
    r"(days\s*=\s*[3-9]\d+|[1-9]\d{3,}|hours\s*=\s*[4-9]\d+)",
    re.IGNORECASE,
)
_ROTATE_DISABLED_RE = re.compile(
    r"ROTATE_REFRESH_TOKENS\s*[:=]\s*(False|0|['\"]0['\"])",
    re.IGNORECASE,
)
_JWT_IN_QUERY_RE = re.compile(
    r"(request\.GET|request\.query_params|request\.args)\s*\.get\s*\(\s*['\"]token['\"]|"
    r"['\"]token['\"]\s*:\s*request\.(GET|query_params|args)",
    re.IGNORECASE,
)
_WEAK_HS256_RE = re.compile(
    r"SIGNING_KEY\s*[:=]\s*['\"][^'\"]{1,15}['\"]",
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


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_hardcoded_secret(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) >= 8 and not node.value.startswith(("os.", "env", "${"))
    return False


def _is_jwt_secret_name(name: str) -> bool:
    upper = name.upper()
    if upper in {
        "JWT_SECRET",
        "JWT_SIGNING_KEY",
        "JWT_PRIVATE_KEY",
        "JWT_KEY",
        "ACCESS_TOKEN_SECRET",
        "REFRESH_TOKEN_SECRET",
        "SIGNING_KEY",
    }:
        return True
    if upper.startswith("JWT_") and upper.endswith("_SECRET"):
        return True
    return False


def _is_none_algorithm(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower() == "none"
    if isinstance(node, ast.List):
        return any(
            isinstance(elt, ast.Constant)
            and isinstance(elt.value, str)
            and elt.value.lower() == "none"
            for elt in node.elts
        )
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
        if self.filename in _SETTINGS_FILENAMES:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if _is_jwt_secret_name(name) and _is_hardcoded_secret(node.value):
                        self._add(
                            node.lineno,
                            "hardcoded_jwt_secret",
                            "critical",
                            f"{name} is hardcoded — load JWT signing keys from environment variables",
                            setting=name,
                        )
                    elif name.upper() in {"JWT_ALGORITHM", "ALGORITHM"} and _is_none_algorithm(
                        node.value
                    ):
                        self._add(
                            node.lineno,
                            "none_jwt_algorithm",
                            "critical",
                            f"{name} uses 'none' — this allows unsigned JWT forgery",
                            setting=name,
                        )
                    elif name.upper() == "ROTATE_REFRESH_TOKENS" and (
                        _is_false(node.value) or _is_none(node.value)
                    ):
                        self._add(
                            node.lineno,
                            "disabled_token_rotation",
                            "medium",
                            f"{name} is disabled — enable refresh token rotation to limit replay risk",
                            setting=name,
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in {"decode", "decode_jwt", "verify_jwt"}:
            for keyword in node.keywords:
                if keyword.arg == "verify" and (_is_false(keyword.value) or _is_none(keyword.value)):
                    self._add(
                        node.lineno,
                        "skip_jwt_verification",
                        "critical",
                        f"{func_name}() called with verify=False — always verify JWT signatures",
                        setting=f"{func_name}.verify",
                    )
                if keyword.arg == "options" and isinstance(keyword.value, ast.Dict):
                    for key, value in zip(keyword.value.keys, keyword.value.values):
                        if (
                            isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            and "verify" in key.value.lower()
                            and _is_false(value)
                        ):
                            self._add(
                                node.lineno,
                                "skip_jwt_verification",
                                "critical",
                                f"{func_name}() disables signature verification via options",
                                setting=f"{func_name}.options",
                            )
                if keyword.arg == "algorithms" and _is_none_algorithm(keyword.value):
                    self._add(
                        node.lineno,
                        "none_jwt_algorithm",
                        "critical",
                        f"{func_name}() accepts 'none' algorithm — reject unsigned tokens",
                        setting=f"{func_name}.algorithms",
                    )
        self.generic_visit(node)


class InsecureJwtSettingsAnalyzer:
    """Detect hardcoded JWT secrets, disabled verification, and weak token configuration."""

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

            if filename in _SETTINGS_FILENAMES:
                if _HARDCODED_SECRET_RE.search(line):
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="hardcoded_jwt_secret",
                            severity="critical",
                            message="JWT signing key is hardcoded — use environment variables",
                        )
                    )
                if _NONE_ALGORITHM_RE.search(line):
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="none_jwt_algorithm",
                            severity="critical",
                            message="JWT algorithm 'none' allows unsigned token forgery",
                        )
                    )
                if _LONG_EXPIRY_RE.search(line):
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="long_jwt_expiry",
                            severity="medium",
                            message="JWT access token lifetime is excessively long",
                        )
                    )
                if _ROTATE_DISABLED_RE.search(line):
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="disabled_token_rotation",
                            severity="medium",
                            message="Refresh token rotation is disabled",
                        )
                    )
                if _WEAK_HS256_RE.search(line) and "SIGNING_KEY" in line.upper():
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="weak_signing_key",
                            severity="high",
                            message="JWT signing key is too short — use at least 256 bits of entropy",
                        )
                    )

            if filename in _AUTH_FILENAMES:
                if _SKIP_VERIFY_RE.search(line):
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="skip_jwt_verification",
                            severity="critical",
                            message="JWT signature verification is disabled",
                        )
                    )
                if _JWT_IN_QUERY_RE.search(line):
                    findings.append(
                        InsecureJwtSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="jwt_in_query_string",
                            severity="high",
                            message="JWT read from query string — tokens in URLs leak via logs and referrers",
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
