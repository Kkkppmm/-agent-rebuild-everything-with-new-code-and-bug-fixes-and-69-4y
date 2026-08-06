"""InsecureAuthSettingsAnalyzer — detect insecure authentication configuration."""

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
    }
)
_WEAK_HASHERS = frozenset(
    {
        "django.contrib.auth.hashers.MD5PasswordHasher",
        "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher",
        "django.contrib.auth.hashers.SHA1PasswordHasher",
        "django.contrib.auth.hashers.UnsaltedSHA1PasswordHasher",
        "MD5PasswordHasher",
        "UnsaltedMD5PasswordHasher",
        "SHA1PasswordHasher",
        "UnsaltedSHA1PasswordHasher",
    }
)
_WEAK_HASHER_RE = re.compile(
    r"PASSWORD_HASHERS\s*=\s*\[[^\]]*(MD5PasswordHasher|UnsaltedMD5PasswordHasher|SHA1PasswordHasher|UnsaltedSHA1PasswordHasher)",
    re.IGNORECASE,
)
_EMPTY_VALIDATORS_RE = re.compile(
    r"AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]",
    re.IGNORECASE,
)
_ALLOW_ALL_BACKEND_RE = re.compile(
    r"AllowAllUsersModelBackend",
    re.IGNORECASE,
)
_LDAP_NO_TLS_RE = re.compile(
    r"AUTH_LDAP_(START_TLS|TLS)\s*=\s*False",
    re.IGNORECASE,
)
_MIN_LENGTH_RE = re.compile(
    r"(MIN_LENGTH|AUTH_PASSWORD_MIN_LENGTH)\s*[=:]\s*([1-7])\b",
    re.IGNORECASE,
)


@dataclass
class InsecureAuthSettingsFinding:
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
class InsecureAuthSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _int_value(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


def _list_string_values(node: ast.AST) -> list[str]:
    if not isinstance(node, ast.List):
        return []
    values: list[str] = []
    for elt in node.elts:
        value = _string_value(elt)
        if value is not None:
            values.append(value)
    return values


def _is_empty_list(node: ast.AST) -> bool:
    return isinstance(node, ast.List) and len(node.elts) == 0


class _InsecureAuthSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureAuthSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureAuthSettingsFinding(
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
            name = target.id
            if name == "PASSWORD_HASHERS":
                hashers = _list_string_values(node.value)
                if hashers and hashers[0] in _WEAK_HASHERS:
                    self._add(
                        node.lineno,
                        "weak_password_hashers",
                        "critical",
                        "Primary password hasher is weak — use Argon2, bcrypt, or PBKDF2 first",
                        setting=name,
                    )
            elif name == "AUTH_PASSWORD_VALIDATORS":
                if _is_empty_list(node.value):
                    self._add(
                        node.lineno,
                        "empty_password_validators",
                        "high",
                        "Password validators are disabled — enable Django auth validators",
                        setting=name,
                    )
            elif name == "AUTHENTICATION_BACKENDS":
                backends = _list_string_values(node.value)
                if any("AllowAllUsersModelBackend" in backend for backend in backends):
                    self._add(
                        node.lineno,
                        "allow_all_users_backend",
                        "critical",
                        "AllowAllUsersModelBackend permits login for inactive users",
                        setting=name,
                    )
            elif name in {"AUTH_LDAP_START_TLS", "AUTH_LDAP_TLS"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "insecure_ldap_auth",
                        "high",
                        "LDAP authentication without TLS exposes credentials on the wire",
                        setting=name,
                    )
            elif name == "AUTH_PASSWORD_MIN_LENGTH":
                min_length = _int_value(node.value)
                if min_length is not None and min_length < 8:
                    self._add(
                        node.lineno,
                        "weak_min_length",
                        "medium",
                        f"Minimum password length {min_length} is below recommended 8 characters",
                        setting=name,
                    )
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        if self.filename not in _PROD_FILENAMES:
            self.generic_visit(node)
            return

        for key, value in zip(node.keys, node.values):
            if key is None:
                continue
            key_name = _string_value(key)
            if key_name == "MIN_LENGTH":
                min_length = _int_value(value)
                if min_length is not None and min_length < 8:
                    self._add(
                        node.lineno,
                        "weak_min_length",
                        "medium",
                        f"Minimum password length {min_length} is below recommended 8 characters",
                        setting="MIN_LENGTH",
                    )
        self.generic_visit(node)


class InsecureAuthSettingsAnalyzer:
    """Detect insecure authentication and password policy configuration."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureAuthSettingsFinding] = []
        self._stats: InsecureAuthSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureAuthSettingsFinding]:
        findings: list[InsecureAuthSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureAuthSettingsVisitor(rel, filename)
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
            if _WEAK_HASHER_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="weak_password_hashers",
                        severity="critical",
                        message="Primary password hasher is weak — use Argon2, bcrypt, or PBKDF2 first",
                        setting="PASSWORD_HASHERS",
                    )
                )
            if _EMPTY_VALIDATORS_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="empty_password_validators",
                        severity="high",
                        message="Password validators are disabled — enable Django auth validators",
                        setting="AUTH_PASSWORD_VALIDATORS",
                    )
                )
            if _ALLOW_ALL_BACKEND_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="allow_all_users_backend",
                        severity="critical",
                        message="AllowAllUsersModelBackend permits login for inactive users",
                        setting="AUTHENTICATION_BACKENDS",
                    )
                )
            if _LDAP_NO_TLS_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="insecure_ldap_auth",
                        severity="high",
                        message="LDAP authentication without TLS exposes credentials on the wire",
                        setting="AUTH_LDAP_START_TLS",
                    )
                )
            match = _MIN_LENGTH_RE.search(line)
            if match:
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="weak_min_length",
                        severity="medium",
                        message=(
                            f"Minimum password length {match.group(2)} is below "
                            "recommended 8 characters"
                        ),
                        setting=match.group(1),
                    )
                )
        return findings

    def analyze(self) -> list[InsecureAuthSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureAuthSettingsFinding] = []
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
        self._stats = InsecureAuthSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureAuthSettingsStats:
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
            f"Insecure auth settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure auth settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure authentication configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
