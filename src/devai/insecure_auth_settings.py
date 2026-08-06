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
_WEAK_HASHER_RE = re.compile(
    r"(MD5PasswordHasher|SHA1PasswordHasher|UnsaltedMD5PasswordHasher|"
    r"UnsaltedSHA1PasswordHasher|CryptPasswordHasher)",
    re.IGNORECASE,
)
_ALLOW_ALL_BACKEND_RE = re.compile(
    r"AllowAllUsersModelBackend",
    re.IGNORECASE,
)
_LDAP_NO_TLS_RE = re.compile(
    r"ldap://|AUTH_LDAP_SERVER_URI\s*=\s*['\"]ldap://",
    re.IGNORECASE,
)
_LDAP_TLS_FALSE_RE = re.compile(
    r"AUTH_LDAP_(?:START_TLS|CONNECTION_OPTIONS|USE_TLS)\s*=\s*False\b",
    re.IGNORECASE,
)
_WEAK_HASHERS_ASSIGN_RE = re.compile(
    r"PASSWORD_HASHERS\s*=\s*\[[^\]]*(?:MD5|SHA1|Unsalted|Crypt)PasswordHasher",
    re.IGNORECASE,
)
_EMPTY_VALIDATORS_RE = re.compile(
    r"AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]",
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


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.NameConstant):  # noqa: SIM114 — py310 compat
        return node.value
    return None


def _is_weak_hasher(value: str) -> bool:
    return bool(_WEAK_HASHER_RE.search(value))


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
            if name == "PASSWORD_HASHERS" and isinstance(node.value, ast.List):
                self._scan_password_hashers(node.value)
            elif name == "AUTH_PASSWORD_VALIDATORS" and isinstance(node.value, ast.List):
                if len(node.value.elts) == 0:
                    self._add(
                        node.lineno,
                        "empty_password_validators",
                        "high",
                        "AUTH_PASSWORD_VALIDATORS is empty — passwords are not validated",
                        setting="AUTH_PASSWORD_VALIDATORS",
                    )
            elif name == "AUTHENTICATION_BACKENDS" and isinstance(node.value, ast.List):
                self._scan_auth_backends(node.value)
            elif name == "AUTH_LDAP_SERVER_URI":
                value = _dict_string_value(node.value)
                if value and value.lower().startswith("ldap://"):
                    self._add(
                        node.lineno,
                        "ldap_without_tls",
                        "high",
                        "LDAP server URI uses unencrypted ldap:// — use ldaps:// or enable START_TLS",
                        setting="AUTH_LDAP_SERVER_URI",
                    )
            elif name in {"AUTH_LDAP_START_TLS", "AUTH_LDAP_USE_TLS"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "ldap_without_tls",
                        "high",
                        f"{name}=False disables TLS for LDAP authentication",
                        setting=name,
                    )
        self.generic_visit(node)

    def _scan_password_hashers(self, node: ast.List) -> None:
        for element in node.elts:
            value = _dict_string_value(element)
            if value and _is_weak_hasher(value):
                self._add(
                    node.lineno,
                    "weak_password_hasher",
                    "high",
                    f"PASSWORD_HASHERS includes weak hasher '{value}' — use Argon2 or PBKDF2",
                    setting="PASSWORD_HASHERS",
                )

    def _scan_auth_backends(self, node: ast.List) -> None:
        for element in node.elts:
            value = _dict_string_value(element)
            if value and _ALLOW_ALL_BACKEND_RE.search(value):
                self._add(
                    node.lineno,
                    "allow_all_users_backend",
                    "critical",
                    "AllowAllUsersModelBackend bypasses password authentication",
                    setting="AUTHENTICATION_BACKENDS",
                )


class InsecureAuthSettingsAnalyzer:
    """Detect insecure authentication configuration in Django and similar apps."""

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
            if _WEAK_HASHERS_ASSIGN_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="weak_password_hasher",
                        severity="high",
                        message="PASSWORD_HASHERS includes weak hash algorithm — use Argon2 or PBKDF2",
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
                        message="AUTH_PASSWORD_VALIDATORS is empty — passwords are not validated",
                        setting="AUTH_PASSWORD_VALIDATORS",
                    )
                )
            if _ALLOW_ALL_BACKEND_RE.search(line) and "AUTHENTICATION_BACKENDS" in line:
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="allow_all_users_backend",
                        severity="critical",
                        message="AllowAllUsersModelBackend bypasses password authentication",
                        setting="AUTHENTICATION_BACKENDS",
                    )
                )
            if _LDAP_NO_TLS_RE.search(line) or _LDAP_TLS_FALSE_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="ldap_without_tls",
                        severity="high",
                        message="LDAP authentication configured without TLS encryption",
                        setting="AUTH_LDAP_SERVER_URI",
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
