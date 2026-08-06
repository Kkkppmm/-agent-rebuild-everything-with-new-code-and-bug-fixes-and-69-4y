"""InsecureAuthSettingsAnalyzer — detect insecure authentication configuration in settings."""

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
        "ldap.py",
    }
)
_WEAK_HASHER_NAMES = frozenset(
    {
        "MD5PasswordHasher",
        "SHA1PasswordHasher",
        "UnsaltedMD5PasswordHasher",
        "UnsaltedSHA1PasswordHasher",
        "CryptPasswordHasher",
    }
)
_ALLOW_ALL_BACKEND = "AllowAllUsersModelBackend"
_LDAP_URI_RE = re.compile(
    r"AUTH_LDAP_SERVER_URI\s*=\s*['\"]ldap://",
    re.IGNORECASE,
)
_LDAPS_URI_RE = re.compile(
    r"AUTH_LDAP_SERVER_URI\s*=\s*['\"]ldaps://",
    re.IGNORECASE,
)
_START_TLS_RE = re.compile(
    r"AUTH_LDAP_START_TLS\s*=\s*True",
    re.IGNORECASE,
)
_ALLOW_ALL_BACKEND_RE = re.compile(
    r"AllowAllUsersModelBackend",
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


def _hasher_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        for weak in _WEAK_HASHER_NAMES:
            if weak in node.value:
                return weak
    if isinstance(node, ast.Attribute):
        return node.attr if node.attr in _WEAK_HASHER_NAMES else None
    return None


def _list_contains_backend(node: ast.AST, backend: str) -> bool:
    if not isinstance(node, ast.List):
        return False
    for elt in node.elts:
        value = _string_value(elt)
        if value and backend in value:
            return True
        if isinstance(elt, ast.Attribute) and elt.attr == backend:
            return True
    return False


def _list_has_weak_hasher(node: ast.AST) -> str | None:
    if not isinstance(node, ast.List):
        return None
    for elt in node.elts:
        hasher = _hasher_name(elt)
        if hasher:
            return hasher
    return None


class _InsecureAuthSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureAuthSettingsFinding] = []
        self._ldap_uri: str | None = None
        self._ldap_start_tls = False

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
                weak = _list_has_weak_hasher(node.value)
                if weak:
                    self._add(
                        node.lineno,
                        "weak_password_hasher",
                        "high",
                        f"PASSWORD_HASHERS includes weak hasher {weak} — use Argon2 or PBKDF2",
                        setting="PASSWORD_HASHERS",
                    )
            elif name == "AUTH_PASSWORD_VALIDATORS":
                if isinstance(node.value, ast.List) and not node.value.elts:
                    self._add(
                        node.lineno,
                        "empty_password_validators",
                        "high",
                        "AUTH_PASSWORD_VALIDATORS is empty — enforce minimum password complexity",
                        setting="AUTH_PASSWORD_VALIDATORS",
                    )
            elif name == "AUTHENTICATION_BACKENDS":
                if _list_contains_backend(node.value, _ALLOW_ALL_BACKEND):
                    self._add(
                        node.lineno,
                        "allow_all_users_backend",
                        "critical",
                        "AllowAllUsersModelBackend permits any password — remove from production",
                        setting="AUTHENTICATION_BACKENDS",
                    )
            elif name == "AUTH_LDAP_SERVER_URI":
                uri = _string_value(node.value)
                if uri:
                    self._ldap_uri = uri
                    if uri.lower().startswith("ldap://"):
                        self._add(
                            node.lineno,
                            "ldap_without_tls",
                            "high",
                            "LDAP server URI uses unencrypted ldap:// — use ldaps:// or START_TLS",
                            setting="AUTH_LDAP_SERVER_URI",
                        )
            elif name == "AUTH_LDAP_START_TLS":
                if _bool_value(node.value) is True:
                    self._ldap_start_tls = True
        self.generic_visit(node)

    def finalize(self) -> None:
        if self.filename not in _PROD_FILENAMES:
            return
        if self._ldap_uri and self._ldap_uri.lower().startswith("ldap://") and not self._ldap_start_tls:
            already = any(f.pattern == "ldap_without_tls" for f in self.findings)
            if not already:
                self._add(
                    0,
                    "ldap_without_tls",
                    "high",
                    "LDAP configured without TLS — enable AUTH_LDAP_START_TLS or use ldaps://",
                    setting="AUTH_LDAP_SERVER_URI",
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
            visitor.finalize()
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        has_ldap = bool(_LDAP_URI_RE.search(source))
        has_ldaps = bool(_LDAPS_URI_RE.search(source))
        has_start_tls = bool(_START_TLS_RE.search(source))

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for weak in _WEAK_HASHER_NAMES:
                if weak in line and "PASSWORD_HASHERS" in source:
                    findings.append(
                        InsecureAuthSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="weak_password_hasher",
                            severity="high",
                            message=f"PASSWORD_HASHERS includes weak hasher {weak} — use Argon2 or PBKDF2",
                            setting="PASSWORD_HASHERS",
                        )
                    )
                    break
            if _EMPTY_VALIDATORS_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="empty_password_validators",
                        severity="high",
                        message="AUTH_PASSWORD_VALIDATORS is empty — enforce minimum password complexity",
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
                        message="AllowAllUsersModelBackend permits any password — remove from production",
                        setting="AUTHENTICATION_BACKENDS",
                    )
                )
            if _LDAP_URI_RE.search(line):
                findings.append(
                    InsecureAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="ldap_without_tls",
                        severity="high",
                        message="LDAP server URI uses unencrypted ldap:// — use ldaps:// or START_TLS",
                        setting="AUTH_LDAP_SERVER_URI",
                    )
                )

        if has_ldap and not has_ldaps and not has_start_tls:
            findings.append(
                InsecureAuthSettingsFinding(
                    path=rel,
                    lineno=0,
                    pattern="ldap_without_tls",
                    severity="high",
                    message="LDAP configured without TLS — enable AUTH_LDAP_START_TLS or use ldaps://",
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
