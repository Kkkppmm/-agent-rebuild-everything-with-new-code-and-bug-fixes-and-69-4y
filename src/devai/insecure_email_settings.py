"""InsecureEmailSettingsAnalyzer — detect insecure email configuration."""

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
        "email.py",
    }
)
_CONSOLE_BACKEND_RE = re.compile(
    r"(django\.core\.mail\.backends\.)?console\.EmailBackend|console\.EmailBackend",
    re.IGNORECASE,
)
_FILE_BACKEND_RE = re.compile(
    r"(django\.core\.mail\.backends\.)?filebased\.EmailBackend|filebased\.EmailBackend",
    re.IGNORECASE,
)
_SMTP_BACKEND_RE = re.compile(
    r"(django\.core\.mail\.backends\.)?smtp\.EmailBackend|smtp\.EmailBackend",
    re.IGNORECASE,
)
_EMPTY_PASSWORD_RE = re.compile(
    r"EMAIL_HOST_PASSWORD\s*=\s*['\"]['\"]",
    re.IGNORECASE,
)
_TLS_DISABLED_RE = re.compile(
    r"EMAIL_USE_TLS\s*=\s*False",
    re.IGNORECASE,
)
_SSL_DISABLED_RE = re.compile(
    r"EMAIL_USE_SSL\s*=\s*False",
    re.IGNORECASE,
)
_PLAINTEXT_SMTP_PORT_RE = re.compile(
    r"EMAIL_PORT\s*=\s*25\b",
    re.IGNORECASE,
)


@dataclass
class InsecureEmailSettingsFinding:
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
class InsecureEmailSettingsStats:
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


def _int_value(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _is_console_backend(value: str) -> bool:
    return bool(_CONSOLE_BACKEND_RE.search(value))


def _is_file_backend(value: str) -> bool:
    return bool(_FILE_BACKEND_RE.search(value))


def _is_smtp_backend(value: str) -> bool:
    return bool(_SMTP_BACKEND_RE.search(value))


class _InsecureEmailSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureEmailSettingsFinding] = []
        self._email_backend: str | None = None
        self._email_use_tls: bool | None = None
        self._email_use_ssl: bool | None = None
        self._email_port: int | None = None
        self._email_host_password: str | None = None

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureEmailSettingsFinding(
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
            if name == "EMAIL_BACKEND":
                value = _dict_string_value(node.value)
                if value:
                    self._email_backend = value
                    if _is_console_backend(value) and self.filename in _PROD_FILENAMES:
                        self._add(
                            node.lineno,
                            "console_email_in_production",
                            "high",
                            "Console email backend prints messages to stdout — use SMTP in production",
                            setting="EMAIL_BACKEND",
                        )
                    elif _is_file_backend(value) and self.filename in _PROD_FILENAMES:
                        self._add(
                            node.lineno,
                            "file_email_in_production",
                            "medium",
                            "File-based email backend is not suitable for production delivery",
                            setting="EMAIL_BACKEND",
                        )
            elif name == "EMAIL_USE_TLS":
                self._email_use_tls = _bool_value(node.value)
            elif name == "EMAIL_USE_SSL":
                self._email_use_ssl = _bool_value(node.value)
            elif name == "EMAIL_PORT":
                self._email_port = _int_value(node.value)
            elif name == "EMAIL_HOST_PASSWORD":
                value = _dict_string_value(node.value)
                if value is not None:
                    self._email_host_password = value
                    if value == "" and self.filename in _PROD_FILENAMES:
                        self._add(
                            node.lineno,
                            "empty_email_password",
                            "high",
                            "SMTP password is empty — use credentials from environment variables",
                            setting="EMAIL_HOST_PASSWORD",
                        )
        self.generic_visit(node)

    def finalize(self) -> None:
        if self.filename not in _PROD_FILENAMES:
            return
        backend = self._email_backend or ""
        if _is_smtp_backend(backend):
            if self._email_use_tls is False and self._email_use_ssl is not True:
                self._add(
                    0,
                    "smtp_tls_disabled",
                    "high",
                    "SMTP backend without TLS or SSL — enable EMAIL_USE_TLS or EMAIL_USE_SSL",
                    setting="EMAIL_USE_TLS",
                )
            if self._email_port == 25:
                self._add(
                    0,
                    "smtp_plaintext_port",
                    "medium",
                    "SMTP port 25 is often unencrypted — prefer 587 (STARTTLS) or 465 (SSL)",
                    setting="EMAIL_PORT",
                )


class InsecureEmailSettingsAnalyzer:
    """Detect insecure email configuration in Django and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureEmailSettingsFinding] = []
        self._stats: InsecureEmailSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureEmailSettingsFinding]:
        findings: list[InsecureEmailSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureEmailSettingsVisitor(rel, filename)
            visitor.visit(tree)
            visitor.finalize()
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        if filename not in _PROD_FILENAMES:
            return findings

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _CONSOLE_BACKEND_RE.search(line):
                findings.append(
                    InsecureEmailSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="console_email_in_production",
                        severity="high",
                        message="Console email backend prints messages to stdout — use SMTP in production",
                        setting="EMAIL_BACKEND",
                    )
                )
            if _FILE_BACKEND_RE.search(line):
                findings.append(
                    InsecureEmailSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="file_email_in_production",
                        severity="medium",
                        message="File-based email backend is not suitable for production delivery",
                        setting="EMAIL_BACKEND",
                    )
                )
            if _EMPTY_PASSWORD_RE.search(line):
                findings.append(
                    InsecureEmailSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="empty_email_password",
                        severity="high",
                        message="SMTP password is empty — use credentials from environment variables",
                        setting="EMAIL_HOST_PASSWORD",
                    )
                )
            if _TLS_DISABLED_RE.search(line) and _SMTP_BACKEND_RE.search(source):
                findings.append(
                    InsecureEmailSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="smtp_tls_disabled",
                        severity="high",
                        message="SMTP backend without TLS or SSL — enable EMAIL_USE_TLS or EMAIL_USE_SSL",
                        setting="EMAIL_USE_TLS",
                    )
                )
            if _PLAINTEXT_SMTP_PORT_RE.search(line):
                findings.append(
                    InsecureEmailSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="smtp_plaintext_port",
                        severity="medium",
                        message="SMTP port 25 is often unencrypted — prefer 587 (STARTTLS) or 465 (SSL)",
                        setting="EMAIL_PORT",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureEmailSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureEmailSettingsFinding] = []
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
        self._stats = InsecureEmailSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureEmailSettingsStats:
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
            f"Insecure email settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure email settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure email configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
