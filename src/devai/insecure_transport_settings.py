"""InsecureTransportSettingsAnalyzer — detect disabled HTTPS transport security settings."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_TRANSPORT_SETTING_NAMES = frozenset(
    {
        "SECURE_SSL_REDIRECT",
        "SECURE_HSTS_SECONDS",
        "SECURE_HSTS_INCLUDE_SUBDOMAINS",
        "SECURE_CONTENT_TYPE_NOSNIFF",
        "SECURE_BROWSER_XSS_FILTER",
        "SECURE_PROXY_SSL_HEADER",
        "PREFERRED_URL_SCHEME",
    }
)
_INSECURE_FALSE_SETTINGS = frozenset(
    {
        "SECURE_SSL_REDIRECT",
        "SECURE_HSTS_INCLUDE_SUBDOMAINS",
        "SECURE_CONTENT_TYPE_NOSNIFF",
        "SECURE_BROWSER_XSS_FILTER",
    }
)
_SETTING_ASSIGN_RE = re.compile(
    r"(SECURE_SSL_REDIRECT|SECURE_HSTS_SECONDS|SECURE_HSTS_INCLUDE_SUBDOMAINS|"
    r"SECURE_CONTENT_TYPE_NOSNIFF|SECURE_BROWSER_XSS_FILTER|SECURE_PROXY_SSL_HEADER|"
    r"PREFERRED_URL_SCHEME)\s*=\s*(.+)"
)


@dataclass
class InsecureTransportSettingsFinding:
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
class InsecureTransportSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_insecure_false(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and value.value is False


def _is_disabled_hsts(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and value.value == 0


def _is_disabled_proxy_header(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant) and value.value is None:
        return True
    if isinstance(value, ast.Tuple) and len(value.elts) == 0:
        return True
    return False


def _is_insecure_url_scheme(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and value.value == "http"


def _message_for_setting(setting: str, pattern: str) -> str:
    messages = {
        ("SECURE_SSL_REDIRECT", "insecure_secure_ssl_redirect"): (
            "SECURE_SSL_REDIRECT = False disables HTTPS redirects — enable in production"
        ),
        ("SECURE_HSTS_SECONDS", "insecure_secure_hsts_seconds"): (
            "SECURE_HSTS_SECONDS = 0 disables HSTS — set to at least 31536000 (1 year)"
        ),
        ("SECURE_HSTS_INCLUDE_SUBDOMAINS", "insecure_secure_hsts_include_subdomains"): (
            "SECURE_HSTS_INCLUDE_SUBDOMAINS = False limits HSTS protection to the apex domain"
        ),
        ("SECURE_CONTENT_TYPE_NOSNIFF", "insecure_secure_content_type_nosniff"): (
            "SECURE_CONTENT_TYPE_NOSNIFF = False allows MIME-type sniffing attacks"
        ),
        ("SECURE_BROWSER_XSS_FILTER", "insecure_secure_browser_xss_filter"): (
            "SECURE_BROWSER_XSS_FILTER = False disables the browser XSS filter header"
        ),
        ("SECURE_PROXY_SSL_HEADER", "insecure_secure_proxy_ssl_header"): (
            "SECURE_PROXY_SSL_HEADER is disabled — configure proxy SSL header detection"
        ),
        ("PREFERRED_URL_SCHEME", "insecure_preferred_url_scheme"): (
            "PREFERRED_URL_SCHEME = 'http' generates insecure URLs — use 'https' in production"
        ),
    }
    return messages.get((setting, pattern), f"Insecure {setting} configuration")


class _InsecureTransportSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureTransportSettingsFinding] = []

    def _add_finding(
        self,
        setting: str,
        pattern: str,
        lineno: int,
        severity: str,
    ) -> None:
        self.findings.append(
            InsecureTransportSettingsFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=_message_for_setting(setting, pattern),
                setting=setting,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name) or target.id not in _TRANSPORT_SETTING_NAMES:
                continue
            setting = target.id
            if setting in _INSECURE_FALSE_SETTINGS and _is_insecure_false(node.value):
                pattern = f"insecure_{setting.lower()}"
                self._add_finding(setting, pattern, node.lineno, "high")
            elif setting == "SECURE_HSTS_SECONDS" and _is_disabled_hsts(node.value):
                pattern = "insecure_secure_hsts_seconds"
                self._add_finding(setting, pattern, node.lineno, "high")
            elif setting == "SECURE_PROXY_SSL_HEADER" and _is_disabled_proxy_header(node.value):
                pattern = "insecure_secure_proxy_ssl_header"
                self._add_finding(setting, pattern, node.lineno, "medium")
            elif setting == "PREFERRED_URL_SCHEME" and _is_insecure_url_scheme(node.value):
                pattern = "insecure_preferred_url_scheme"
                self._add_finding(setting, pattern, node.lineno, "high")
        self.generic_visit(node)


class InsecureTransportSettingsAnalyzer:
    """Detect disabled Django/Flask HTTPS transport security settings."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureTransportSettingsFinding] = []
        self._stats: InsecureTransportSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureTransportSettingsFinding]:
        findings: list[InsecureTransportSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureTransportSettingsVisitor(rel)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = _SETTING_ASSIGN_RE.search(line)
            if not match:
                continue
            setting = match.group(1)
            value = match.group(2).strip().rstrip(",")
            if setting in _INSECURE_FALSE_SETTINGS and value == "False":
                pattern = f"insecure_{setting.lower()}"
                findings.append(
                    InsecureTransportSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="high",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
            elif setting == "SECURE_HSTS_SECONDS" and value == "0":
                pattern = "insecure_secure_hsts_seconds"
                findings.append(
                    InsecureTransportSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="high",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
            elif setting == "SECURE_PROXY_SSL_HEADER" and value in {"None", "()"}:
                pattern = "insecure_secure_proxy_ssl_header"
                findings.append(
                    InsecureTransportSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="medium",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
            elif setting == "PREFERRED_URL_SCHEME" and value in {"'http'", '"http"'}:
                pattern = "insecure_preferred_url_scheme"
                findings.append(
                    InsecureTransportSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="high",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
        return findings

    def analyze(self) -> list[InsecureTransportSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureTransportSettingsFinding] = []
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
        self._stats = InsecureTransportSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureTransportSettingsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure transport settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure transport settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure HTTPS transport settings found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
