"""InsecureSessionSettingsAnalyzer — detect insecure session and CSRF cookie settings."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SESSION_SETTING_NAMES = frozenset(
    {
        "SESSION_COOKIE_SECURE",
        "SESSION_COOKIE_HTTPONLY",
        "SESSION_COOKIE_SAMESITE",
        "CSRF_COOKIE_SECURE",
        "CSRF_COOKIE_HTTPONLY",
        "CSRF_COOKIE_SAMESITE",
        "REMEMBER_COOKIE_SECURE",
        "REMEMBER_COOKIE_HTTPONLY",
    }
)
_INSECURE_FALSE_SETTINGS = frozenset(
    {
        "SESSION_COOKIE_SECURE",
        "SESSION_COOKIE_HTTPONLY",
        "CSRF_COOKIE_SECURE",
        "CSRF_COOKIE_HTTPONLY",
        "REMEMBER_COOKIE_SECURE",
        "REMEMBER_COOKIE_HTTPONLY",
    }
)
_INSECURE_SAMESITE_SETTINGS = frozenset(
    {
        "SESSION_COOKIE_SAMESITE",
        "CSRF_COOKIE_SAMESITE",
    }
)
_SETTING_ASSIGN_RE = re.compile(
    r"(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|SESSION_COOKIE_SAMESITE|"
    r"CSRF_COOKIE_SECURE|CSRF_COOKIE_HTTPONLY|CSRF_COOKIE_SAMESITE|"
    r"REMEMBER_COOKIE_SECURE|REMEMBER_COOKIE_HTTPONLY)\s*=\s*(.+)"
)


@dataclass
class InsecureSessionSettingsFinding:
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
class InsecureSessionSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_insecure_false(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and value.value is False


def _is_insecure_samesite(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant):
        if value.value is None:
            return True
        if isinstance(value.value, str) and value.value.strip().lower() in {"", "none", "false"}:
            return True
    return False


def _message_for_setting(setting: str, pattern: str) -> str:
    messages = {
        ("SESSION_COOKIE_SECURE", "insecure_session_cookie_secure"): (
            "SESSION_COOKIE_SECURE = False allows session cookies over HTTP — enable in production"
        ),
        ("SESSION_COOKIE_HTTPONLY", "insecure_session_cookie_httponly"): (
            "SESSION_COOKIE_HTTPONLY = False exposes session cookies to JavaScript — enable HttpOnly"
        ),
        ("CSRF_COOKIE_SECURE", "insecure_csrf_cookie_secure"): (
            "CSRF_COOKIE_SECURE = False allows CSRF cookies over HTTP — enable in production"
        ),
        ("CSRF_COOKIE_HTTPONLY", "insecure_csrf_cookie_httponly"): (
            "CSRF_COOKIE_HTTPONLY = False exposes CSRF cookies to JavaScript — enable HttpOnly"
        ),
        ("REMEMBER_COOKIE_SECURE", "insecure_remember_cookie_secure"): (
            "REMEMBER_COOKIE_SECURE = False allows remember-me cookies over HTTP"
        ),
        ("REMEMBER_COOKIE_HTTPONLY", "insecure_remember_cookie_httponly"): (
            "REMEMBER_COOKIE_HTTPONLY = False exposes remember-me cookies to JavaScript"
        ),
        ("SESSION_COOKIE_SAMESITE", "insecure_session_cookie_samesite"): (
            "SESSION_COOKIE_SAMESITE is disabled — set to 'Lax' or 'Strict' to mitigate CSRF"
        ),
        ("CSRF_COOKIE_SAMESITE", "insecure_csrf_cookie_samesite"): (
            "CSRF_COOKIE_SAMESITE is disabled — set to 'Lax' or 'Strict' to mitigate CSRF"
        ),
    }
    return messages.get((setting, pattern), f"Insecure {setting} configuration")


class _InsecureSessionSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureSessionSettingsFinding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name) or target.id not in _SESSION_SETTING_NAMES:
                continue
            setting = target.id
            if setting in _INSECURE_FALSE_SETTINGS and _is_insecure_false(node.value):
                pattern = f"insecure_{setting.lower()}"
                self.findings.append(
                    InsecureSessionSettingsFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity="high",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
            elif setting in _INSECURE_SAMESITE_SETTINGS and _is_insecure_samesite(node.value):
                pattern = f"insecure_{setting.lower()}"
                self.findings.append(
                    InsecureSessionSettingsFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity="medium",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
        self.generic_visit(node)


class InsecureSessionSettingsAnalyzer:
    """Detect insecure Django/Flask session and CSRF cookie configuration."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureSessionSettingsFinding] = []
        self._stats: InsecureSessionSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(self, rel: str, source: str) -> list[InsecureSessionSettingsFinding]:
        findings: list[InsecureSessionSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureSessionSettingsVisitor(rel)
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
                    InsecureSessionSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="high",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
            elif setting in _INSECURE_SAMESITE_SETTINGS and value in {"None", "''", '""', "False"}:
                pattern = f"insecure_{setting.lower()}"
                findings.append(
                    InsecureSessionSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern=pattern,
                        severity="medium",
                        message=_message_for_setting(setting, pattern),
                        setting=setting,
                    )
                )
        return findings

    def analyze(self) -> list[InsecureSessionSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureSessionSettingsFinding] = []
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
        self._stats = InsecureSessionSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureSessionSettingsStats:
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
            f"Insecure session settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure session settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure session or CSRF cookie settings found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
