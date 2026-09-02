"""InsecureOAuthSettingsAnalyzer — detect insecure OAuth2/OIDC configuration."""

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
        "oauth.py",
        "auth.py",
    }
)
_PKCE_DISABLED_RE = re.compile(
    r"(OAUTH_PKCE_REQUIRED|PKCE_REQUIRED|REQUIRE_PKCE)\s*=\s*False",
    re.IGNORECASE,
)
_STATE_DISABLED_RE = re.compile(
    r"(OAUTH_STATE_ENABLED|OAUTH_USE_STATE|USE_OAUTH_STATE)\s*=\s*False",
    re.IGNORECASE,
)
_HARDCODED_CLIENT_SECRET_RE = re.compile(
    r"(OAUTH_CLIENT_SECRET|SOCIAL_AUTH_[A-Z_]+_SECRET|OIDC_CLIENT_SECRET)\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
_INSECURE_TRANSPORT_RE = re.compile(
    r"(OAUTHLIB_INSECURE_TRANSPORT|OAUTH_INSECURE_TRANSPORT)\s*=\s*['\"]1['\"]|"
    r"(OAUTHLIB_INSECURE_TRANSPORT|OAUTH_INSECURE_TRANSPORT)\s*=\s*True",
    re.IGNORECASE,
)


@dataclass
class InsecureOAuthSettingsFinding:
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
class InsecureOAuthSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _bool_value(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _InsecureOAuthSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureOAuthSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureOAuthSettingsFinding(
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
            name = target.id.upper()
            if name in {"OAUTH_PKCE_REQUIRED", "PKCE_REQUIRED", "REQUIRE_PKCE"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "oauth_pkce_disabled",
                        "high",
                        "OAuth PKCE is disabled — authorization codes are vulnerable to interception",
                        setting=target.id,
                    )
            elif name in {"OAUTH_STATE_ENABLED", "OAUTH_USE_STATE", "USE_OAUTH_STATE"}:
                if _bool_value(node.value) is False:
                    self._add(
                        node.lineno,
                        "oauth_state_disabled",
                        "high",
                        "OAuth state parameter validation is disabled — CSRF attacks are possible",
                        setting=target.id,
                    )
            elif name in {
                "OAUTH_CLIENT_SECRET",
                "OIDC_CLIENT_SECRET",
            } or (name.startswith("SOCIAL_AUTH_") and name.endswith("_SECRET")):
                value = _string_value(node.value)
                if value is not None and len(value) >= 8:
                    self._add(
                        node.lineno,
                        "hardcoded_oauth_client_secret",
                        "critical",
                        f"{target.id} is hardcoded — load OAuth secrets from environment variables",
                        setting=target.id,
                    )
            elif name in {"OAUTHLIB_INSECURE_TRANSPORT", "OAUTH_INSECURE_TRANSPORT"}:
                value = _string_value(node.value)
                if _bool_value(node.value) is True or value == "1":
                    self._add(
                        node.lineno,
                        "oauth_insecure_transport",
                        "critical",
                        "OAuth insecure transport is enabled — tokens may be sent over HTTP",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureOAuthSettingsAnalyzer:
    """Detect insecure OAuth2/OIDC configuration in Django, Flask, and similar apps."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureOAuthSettingsFinding] = []
        self._stats: InsecureOAuthSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureOAuthSettingsFinding]:
        findings: list[InsecureOAuthSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureOAuthSettingsVisitor(rel, filename)
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
            if _PKCE_DISABLED_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="oauth_pkce_disabled",
                        severity="high",
                        message="OAuth PKCE is disabled — authorization codes are vulnerable to interception",
                        setting="OAUTH_PKCE_REQUIRED",
                    )
                )
            if _STATE_DISABLED_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="oauth_state_disabled",
                        severity="high",
                        message="OAuth state parameter validation is disabled — CSRF attacks are possible",
                        setting="OAUTH_STATE_ENABLED",
                    )
                )
            if _HARDCODED_CLIENT_SECRET_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_oauth_client_secret",
                        severity="critical",
                        message="OAuth client secret is hardcoded — load from environment variables",
                        setting="OAUTH_CLIENT_SECRET",
                    )
                )
            if _INSECURE_TRANSPORT_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="oauth_insecure_transport",
                        severity="critical",
                        message="OAuth insecure transport is enabled — tokens may be sent over HTTP",
                        setting="OAUTHLIB_INSECURE_TRANSPORT",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureOAuthSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureOAuthSettingsFinding] = []
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
        self._stats = InsecureOAuthSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureOAuthSettingsStats:
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
            f"Insecure OAuth settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure OAuth settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure OAuth configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
