"""InsecureOAuthSettingsAnalyzer — detect insecure OAuth and social-auth configuration."""

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
        "social_auth.py",
    }
)
_OAUTH_SECRET_NAME_RE = re.compile(
    r"(CLIENT_SECRET|SOCIAL_AUTH_.*_SECRET|OIDC_RP_CLIENT_SECRET|OAUTH_.*_SECRET)",
    re.IGNORECASE,
)
_INSECURE_TRANSPORT_RE = re.compile(
    r"OAUTHLIB_INSECURE_TRANSPORT\s*=\s*(True|1|['\"]1['\"])",
    re.IGNORECASE,
)
_HTTP_REDIRECT_RE = re.compile(
    r"(redirect_uri|REDIRECT_URI|ALLOWED_REDIRECT_URIS?)\s*[=:]\s*['\"]http://",
    re.IGNORECASE,
)
_WILDCARD_REDIRECT_RE = re.compile(
    r"(ALLOWED_REDIRECT_URIS?|redirect_uris?)\s*[=:].*\*",
    re.IGNORECASE,
)
_HARDCODED_SECRET_RE = re.compile(
    r"(CLIENT_SECRET|SOCIAL_AUTH_\w+_SECRET|OIDC_RP_CLIENT_SECRET)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_INSECURE_STATE_RE = re.compile(
    r"SOCIAL_AUTH_.*STATE\s*=\s*False|OAUTH_.*USE_PKCE\s*=\s*False",
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


def _dict_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_insecure_transport_value(node: ast.AST) -> bool:
    if _is_true(node):
        return True
    if isinstance(node, ast.Constant) and node.value in {1, "1"}:
        return True
    return False


def _is_oauth_secret_name(name: str) -> bool:
    upper = name.upper()
    if upper == "CLIENT_SECRET":
        return True
    if upper.startswith("SOCIAL_AUTH_") and upper.endswith("_SECRET"):
        return True
    if upper == "OIDC_RP_CLIENT_SECRET":
        return True
    if upper.startswith("OAUTH_") and upper.endswith("_SECRET"):
        return True
    return False


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
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if name.upper() == "OAUTHLIB_INSECURE_TRANSPORT" and _is_insecure_transport_value(
                node.value
            ):
                self._add(
                    node.lineno,
                    "oauth_insecure_transport",
                    "high",
                    "OAUTHLIB_INSECURE_TRANSPORT allows OAuth over HTTP — disable in production",
                    setting="OAUTHLIB_INSECURE_TRANSPORT",
                )
            elif _is_oauth_secret_name(name):
                value = _dict_string_value(node.value)
                if value and len(value) >= 8 and not value.startswith("os.environ"):
                    self._add(
                        node.lineno,
                        "hardcoded_oauth_secret",
                        "critical",
                        f"{name} is hardcoded — load OAuth secrets from environment variables",
                        setting=name,
                    )
            elif name.upper() in {"ALLOWED_REDIRECT_URIS", "REDIRECT_URIS"}:
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        uri = _dict_string_value(elt)
                        if uri:
                            if uri.startswith("http://"):
                                self._add(
                                    node.lineno,
                                    "http_redirect_uri",
                                    "high",
                                    f"Redirect URI uses HTTP instead of HTTPS: {uri}",
                                    setting=name,
                                )
                            if "*" in uri:
                                self._add(
                                    node.lineno,
                                    "wildcard_redirect_uri",
                                    "high",
                                    f"Wildcard redirect URI is insecure: {uri}",
                                    setting=name,
                                )
        self.generic_visit(node)


class InsecureOAuthSettingsAnalyzer:
    """Detect insecure OAuth and social-auth configuration in production settings."""

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
            if _INSECURE_TRANSPORT_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="oauth_insecure_transport",
                        severity="high",
                        message="OAUTHLIB_INSECURE_TRANSPORT allows OAuth over HTTP",
                        setting="OAUTHLIB_INSECURE_TRANSPORT",
                    )
                )
            if _HARDCODED_SECRET_RE.search(line) and not line.strip().startswith("#"):
                match = _OAUTH_SECRET_NAME_RE.search(line)
                setting = match.group(1) if match else "CLIENT_SECRET"
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_oauth_secret",
                        severity="critical",
                        message="OAuth client secret is hardcoded in source",
                        setting=setting,
                    )
                )
            if _HTTP_REDIRECT_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="http_redirect_uri",
                        severity="high",
                        message="OAuth redirect URI uses HTTP instead of HTTPS",
                    )
                )
            if _WILDCARD_REDIRECT_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="wildcard_redirect_uri",
                        severity="high",
                        message="Wildcard OAuth redirect URI allows open redirect attacks",
                    )
                )
            if _INSECURE_STATE_RE.search(line):
                findings.append(
                    InsecureOAuthSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="oauth_state_disabled",
                        severity="medium",
                        message="OAuth state/PKCE protection is disabled",
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
