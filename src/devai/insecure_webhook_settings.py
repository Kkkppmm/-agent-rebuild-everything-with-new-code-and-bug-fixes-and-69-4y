"""InsecureWebhookSettingsAnalyzer — detect insecure webhook configuration."""

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
        "webhooks.py",
        "views.py",
    }
)
_HARDCODED_WEBHOOK_SECRET_RE = re.compile(
    r"(WEBHOOK_SECRET|STRIPE_WEBHOOK_SECRET|GITHUB_WEBHOOK_SECRET|"
    r"SLACK_SIGNING_SECRET|WEBHOOK_SIGNING_SECRET)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_VERIFY_DISABLED_RE = re.compile(
    r"(verify_signature|VERIFY_WEBHOOK|WEBHOOK_VERIFY)\s*=\s*False",
    re.IGNORECASE,
)
_HTTP_WEBHOOK_URL_RE = re.compile(
    r"(WEBHOOK_URL|WEBHOOK_ENDPOINT|CALLBACK_URL)\s*=\s*['\"]http://",
    re.IGNORECASE,
)
_CSRF_EXEMPT_WEBHOOK_RE = re.compile(
    r"csrf_exempt.*webhook|@csrf_exempt\s*\n\s*def\s+\w*webhook",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class InsecureWebhookSettingsFinding:
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
class InsecureWebhookSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


_WEBHOOK_SECRET_NAMES = frozenset(
    {
        "WEBHOOK_SECRET",
        "STRIPE_WEBHOOK_SECRET",
        "GITHUB_WEBHOOK_SECRET",
        "SLACK_SIGNING_SECRET",
        "WEBHOOK_SIGNING_SECRET",
        "WEBHOOK_VERIFY",
        "VERIFY_WEBHOOK",
    }
)
_VERIFY_SETTING_NAMES = frozenset({"WEBHOOK_VERIFY", "VERIFY_WEBHOOK", "verify_signature"})


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_hardcoded_secret(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) >= 8 and not node.value.startswith("${")
    return False


def _is_http_url(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower().startswith("http://")
    return False


class _InsecureWebhookSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureWebhookSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureWebhookSettingsFinding(
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
            name = target.id.upper()
            if name in _WEBHOOK_SECRET_NAMES and _is_hardcoded_secret(node.value):
                self._add(
                    node.lineno,
                    "hardcoded_webhook_secret",
                    "critical",
                    f"{target.id} is hardcoded — load from environment or secrets manager",
                    setting=target.id,
                )
            if name in _VERIFY_SETTING_NAMES and _is_false(node.value):
                self._add(
                    node.lineno,
                    "webhook_verify_disabled",
                    "critical",
                    f"{target.id} is False — webhook signature verification is disabled",
                    setting=target.id,
                )
            if "WEBHOOK" in name and "URL" in name and _is_http_url(node.value):
                self._add(
                    node.lineno,
                    "http_webhook_url",
                    "high",
                    f"{target.id} uses http:// — use HTTPS for webhook endpoints",
                    setting=target.id,
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "csrf_exempt":
                if "webhook" in node.name.lower():
                    self._add(
                        node.lineno,
                        "csrf_exempt_webhook_handler",
                        "high",
                        f"Webhook handler {node.name} uses @csrf_exempt — validate signatures instead",
                        setting="csrf_exempt",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr == "verify":
            for kw in node.keywords:
                if kw.arg == "verify" and _is_false(kw.value):
                    self._add(
                        node.lineno,
                        "webhook_verify_disabled",
                        "critical",
                        "Webhook signature verification disabled in verify() call",
                        setting="verify",
                    )
        self.generic_visit(node)


class InsecureWebhookSettingsAnalyzer:
    """Detect insecure webhook configuration and handlers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureWebhookSettingsFinding] = []
        self._stats: InsecureWebhookSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureWebhookSettingsFinding]:
        findings: list[InsecureWebhookSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureWebhookSettingsVisitor(rel, filename)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _HARDCODED_WEBHOOK_SECRET_RE.search(line):
                findings.append(
                    InsecureWebhookSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_webhook_secret",
                        severity="critical",
                        message="Webhook secret is hardcoded — load from environment or secrets manager",
                        setting="WEBHOOK_SECRET",
                    )
                )
            if _VERIFY_DISABLED_RE.search(line):
                findings.append(
                    InsecureWebhookSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="webhook_verify_disabled",
                        severity="critical",
                        message="Webhook signature verification is disabled",
                        setting="VERIFY_WEBHOOK",
                    )
                )
            if _HTTP_WEBHOOK_URL_RE.search(line):
                findings.append(
                    InsecureWebhookSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="http_webhook_url",
                        severity="high",
                        message="Webhook URL uses http:// — use HTTPS",
                        setting="WEBHOOK_URL",
                    )
                )
            if "csrf_exempt" in line.lower() and "webhook" in line.lower():
                findings.append(
                    InsecureWebhookSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="csrf_exempt_webhook_handler",
                        severity="high",
                        message="Webhook handler uses csrf_exempt — validate signatures instead",
                        setting="csrf_exempt",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureWebhookSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureWebhookSettingsFinding] = []
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
        self._stats = InsecureWebhookSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureWebhookSettingsStats:
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
            f"Insecure webhook settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure webhook settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure webhook configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
