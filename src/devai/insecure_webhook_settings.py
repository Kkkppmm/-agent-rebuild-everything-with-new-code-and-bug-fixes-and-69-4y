"""InsecureWebhookSettingsAnalyzer — detect insecure webhook configuration and handlers."""

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
        "webhooks.py",
        "stripe.py",
    }
)
_WEBHOOK_VIEW_FILENAMES = frozenset(
    {
        "views.py",
        "webhooks.py",
        "handlers.py",
        "urls.py",
        "api.py",
        "routes.py",
    }
)
_HARDCODED_SECRET_RE = re.compile(
    r"(WEBHOOK_SECRET|WEBHOOK_SIGNING_SECRET|STRIPE_WEBHOOK_SECRET|"
    r"GITHUB_WEBHOOK_SECRET|SLACK_SIGNING_SECRET|SHOPIFY_WEBHOOK_SECRET|"
    r"TWILIO_AUTH_TOKEN|WEBHOOK_API_KEY)\s*=\s*['\"][^'\"]{8,}['\"]",
    re.IGNORECASE,
)
_SKIP_VERIFICATION_RE = re.compile(
    r"(verify_webhook_signature|verify_signature|webhook_verification|"
    r"WEBHOOK_VERIFY|WEBHOOK_SIGNATURE_VERIFICATION|validate_webhook)\s*"
    r"[:=]\s*(False|0|['\"]0['\"]|None)",
    re.IGNORECASE,
)
_HTTP_WEBHOOK_URL_RE = re.compile(
    r"(WEBHOOK_URL|webhook_url|callback_url|notify_url)\s*[:=]\s*['\"]http://",
    re.IGNORECASE,
)
_CSRF_EXEMPT_WEBHOOK_RE = re.compile(
    r"csrf_exempt.*webhook|webhook.*csrf_exempt|@csrf_exempt",
    re.IGNORECASE,
)
_WEBHOOK_ROUTE_RE = re.compile(
    r"['\"](webhooks?|stripe/webhook|github/webhook|slack/events)['\"]",
    re.IGNORECASE,
)
_ALLOW_ANY_WEBHOOK_RE = re.compile(
    r"(permission_classes|authentication_classes)\s*=\s*\[\s*\]|AllowAny",
    re.IGNORECASE,
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


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _is_hardcoded_secret(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) >= 8 and not node.value.startswith(("os.", "env", "${"))
    return False


def _is_webhook_secret_name(name: str) -> bool:
    upper = name.upper()
    if upper.endswith("_WEBHOOK_SECRET") or upper.endswith("_SIGNING_SECRET"):
        return True
    if upper in {
        "WEBHOOK_SECRET",
        "WEBHOOK_SIGNING_SECRET",
        "STRIPE_WEBHOOK_SECRET",
        "GITHUB_WEBHOOK_SECRET",
        "SLACK_SIGNING_SECRET",
        "SHOPIFY_WEBHOOK_SECRET",
        "TWILIO_AUTH_TOKEN",
        "WEBHOOK_API_KEY",
    }:
        return True
    return False


def _is_verification_setting(name: str) -> bool:
    lower = name.lower()
    return any(
        token in lower
        for token in (
            "verify_webhook",
            "webhook_verify",
            "webhook_verification",
            "verify_signature",
            "validate_webhook",
            "signature_verification",
        )
    )


class _InsecureWebhookSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureWebhookSettingsFinding] = []
        self._has_webhook_context = False

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self.filename in _WEBHOOK_VIEW_FILENAMES:
            name_lower = node.name.lower()
            if "webhook" in name_lower:
                self._has_webhook_context = True
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id == "csrf_exempt":
                        self._add(
                            node.lineno,
                            "csrf_exempt_webhook",
                            "high",
                            f"Webhook handler '{node.name}' uses @csrf_exempt — verify signature instead",
                            setting=node.name,
                        )
                    elif isinstance(decorator, ast.Call):
                        func = decorator.func
                        if isinstance(func, ast.Name) and func.id == "csrf_exempt":
                            self._add(
                                node.lineno,
                                "csrf_exempt_webhook",
                                "high",
                                f"Webhook handler '{node.name}' uses @csrf_exempt — verify signature instead",
                                setting=node.name,
                            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.filename in _SETTINGS_FILENAMES:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if _is_webhook_secret_name(name) and _is_hardcoded_secret(node.value):
                        self._add(
                            node.lineno,
                            "hardcoded_webhook_secret",
                            "critical",
                            f"{name} is hardcoded — load webhook secrets from environment variables",
                            setting=name,
                        )
                    elif _is_verification_setting(name) and (
                        _is_false(node.value) or _is_none(node.value)
                    ):
                        self._add(
                            node.lineno,
                            "skip_signature_verification",
                            "critical",
                            f"{name} disables webhook signature verification",
                            setting=name,
                        )
                    elif name.upper() in {"WEBHOOK_URL", "WEBHOOK_CALLBACK_URL"}:
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            if node.value.value.lower().startswith("http://"):
                                self._add(
                                    node.lineno,
                                    "http_webhook_url",
                                    "high",
                                    f"{name} uses HTTP — webhooks must use HTTPS endpoints",
                                    setting=name,
                                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.filename in _WEBHOOK_VIEW_FILENAMES:
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in {"Webhook", "construct_event", "verify_webhook"}:
                for keyword in node.keywords:
                    if keyword.arg in {"verify", "verify_signature", "validate"}:
                        if _is_false(keyword.value) or _is_none(keyword.value):
                            self._add(
                                node.lineno,
                                "skip_signature_verification",
                                "critical",
                                f"{func_name}() called with {keyword.arg}=False — always verify webhook signatures",
                                setting=f"{func_name}.{keyword.arg}",
                            )
        self.generic_visit(node)


class InsecureWebhookSettingsAnalyzer:
    """Detect hardcoded webhook secrets, disabled verification, and unauthenticated handlers."""

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

            if filename in _SETTINGS_FILENAMES:
                if _HARDCODED_SECRET_RE.search(line):
                    findings.append(
                        InsecureWebhookSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="hardcoded_webhook_secret",
                            severity="critical",
                            message="Webhook secret is hardcoded — use environment variables",
                        )
                    )
                if _SKIP_VERIFICATION_RE.search(line):
                    findings.append(
                        InsecureWebhookSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="skip_signature_verification",
                            severity="critical",
                            message="Webhook signature verification is disabled",
                        )
                    )
                if _HTTP_WEBHOOK_URL_RE.search(line):
                    findings.append(
                        InsecureWebhookSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="http_webhook_url",
                            severity="high",
                            message="Webhook URL uses HTTP — use HTTPS for callback endpoints",
                        )
                    )

            if filename in _WEBHOOK_VIEW_FILENAMES:
                if _CSRF_EXEMPT_WEBHOOK_RE.search(line) and "webhook" in line.lower():
                    findings.append(
                        InsecureWebhookSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="csrf_exempt_webhook",
                            severity="high",
                            message="Webhook handler uses csrf_exempt — verify HMAC/signature instead",
                        )
                    )
                if _WEBHOOK_ROUTE_RE.search(line) and _ALLOW_ANY_WEBHOOK_RE.search(line):
                    findings.append(
                        InsecureWebhookSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="unauthenticated_webhook",
                            severity="high",
                            message="Webhook route may lack authentication — verify signatures on all webhook endpoints",
                        )
                    )
                if "verify=False" in line.replace(" ", "") or "verify_signature=False" in line.replace(
                    " ", ""
                ):
                    findings.append(
                        InsecureWebhookSettingsFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="skip_signature_verification",
                            severity="critical",
                            message="Webhook signature verification explicitly disabled in handler",
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
