"""InsecureStripeSettingsAnalyzer — detect insecure Stripe payment configuration."""

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
        "payments.py",
        "stripe.py",
    }
)
_STRIPE_KEY_RE = re.compile(
    r"(STRIPE_SECRET_KEY|STRIPE_API_KEY)\s*=\s*['\"]sk_(live|test)_[^'\"]+['\"]",
    re.IGNORECASE,
)
_WEBHOOK_SECRET_RE = re.compile(
    r"STRIPE_WEBHOOK_SECRET\s*=\s*['\"]whsec_[^'\"]+['\"]",
    re.IGNORECASE,
)
_LIVE_KEY_IN_TEST_RE = re.compile(
    r"STRIPE_SECRET_KEY\s*=\s*['\"]sk_live_",
    re.IGNORECASE,
)


@dataclass
class InsecureStripeSettingsFinding:
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
class InsecureStripeSettingsStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class _InsecureStripeSettingsVisitor(ast.NodeVisitor):
    def __init__(self, path: str, filename: str) -> None:
        self.path = path
        self.filename = filename
        self.findings: list[InsecureStripeSettingsFinding] = []

    def _add(
        self,
        lineno: int,
        pattern: str,
        severity: str,
        message: str,
        setting: str = "",
    ) -> None:
        self.findings.append(
            InsecureStripeSettingsFinding(
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
            if name in {"STRIPE_SECRET_KEY", "STRIPE_API_KEY"}:
                value = _string_value(node.value)
                if value is not None and value.startswith(("sk_live_", "sk_test_")):
                    severity = "critical" if value.startswith("sk_live_") else "high"
                    self._add(
                        node.lineno,
                        "hardcoded_stripe_secret",
                        severity,
                        f"{target.id} is hardcoded — load Stripe keys from environment variables",
                        setting=target.id,
                    )
            elif name == "STRIPE_WEBHOOK_SECRET":
                value = _string_value(node.value)
                if value is not None and value.startswith("whsec_"):
                    self._add(
                        node.lineno,
                        "hardcoded_webhook_secret",
                        "critical",
                        f"{target.id} is hardcoded — load webhook secrets from environment",
                        setting=target.id,
                    )
            elif name == "STRIPE_PUBLISHABLE_KEY":
                value = _string_value(node.value)
                if value is not None and value.startswith("pk_live_"):
                    self._add(
                        node.lineno,
                        "hardcoded_live_publishable_key",
                        "medium",
                        f"{target.id} live key is hardcoded — prefer environment variables",
                        setting=target.id,
                    )
        self.generic_visit(node)


class InsecureStripeSettingsAnalyzer:
    """Detect insecure Stripe payment API configuration."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureStripeSettingsFinding] = []
        self._stats: InsecureStripeSettingsStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_source(
        self, rel: str, source: str, filename: str
    ) -> list[InsecureStripeSettingsFinding]:
        findings: list[InsecureStripeSettingsFinding] = []
        try:
            tree = ast.parse(source, filename=rel)
            visitor = _InsecureStripeSettingsVisitor(rel, filename)
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
            if _STRIPE_KEY_RE.search(line):
                severity = "critical" if _LIVE_KEY_IN_TEST_RE.search(line) else "high"
                findings.append(
                    InsecureStripeSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_stripe_secret",
                        severity=severity,
                        message="Stripe secret key is hardcoded — load from environment variables",
                        setting="STRIPE_SECRET_KEY",
                    )
                )
            if _WEBHOOK_SECRET_RE.search(line):
                findings.append(
                    InsecureStripeSettingsFinding(
                        path=rel,
                        lineno=lineno,
                        pattern="hardcoded_webhook_secret",
                        severity="critical",
                        message="Stripe webhook secret is hardcoded — load from environment",
                        setting="STRIPE_WEBHOOK_SECRET",
                    )
                )
        return findings

    def analyze(self) -> list[InsecureStripeSettingsFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureStripeSettingsFinding] = []
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
        self._stats = InsecureStripeSettingsStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureStripeSettingsStats:
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
            f"Insecure Stripe settings: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure Stripe settings analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure Stripe configuration patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
