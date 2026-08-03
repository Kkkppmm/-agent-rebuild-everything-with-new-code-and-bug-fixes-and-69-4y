"""SecurityScanner — unified static security analysis for Python projects."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.command_injection import CommandInjectionAnalyzer
from devai.csrf import CSRFAnalyzer
from devai.dangerous_calls import DangerousCallsAnalyzer
from devai.hardcoded_config import HardcodedConfigAnalyzer
from devai.insecure_random import InsecureRandomAnalyzer
from devai.log_injection import LogInjectionAnalyzer
from devai.open_redirect import OpenRedirectAnalyzer
from devai.path_traversal import PathTraversalAnalyzer
from devai.project import DEFAULT_IGNORE_DIRS
from devai.redos import ReDoSAnalyzer
from devai.secrets import SecretsScanner
from devai.sql_injection import SQLInjectionAnalyzer
from devai.ssrf import SSRFAnalyzer
from devai.timing_attack import TimingAttackAnalyzer
from devai.weak_crypto import WeakCryptoAnalyzer
from devai.xss import XSSAnalyzer

CHECK_NAMES = (
    "secrets",
    "dangerous_calls",
    "sql_injection",
    "command_injection",
    "insecure_random",
    "path_traversal",
    "weak_crypto",
    "log_injection",
    "ssrf",
    "xss",
    "csrf",
    "redos",
    "open_redirect",
    "timing_attack",
    "hardcoded_config",
)


@dataclass
class SecurityScanCategory:
    """Score and summary for one security check."""

    name: str
    score: float
    findings: int
    summary: str


@dataclass
class SecurityScanReport:
    """Aggregate security scan report."""

    root: str
    overall_score: float
    total_findings: int
    categories: list[SecurityScanCategory] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Security scan: {self.overall_score:.0f}/100",
            f"Root: {self.root}",
            f"Total findings: {self.total_findings}",
            "",
        ]
        for cat in self.categories:
            lines.append(f"  {cat.name}: {cat.score:.0f}/100 — {cat.findings} findings")
        if self.recommendations:
            lines.append("")
            lines.append("Recommendations:")
            for rec in self.recommendations:
                lines.append(f"  - {rec}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Export as a JSON-serializable dict."""
        return {
            "root": self.root,
            "overall_score": self.overall_score,
            "total_findings": self.total_findings,
            "categories": [
                {
                    "name": c.name,
                    "score": c.score,
                    "findings": c.findings,
                    "summary": c.summary,
                }
                for c in self.categories
            ],
            "recommendations": self.recommendations,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export as formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Export as a Markdown report."""
        lines = [
            "# Security Scan Report",
            "",
            f"**Overall score:** {self.overall_score:.0f}/100",
            f"**Root:** `{self.root}`",
            f"**Total findings:** {self.total_findings}",
            "",
            "## Checks",
            "",
            "| Check | Score | Findings | Summary |",
            "|-------|-------|----------|---------|",
        ]
        for cat in self.categories:
            safe_summary = cat.summary.replace("|", "\\|")
            lines.append(
                f"| {cat.name} | {cat.score:.0f} | {cat.findings} | {safe_summary} |"
            )
        if self.recommendations:
            lines.extend(["", "## Recommendations", ""])
            for rec in self.recommendations:
                lines.append(f"- {rec}")
        return "\n".join(lines)


class SecurityScanner:
    """Run multiple static security analyzers and aggregate results.

    Combines secrets scanning, dangerous-call detection, SQL injection checks,
    command injection checks, insecure random usage, path-traversal risks,
    weak crypto usage, log injection risks, SSRF risks, XSS, CSRF, ReDoS,
    open redirect, timing attacks, and hardcoded configuration into one report.
  """

    def __init__(
        self,
        root: str,
        *,
        checks: tuple[str, ...] | list[str] | None = None,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        requested = tuple(checks) if checks is not None else CHECK_NAMES
        unknown = set(requested) - set(CHECK_NAMES)
        if unknown:
            raise ValueError(f"Unknown security checks: {sorted(unknown)}")
        self.checks = requested
        self._report: SecurityScanReport | None = None
        self._secrets: SecretsScanner | None = None
        self._dangerous: DangerousCallsAnalyzer | None = None
        self._sql: SQLInjectionAnalyzer | None = None
        self._command: CommandInjectionAnalyzer | None = None
        self._random: InsecureRandomAnalyzer | None = None
        self._paths: PathTraversalAnalyzer | None = None
        self._weak_crypto: WeakCryptoAnalyzer | None = None
        self._log_injection: LogInjectionAnalyzer | None = None
        self._ssrf: SSRFAnalyzer | None = None
        self._xss: XSSAnalyzer | None = None
        self._csrf: CSRFAnalyzer | None = None
        self._redos: ReDoSAnalyzer | None = None
        self._open_redirect: OpenRedirectAnalyzer | None = None
        self._timing_attack: TimingAttackAnalyzer | None = None
        self._hardcoded_config: HardcodedConfigAnalyzer | None = None

    def _secrets_scanner(self) -> SecretsScanner:
        if self._secrets is None:
            self._secrets = SecretsScanner(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._secrets

    def _dangerous_analyzer(self) -> DangerousCallsAnalyzer:
        if self._dangerous is None:
            self._dangerous = DangerousCallsAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._dangerous

    def _sql_analyzer(self) -> SQLInjectionAnalyzer:
        if self._sql is None:
            self._sql = SQLInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._sql

    def _command_analyzer(self) -> CommandInjectionAnalyzer:
        if self._command is None:
            self._command = CommandInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._command

    def _random_analyzer(self) -> InsecureRandomAnalyzer:
        if self._random is None:
            self._random = InsecureRandomAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._random

    def _path_analyzer(self) -> PathTraversalAnalyzer:
        if self._paths is None:
            self._paths = PathTraversalAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._paths

    def _weak_crypto_analyzer(self) -> WeakCryptoAnalyzer:
        if self._weak_crypto is None:
            self._weak_crypto = WeakCryptoAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._weak_crypto

    def _log_injection_analyzer(self) -> LogInjectionAnalyzer:
        if self._log_injection is None:
            self._log_injection = LogInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._log_injection

    def _ssrf_analyzer(self) -> SSRFAnalyzer:
        if self._ssrf is None:
            self._ssrf = SSRFAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._ssrf

    def _xss_analyzer(self) -> XSSAnalyzer:
        if self._xss is None:
            self._xss = XSSAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._xss

    def _csrf_analyzer(self) -> CSRFAnalyzer:
        if self._csrf is None:
            self._csrf = CSRFAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._csrf

    def _redos_analyzer(self) -> ReDoSAnalyzer:
        if self._redos is None:
            self._redos = ReDoSAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._redos

    def _open_redirect_analyzer(self) -> OpenRedirectAnalyzer:
        if self._open_redirect is None:
            self._open_redirect = OpenRedirectAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._open_redirect

    def _timing_attack_analyzer(self) -> TimingAttackAnalyzer:
        if self._timing_attack is None:
            self._timing_attack = TimingAttackAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._timing_attack

    def _hardcoded_config_analyzer(self) -> HardcodedConfigAnalyzer:
        if self._hardcoded_config is None:
            self._hardcoded_config = HardcodedConfigAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._hardcoded_config

    def _secrets_score(self, findings: int) -> float:
        if findings == 0:
            return 100.0
        return round(max(0.0, 100.0 - findings * 25.0), 1)

    def _build_recommendations(self, categories: list[SecurityScanCategory]) -> list[str]:
        recs: list[str] = []
        by_name = {cat.name: cat for cat in categories}
        if by_name.get("secrets", SecurityScanCategory("secrets", 100, 0, "")).findings:
            recs.append("Rotate exposed credentials and move secrets to environment variables.")
        if by_name.get("dangerous_calls", SecurityScanCategory("dangerous_calls", 100, 0, "")).findings:
            recs.append("Replace eval/exec and shell=True subprocess calls with safer alternatives.")
        if by_name.get("sql_injection", SecurityScanCategory("sql_injection", 100, 0, "")).findings:
            recs.append("Use parameterized queries instead of string-built SQL.")
        if by_name.get("command_injection", SecurityScanCategory("command_injection", 100, 0, "")).findings:
            recs.append("Pass subprocess argv as a list instead of building shell commands from user input.")
        if by_name.get("insecure_random", SecurityScanCategory("insecure_random", 100, 0, "")).findings:
            recs.append("Use secrets module for tokens, passwords, and session identifiers.")
        if by_name.get("path_traversal", SecurityScanCategory("path_traversal", 100, 0, "")).findings:
            recs.append("Validate and normalize user-supplied paths before file operations.")
        if by_name.get("weak_crypto", SecurityScanCategory("weak_crypto", 100, 0, "")).findings:
            recs.append("Replace MD5/SHA1 with bcrypt, scrypt, argon2, or SHA-256+ for security use.")
        if by_name.get("log_injection", SecurityScanCategory("log_injection", 100, 0, "")).findings:
            recs.append("Use structured logging with extra={} instead of interpolating user data into messages.")
        if by_name.get("ssrf", SecurityScanCategory("ssrf", 100, 0, "")).findings:
            recs.append("Validate outbound URLs, block internal/private IP ranges, and use an allowlist of hosts.")
        if by_name.get("xss", SecurityScanCategory("xss", 100, 0, "")).findings:
            recs.append("Escape user input in HTML output and use auto-escaping templates.")
        if by_name.get("csrf", SecurityScanCategory("csrf", 100, 0, "")).findings:
            recs.append("Add CSRF token validation to all state-changing routes.")
        if by_name.get("redos", SecurityScanCategory("redos", 100, 0, "")).findings:
            recs.append("Simplify regex patterns to avoid nested quantifiers and catastrophic backtracking.")
        if by_name.get("open_redirect", SecurityScanCategory("open_redirect", 100, 0, "")).findings:
            recs.append("Validate redirect URLs against an allowlist of trusted domains.")
        if by_name.get("timing_attack", SecurityScanCategory("timing_attack", 100, 0, "")).findings:
            recs.append("Use hmac.compare_digest() or secrets.compare_digest() for secret comparisons.")
        if by_name.get("hardcoded_config", SecurityScanCategory("hardcoded_config", 100, 0, "")).findings:
            recs.append("Move configuration values to environment variables or a secrets manager.")
        return recs

    def scan(self) -> SecurityScanReport:
        """Run all configured security checks and return an aggregate report."""
        if self._report is not None:
            return self._report

        categories: list[SecurityScanCategory] = []

        if "secrets" in self.checks:
            scanner = self._secrets_scanner()
            findings = scanner.scan()
            score = self._secrets_score(len(findings))
            categories.append(
                SecurityScanCategory(
                    name="secrets",
                    score=score,
                    findings=len(findings),
                    summary=scanner.summary().splitlines()[0] if findings else "No secrets found",
                )
            )

        if "dangerous_calls" in self.checks:
            analyzer = self._dangerous_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="dangerous_calls",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "sql_injection" in self.checks:
            analyzer = self._sql_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="sql_injection",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "command_injection" in self.checks:
            analyzer = self._command_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="command_injection",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "insecure_random" in self.checks:
            analyzer = self._random_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_random",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "path_traversal" in self.checks:
            analyzer = self._path_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="path_traversal",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "weak_crypto" in self.checks:
            analyzer = self._weak_crypto_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="weak_crypto",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "log_injection" in self.checks:
            analyzer = self._log_injection_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="log_injection",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "ssrf" in self.checks:
            analyzer = self._ssrf_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="ssrf",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "xss" in self.checks:
            analyzer = self._xss_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="xss",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "csrf" in self.checks:
            analyzer = self._csrf_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="csrf",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "redos" in self.checks:
            analyzer = self._redos_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="redos",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "open_redirect" in self.checks:
            analyzer = self._open_redirect_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="open_redirect",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "timing_attack" in self.checks:
            analyzer = self._timing_attack_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="timing_attack",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "hardcoded_config" in self.checks:
            analyzer = self._hardcoded_config_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="hardcoded_config",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        total_findings = sum(cat.findings for cat in categories)
        overall = 100.0
        if categories:
            overall = round(sum(cat.score for cat in categories) / len(categories), 1)

        self._report = SecurityScanReport(
            root=str(self.root),
            overall_score=overall,
            total_findings=total_findings,
            categories=categories,
            recommendations=self._build_recommendations(categories),
        )
        return self._report

    @property
    def report(self) -> SecurityScanReport:
        """Return the scan report, running a scan on first access."""
        return self.scan()

    def health_score(self) -> float:
        """Return the overall security health score (0-100)."""
        return self.scan().overall_score

    def summary(self) -> str:
        """Return a human-readable summary."""
        return self.report.summary()

    def to_context(self, limit: int = 40) -> str:
        """Build LLM-ready context from security scan results."""
        report = self.scan()
        lines = ["Security scan results:", report.summary(), ""]
        if "secrets" in self.checks:
            lines.extend(["## Secrets", self._secrets_scanner().to_context(max_findings=limit), ""])
        if "dangerous_calls" in self.checks:
            lines.extend(["## Dangerous calls", self._dangerous_analyzer().to_context(limit=limit), ""])
        if "sql_injection" in self.checks:
            lines.extend(["## SQL injection", self._sql_analyzer().to_context(limit=limit), ""])
        if "command_injection" in self.checks:
            lines.extend(["## Command injection", self._command_analyzer().to_context(limit=limit), ""])
        if "insecure_random" in self.checks:
            lines.extend(["## Insecure random", self._random_analyzer().to_context(limit=limit), ""])
        if "path_traversal" in self.checks:
            lines.extend(["## Path traversal", self._path_analyzer().to_context(limit=limit), ""])
        if "weak_crypto" in self.checks:
            lines.extend(["## Weak crypto", self._weak_crypto_analyzer().to_context(limit=limit), ""])
        if "log_injection" in self.checks:
            lines.extend(["## Log injection", self._log_injection_analyzer().to_context(limit=limit), ""])
        if "ssrf" in self.checks:
            lines.extend(["## SSRF", self._ssrf_analyzer().to_context(limit=limit), ""])
        if "xss" in self.checks:
            lines.extend(["## XSS", self._xss_analyzer().to_context(limit=limit), ""])
        if "csrf" in self.checks:
            lines.extend(["## CSRF", self._csrf_analyzer().to_context(limit=limit), ""])
        if "redos" in self.checks:
            lines.extend(["## ReDoS", self._redos_analyzer().to_context(limit=limit), ""])
        if "open_redirect" in self.checks:
            lines.extend(["## Open redirect", self._open_redirect_analyzer().to_context(limit=limit), ""])
        if "timing_attack" in self.checks:
            lines.extend(["## Timing attack", self._timing_attack_analyzer().to_context(limit=limit), ""])
        if "hardcoded_config" in self.checks:
            lines.extend(["## Hardcoded config", self._hardcoded_config_analyzer().to_context(limit=limit), ""])
        return "\n".join(lines).rstrip()

    @property
    def secrets(self) -> SecretsScanner:
        """Underlying secrets scanner."""
        return self._secrets_scanner()

    @property
    def dangerous_calls(self) -> DangerousCallsAnalyzer:
        """Underlying dangerous-calls analyzer."""
        return self._dangerous_analyzer()

    @property
    def sql_injection(self) -> SQLInjectionAnalyzer:
        """Underlying SQL injection analyzer."""
        return self._sql_analyzer()

    @property
    def command_injection(self) -> CommandInjectionAnalyzer:
        """Underlying command injection analyzer."""
        return self._command_analyzer()

    @property
    def insecure_random(self) -> InsecureRandomAnalyzer:
        """Underlying insecure-random analyzer."""
        return self._random_analyzer()

    @property
    def path_traversal(self) -> PathTraversalAnalyzer:
        """Underlying path-traversal analyzer."""
        return self._path_analyzer()

    @property
    def weak_crypto(self) -> WeakCryptoAnalyzer:
        """Underlying weak-crypto analyzer."""
        return self._weak_crypto_analyzer()

    @property
    def log_injection(self) -> LogInjectionAnalyzer:
        """Underlying log-injection analyzer."""
        return self._log_injection_analyzer()

    @property
    def ssrf(self) -> SSRFAnalyzer:
        """Underlying SSRF analyzer."""
        return self._ssrf_analyzer()

    @property
    def xss(self) -> XSSAnalyzer:
        """Underlying XSS analyzer."""
        return self._xss_analyzer()

    @property
    def csrf(self) -> CSRFAnalyzer:
        """Underlying CSRF analyzer."""
        return self._csrf_analyzer()

    @property
    def redos(self) -> ReDoSAnalyzer:
        """Underlying ReDoS analyzer."""
        return self._redos_analyzer()

    @property
    def open_redirect(self) -> OpenRedirectAnalyzer:
        """Underlying open-redirect analyzer."""
        return self._open_redirect_analyzer()

    @property
    def timing_attack(self) -> TimingAttackAnalyzer:
        """Underlying timing-attack analyzer."""
        return self._timing_attack_analyzer()

    @property
    def hardcoded_config(self) -> HardcodedConfigAnalyzer:
        """Underlying hardcoded-config analyzer."""
        return self._hardcoded_config_analyzer()
