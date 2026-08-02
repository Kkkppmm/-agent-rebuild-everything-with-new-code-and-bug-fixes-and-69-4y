"""SecurityScanner — unified static security analysis for Python projects."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.command_injection import CommandInjectionAnalyzer
from devai.dangerous_calls import DangerousCallsAnalyzer
from devai.insecure_random import InsecureRandomAnalyzer
from devai.log_injection import LogInjectionAnalyzer
from devai.path_traversal import PathTraversalAnalyzer
from devai.project import DEFAULT_IGNORE_DIRS
from devai.secrets import SecretsScanner
from devai.sql_injection import SQLInjectionAnalyzer
from devai.cors_misconfig import CorsMisconfigAnalyzer
from devai.insecure_cookies import InsecureCookieAnalyzer
from devai.mass_assignment import MassAssignmentAnalyzer
from devai.open_redirect import OpenRedirectAnalyzer
from devai.ssrf import SSRFAnalyzer
from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer
from devai.weak_crypto import WeakCryptoAnalyzer
from devai.xss_vulnerabilities import XssVulnerabilityAnalyzer

CHECK_NAMES = (
    "secrets",
    "dangerous_calls",
    "sql_injection",
    "insecure_random",
    "path_traversal",
    "command_injection",
    "weak_crypto",
    "log_injection",
    "ssrf",
    "unsafe_deserialization",
    "open_redirect",
    "xss_vulnerabilities",
    "cors_misconfig",
    "insecure_cookies",
    "mass_assignment",
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
    insecure random usage, path-traversal risks, command injection, weak crypto,
    log injection, SSRF, unsafe deserialization, open redirects, XSS, CORS,
    insecure cookies, and mass assignment into one report.
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
        self._random: InsecureRandomAnalyzer | None = None
        self._paths: PathTraversalAnalyzer | None = None
        self._command: CommandInjectionAnalyzer | None = None
        self._crypto: WeakCryptoAnalyzer | None = None
        self._logs: LogInjectionAnalyzer | None = None
        self._ssrf: SSRFAnalyzer | None = None
        self._deserialization: UnsafeDeserializationAnalyzer | None = None
        self._redirect: OpenRedirectAnalyzer | None = None
        self._xss: XssVulnerabilityAnalyzer | None = None
        self._cors: CorsMisconfigAnalyzer | None = None
        self._cookies: InsecureCookieAnalyzer | None = None
        self._mass: MassAssignmentAnalyzer | None = None

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

    def _random_analyzer(self) -> InsecureRandomAnalyzer:
        if self._random is None:
            self._random = InsecureRandomAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._random

    def _path_analyzer(self) -> PathTraversalAnalyzer:
        if self._paths is None:
            self._paths = PathTraversalAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._paths

    def _command_analyzer(self) -> CommandInjectionAnalyzer:
        if self._command is None:
            self._command = CommandInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._command

    def _crypto_analyzer(self) -> WeakCryptoAnalyzer:
        if self._crypto is None:
            self._crypto = WeakCryptoAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._crypto

    def _log_analyzer(self) -> LogInjectionAnalyzer:
        if self._logs is None:
            self._logs = LogInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._logs

    def _ssrf_analyzer(self) -> SSRFAnalyzer:
        if self._ssrf is None:
            self._ssrf = SSRFAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._ssrf

    def _deserialization_analyzer(self) -> UnsafeDeserializationAnalyzer:
        if self._deserialization is None:
            self._deserialization = UnsafeDeserializationAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._deserialization

    def _redirect_analyzer(self) -> OpenRedirectAnalyzer:
        if self._redirect is None:
            self._redirect = OpenRedirectAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._redirect

    def _xss_analyzer(self) -> XssVulnerabilityAnalyzer:
        if self._xss is None:
            self._xss = XssVulnerabilityAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._xss

    def _cors_analyzer(self) -> CorsMisconfigAnalyzer:
        if self._cors is None:
            self._cors = CorsMisconfigAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._cors

    def _cookies_analyzer(self) -> InsecureCookieAnalyzer:
        if self._cookies is None:
            self._cookies = InsecureCookieAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._cookies

    def _mass_analyzer(self) -> MassAssignmentAnalyzer:
        if self._mass is None:
            self._mass = MassAssignmentAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._mass

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
        if by_name.get("insecure_random", SecurityScanCategory("insecure_random", 100, 0, "")).findings:
            recs.append("Use secrets module for tokens, passwords, and session identifiers.")
        if by_name.get("path_traversal", SecurityScanCategory("path_traversal", 100, 0, "")).findings:
            recs.append("Validate and normalize user-supplied paths before file operations.")
        if by_name.get("command_injection", SecurityScanCategory("command_injection", 100, 0, "")).findings:
            recs.append("Avoid shell=True and never pass user input directly to os.system or subprocess.")
        if by_name.get("weak_crypto", SecurityScanCategory("weak_crypto", 100, 0, "")).findings:
            recs.append("Replace MD5/SHA1 with SHA-256+ or bcrypt/argon2 for password hashing.")
        if by_name.get("log_injection", SecurityScanCategory("log_injection", 100, 0, "")).findings:
            recs.append("Use structured logging with extra fields instead of f-strings in log messages.")
        if by_name.get("ssrf", SecurityScanCategory("ssrf", 100, 0, "")).findings:
            recs.append("Validate outbound URLs against an allowlist and block internal network ranges.")
        if by_name.get("unsafe_deserialization", SecurityScanCategory("unsafe_deserialization", 100, 0, "")).findings:
            recs.append("Never deserialize untrusted data with pickle or yaml.load — use safe formats and loaders.")
        if by_name.get("open_redirect", SecurityScanCategory("open_redirect", 100, 0, "")).findings:
            recs.append("Validate redirect destinations against a same-origin or explicit allowlist.")
        if by_name.get("xss_vulnerabilities", SecurityScanCategory("xss_vulnerabilities", 100, 0, "")).findings:
            recs.append("Avoid mark_safe and |safe filters on user input; keep autoescaping enabled.")
        if by_name.get("cors_misconfig", SecurityScanCategory("cors_misconfig", 100, 0, "")).findings:
            recs.append("Restrict CORS origins to trusted domains instead of wildcard *.")
        if by_name.get("insecure_cookies", SecurityScanCategory("insecure_cookies", 100, 0, "")).findings:
            recs.append("Set secure=True, httponly=True, and samesite='Lax' on session cookies.")
        if by_name.get("mass_assignment", SecurityScanCategory("mass_assignment", 100, 0, "")).findings:
            recs.append("Whitelist allowed model fields instead of passing request data directly to ORMs.")
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

        if "weak_crypto" in self.checks:
            analyzer = self._crypto_analyzer()
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
            analyzer = self._log_analyzer()
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

        if "unsafe_deserialization" in self.checks:
            analyzer = self._deserialization_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="unsafe_deserialization",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "open_redirect" in self.checks:
            analyzer = self._redirect_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="open_redirect",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "xss_vulnerabilities" in self.checks:
            analyzer = self._xss_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="xss_vulnerabilities",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "cors_misconfig" in self.checks:
            analyzer = self._cors_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="cors_misconfig",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "insecure_cookies" in self.checks:
            analyzer = self._cookies_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_cookies",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "mass_assignment" in self.checks:
            analyzer = self._mass_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="mass_assignment",
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
        if "insecure_random" in self.checks:
            lines.extend(["## Insecure random", self._random_analyzer().to_context(limit=limit), ""])
        if "path_traversal" in self.checks:
            lines.extend(["## Path traversal", self._path_analyzer().to_context(limit=limit), ""])
        if "command_injection" in self.checks:
            lines.extend(["## Command injection", self._command_analyzer().to_context(limit=limit), ""])
        if "weak_crypto" in self.checks:
            lines.extend(["## Weak crypto", self._crypto_analyzer().to_context(limit=limit), ""])
        if "log_injection" in self.checks:
            lines.extend(["## Log injection", self._log_analyzer().to_context(limit=limit), ""])
        if "ssrf" in self.checks:
            lines.extend(["## SSRF", self._ssrf_analyzer().to_context(limit=limit), ""])
        if "unsafe_deserialization" in self.checks:
            lines.extend(
                ["## Unsafe deserialization", self._deserialization_analyzer().to_context(limit=limit), ""]
            )
        if "open_redirect" in self.checks:
            lines.extend(["## Open redirect", self._redirect_analyzer().to_context(limit=limit), ""])
        if "xss_vulnerabilities" in self.checks:
            lines.extend(["## XSS", self._xss_analyzer().to_context(limit=limit), ""])
        if "cors_misconfig" in self.checks:
            lines.extend(["## CORS", self._cors_analyzer().to_context(limit=limit), ""])
        if "insecure_cookies" in self.checks:
            lines.extend(["## Insecure cookies", self._cookies_analyzer().to_context(limit=limit), ""])
        if "mass_assignment" in self.checks:
            lines.extend(["## Mass assignment", self._mass_analyzer().to_context(limit=limit), ""])
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
    def insecure_random(self) -> InsecureRandomAnalyzer:
        """Underlying insecure-random analyzer."""
        return self._random_analyzer()

    @property
    def path_traversal(self) -> PathTraversalAnalyzer:
        """Underlying path-traversal analyzer."""
        return self._path_analyzer()

    @property
    def command_injection(self) -> CommandInjectionAnalyzer:
        """Underlying command-injection analyzer."""
        return self._command_analyzer()

    @property
    def weak_crypto(self) -> WeakCryptoAnalyzer:
        """Underlying weak-crypto analyzer."""
        return self._crypto_analyzer()

    @property
    def log_injection(self) -> LogInjectionAnalyzer:
        """Underlying log-injection analyzer."""
        return self._log_analyzer()

    @property
    def ssrf(self) -> SSRFAnalyzer:
        """Underlying SSRF analyzer."""
        return self._ssrf_analyzer()

    @property
    def unsafe_deserialization(self) -> UnsafeDeserializationAnalyzer:
        """Underlying unsafe-deserialization analyzer."""
        return self._deserialization_analyzer()

    @property
    def open_redirect(self) -> OpenRedirectAnalyzer:
        """Underlying open-redirect analyzer."""
        return self._redirect_analyzer()

    @property
    def xss_vulnerabilities(self) -> XssVulnerabilityAnalyzer:
        """Underlying XSS vulnerability analyzer."""
        return self._xss_analyzer()

    @property
    def cors_misconfig(self) -> CorsMisconfigAnalyzer:
        """Underlying CORS misconfiguration analyzer."""
        return self._cors_analyzer()

    @property
    def insecure_cookies(self) -> InsecureCookieAnalyzer:
        """Underlying insecure-cookie analyzer."""
        return self._cookies_analyzer()

    @property
    def mass_assignment(self) -> MassAssignmentAnalyzer:
        """Underlying mass-assignment analyzer."""
        return self._mass_analyzer()
