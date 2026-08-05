"""SecurityScanner — unified static security analysis for Python projects."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devai.command_injection import CommandInjectionAnalyzer
from devai.cors import CORSAnalyzer
from devai.csrf import CSRFAnalyzer
from devai.dangerous_calls import DangerousCallsAnalyzer
from devai.hardcoded_config import HardcodedConfigAnalyzer
from devai.insecure_cookies import InsecureCookieAnalyzer
from devai.insecure_random import InsecureRandomAnalyzer
from devai.jwt_security import JWTSecurityAnalyzer
from devai.log_injection import LogInjectionAnalyzer
from devai.nosql_injection import NoSQLInjectionAnalyzer
from devai.open_redirect import OpenRedirectAnalyzer
from devai.path_traversal import PathTraversalAnalyzer
from devai.project import DEFAULT_IGNORE_DIRS
from devai.redos import ReDoSAnalyzer
from devai.secrets import SecretsScanner
from devai.sql_injection import SQLInjectionAnalyzer
from devai.ssrf import SSRFAnalyzer
from devai.timing_attack import TimingAttackAnalyzer
from devai.unsafe_deserialization import UnsafeDeserializationAnalyzer
from devai.weak_crypto import WeakCryptoAnalyzer
from devai.xss import XSSAnalyzer
from devai.xxe import XXEAnalyzer
from devai.ldap_injection import LDAPInjectionAnalyzer
from devai.debug_exposure import DebugExposureAnalyzer
from devai.tls_verification import TLSVerificationAnalyzer
from devai.ssti import SSTIAnalyzer
from devai.file_permissions import FilePermissionAnalyzer
from devai.information_disclosure import InformationDisclosureAnalyzer
from devai.header_injection import HeaderInjectionAnalyzer
from devai.mass_assignment import MassAssignmentAnalyzer
from devai.clickjacking import ClickjackingAnalyzer
from devai.host_header import HostHeaderAnalyzer
from devai.session_fixation import SessionFixationAnalyzer
from devai.insecure_file_upload import InsecureFileUploadAnalyzer
from devai.weak_password import WeakPasswordAnalyzer
from devai.idor import IDORAnalyzer
from devai.race_condition import RaceConditionAnalyzer
from devai.insecure_tempfile import InsecureTempfileAnalyzer
from devai.graphql_injection import GraphQLInjectionAnalyzer
from devai.broken_auth import BrokenAuthAnalyzer
from devai.insecure_http import InsecureHTTPAnalyzer
from devai.zip_slip import ZipSlipAnalyzer
from devai.dynamic_import import DynamicImportAnalyzer
from devai.assert_security import AssertSecurityAnalyzer
from devai.sensitive_logging import SensitiveLoggingAnalyzer
from devai.proxy_trust import ProxyTrustAnalyzer
from devai.wildcard_hosts import WildcardHostsAnalyzer
from devai.insecure_secret_key import InsecureSecretKeyAnalyzer
from devai.insecure_bind import InsecureBindAnalyzer
from devai.missing_timeout import MissingTimeoutAnalyzer

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
    "unsafe_deserialization",
    "open_redirect",
    "hardcoded_config",
    "timing_attack",
    "nosql_injection",
    "insecure_cookies",
    "jwt_security",
    "cors",
    "csrf",
    "redos",
    "xss",
    "xxe",
    "ldap_injection",
    "debug_exposure",
    "tls_verification",
    "ssti",
    "file_permissions",
    "information_disclosure",
    "header_injection",
    "mass_assignment",
    "clickjacking",
    "host_header",
    "session_fixation",
    "insecure_file_upload",
    "weak_password",
    "idor",
    "race_condition",
    "insecure_tempfile",
    "graphql_injection",
    "broken_auth",
    "insecure_http",
    "zip_slip",
    "dynamic_import",
    "assert_security",
    "sensitive_logging",
    "proxy_trust",
    "wildcard_hosts",
    "insecure_secret_key",
    "insecure_bind",
    "missing_timeout",
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

    Combines secrets scanning, dangerous-call detection, SQL/NoSQL injection,
    command injection, insecure random, path traversal, weak crypto, log
    injection, SSRF, unsafe deserialization, open redirect, hardcoded config,
    timing attacks, insecure cookies, JWT security, CORS, CSRF, ReDoS, XSS,
    XXE, LDAP injection, debug exposure, TLS verification, SSTI, file permissions,
    information disclosure, header injection, mass assignment, clickjacking, host header,
    session fixation, insecure file upload, weak password, IDOR, and race condition
    checks into one report.
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
        self._deserialization: UnsafeDeserializationAnalyzer | None = None
        self._redirect: OpenRedirectAnalyzer | None = None
        self._hardcoded_config: HardcodedConfigAnalyzer | None = None
        self._timing_attack: TimingAttackAnalyzer | None = None
        self._nosql: NoSQLInjectionAnalyzer | None = None
        self._cookies: InsecureCookieAnalyzer | None = None
        self._jwt: JWTSecurityAnalyzer | None = None
        self._cors: CORSAnalyzer | None = None
        self._csrf: CSRFAnalyzer | None = None
        self._redos: ReDoSAnalyzer | None = None
        self._xss: XSSAnalyzer | None = None
        self._xxe: XXEAnalyzer | None = None
        self._ldap: LDAPInjectionAnalyzer | None = None
        self._debug_exposure: DebugExposureAnalyzer | None = None
        self._tls_verification: TLSVerificationAnalyzer | None = None
        self._ssti: SSTIAnalyzer | None = None
        self._file_permissions: FilePermissionAnalyzer | None = None
        self._information_disclosure: InformationDisclosureAnalyzer | None = None
        self._header_injection: HeaderInjectionAnalyzer | None = None
        self._mass_assignment: MassAssignmentAnalyzer | None = None
        self._clickjacking: ClickjackingAnalyzer | None = None
        self._host_header: HostHeaderAnalyzer | None = None
        self._session_fixation: SessionFixationAnalyzer | None = None
        self._insecure_file_upload: InsecureFileUploadAnalyzer | None = None
        self._weak_password: WeakPasswordAnalyzer | None = None
        self._idor: IDORAnalyzer | None = None
        self._race_condition: RaceConditionAnalyzer | None = None
        self._insecure_tempfile: InsecureTempfileAnalyzer | None = None
        self._graphql_injection: GraphQLInjectionAnalyzer | None = None
        self._broken_auth: BrokenAuthAnalyzer | None = None
        self._insecure_http: InsecureHTTPAnalyzer | None = None
        self._zip_slip: ZipSlipAnalyzer | None = None
        self._dynamic_import: DynamicImportAnalyzer | None = None
        self._assert_security: AssertSecurityAnalyzer | None = None
        self._sensitive_logging: SensitiveLoggingAnalyzer | None = None
        self._proxy_trust: ProxyTrustAnalyzer | None = None
        self._wildcard_hosts: WildcardHostsAnalyzer | None = None
        self._insecure_secret_key: InsecureSecretKeyAnalyzer | None = None
        self._insecure_bind: InsecureBindAnalyzer | None = None
        self._missing_timeout: MissingTimeoutAnalyzer | None = None

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

    def _hardcoded_config_analyzer(self) -> HardcodedConfigAnalyzer:
        if self._hardcoded_config is None:
            self._hardcoded_config = HardcodedConfigAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._hardcoded_config

    def _timing_attack_analyzer(self) -> TimingAttackAnalyzer:
        if self._timing_attack is None:
            self._timing_attack = TimingAttackAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._timing_attack

    def _nosql_analyzer(self) -> NoSQLInjectionAnalyzer:
        if self._nosql is None:
            self._nosql = NoSQLInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._nosql

    def _cookies_analyzer(self) -> InsecureCookieAnalyzer:
        if self._cookies is None:
            self._cookies = InsecureCookieAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._cookies

    def _jwt_analyzer(self) -> JWTSecurityAnalyzer:
        if self._jwt is None:
            self._jwt = JWTSecurityAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._jwt

    def _cors_analyzer(self) -> CORSAnalyzer:
        if self._cors is None:
            self._cors = CORSAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._cors

    def _csrf_analyzer(self) -> CSRFAnalyzer:
        if self._csrf is None:
            self._csrf = CSRFAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._csrf

    def _redos_analyzer(self) -> ReDoSAnalyzer:
        if self._redos is None:
            self._redos = ReDoSAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._redos

    def _xss_analyzer(self) -> XSSAnalyzer:
        if self._xss is None:
            self._xss = XSSAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._xss

    def _xxe_analyzer(self) -> XXEAnalyzer:
        if self._xxe is None:
            self._xxe = XXEAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._xxe

    def _ldap_analyzer(self) -> LDAPInjectionAnalyzer:
        if self._ldap is None:
            self._ldap = LDAPInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._ldap

    def _debug_exposure_analyzer(self) -> DebugExposureAnalyzer:
        if self._debug_exposure is None:
            self._debug_exposure = DebugExposureAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._debug_exposure

    def _tls_verification_analyzer(self) -> TLSVerificationAnalyzer:
        if self._tls_verification is None:
            self._tls_verification = TLSVerificationAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._tls_verification

    def _ssti_analyzer(self) -> SSTIAnalyzer:
        if self._ssti is None:
            self._ssti = SSTIAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._ssti

    def _file_permissions_analyzer(self) -> FilePermissionAnalyzer:
        if self._file_permissions is None:
            self._file_permissions = FilePermissionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._file_permissions

    def _information_disclosure_analyzer(self) -> InformationDisclosureAnalyzer:
        if self._information_disclosure is None:
            self._information_disclosure = InformationDisclosureAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._information_disclosure

    def _header_injection_analyzer(self) -> HeaderInjectionAnalyzer:
        if self._header_injection is None:
            self._header_injection = HeaderInjectionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._header_injection

    def _mass_assignment_analyzer(self) -> MassAssignmentAnalyzer:
        if self._mass_assignment is None:
            self._mass_assignment = MassAssignmentAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._mass_assignment

    def _clickjacking_analyzer(self) -> ClickjackingAnalyzer:
        if self._clickjacking is None:
            self._clickjacking = ClickjackingAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._clickjacking

    def _host_header_analyzer(self) -> HostHeaderAnalyzer:
        if self._host_header is None:
            self._host_header = HostHeaderAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._host_header

    def _session_fixation_analyzer(self) -> SessionFixationAnalyzer:
        if self._session_fixation is None:
            self._session_fixation = SessionFixationAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._session_fixation

    def _insecure_file_upload_analyzer(self) -> InsecureFileUploadAnalyzer:
        if self._insecure_file_upload is None:
            self._insecure_file_upload = InsecureFileUploadAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._insecure_file_upload

    def _weak_password_analyzer(self) -> WeakPasswordAnalyzer:
        if self._weak_password is None:
            self._weak_password = WeakPasswordAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._weak_password

    def _idor_analyzer(self) -> IDORAnalyzer:
        if self._idor is None:
            self._idor = IDORAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._idor

    def _race_condition_analyzer(self) -> RaceConditionAnalyzer:
        if self._race_condition is None:
            self._race_condition = RaceConditionAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._race_condition

    def _insecure_tempfile_analyzer(self) -> InsecureTempfileAnalyzer:
        if self._insecure_tempfile is None:
            self._insecure_tempfile = InsecureTempfileAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._insecure_tempfile

    def _graphql_injection_analyzer(self) -> GraphQLInjectionAnalyzer:
        if self._graphql_injection is None:
            self._graphql_injection = GraphQLInjectionAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._graphql_injection

    def _broken_auth_analyzer(self) -> BrokenAuthAnalyzer:
        if self._broken_auth is None:
            self._broken_auth = BrokenAuthAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._broken_auth

    def _insecure_http_analyzer(self) -> InsecureHTTPAnalyzer:
        if self._insecure_http is None:
            self._insecure_http = InsecureHTTPAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._insecure_http

    def _zip_slip_analyzer(self) -> ZipSlipAnalyzer:
        if self._zip_slip is None:
            self._zip_slip = ZipSlipAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._zip_slip

    def _dynamic_import_analyzer(self) -> DynamicImportAnalyzer:
        if self._dynamic_import is None:
            self._dynamic_import = DynamicImportAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._dynamic_import

    def _assert_security_analyzer(self) -> AssertSecurityAnalyzer:
        if self._assert_security is None:
            self._assert_security = AssertSecurityAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._assert_security

    def _sensitive_logging_analyzer(self) -> SensitiveLoggingAnalyzer:
        if self._sensitive_logging is None:
            self._sensitive_logging = SensitiveLoggingAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._sensitive_logging

    def _proxy_trust_analyzer(self) -> ProxyTrustAnalyzer:
        if self._proxy_trust is None:
            self._proxy_trust = ProxyTrustAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._proxy_trust

    def _wildcard_hosts_analyzer(self) -> WildcardHostsAnalyzer:
        if self._wildcard_hosts is None:
            self._wildcard_hosts = WildcardHostsAnalyzer(str(self.root), ignore_dirs=self.ignore_dirs)
        return self._wildcard_hosts

    def _insecure_secret_key_analyzer(self) -> InsecureSecretKeyAnalyzer:
        if self._insecure_secret_key is None:
            self._insecure_secret_key = InsecureSecretKeyAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._insecure_secret_key

    def _insecure_bind_analyzer(self) -> InsecureBindAnalyzer:
        if self._insecure_bind is None:
            self._insecure_bind = InsecureBindAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._insecure_bind

    def _missing_timeout_analyzer(self) -> MissingTimeoutAnalyzer:
        if self._missing_timeout is None:
            self._missing_timeout = MissingTimeoutAnalyzer(
                str(self.root), ignore_dirs=self.ignore_dirs
            )
        return self._missing_timeout

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
        if by_name.get("unsafe_deserialization", SecurityScanCategory("unsafe_deserialization", 100, 0, "")).findings:
            recs.append("Never deserialize untrusted data with pickle or yaml.load — use safe formats and loaders.")
        if by_name.get("open_redirect", SecurityScanCategory("open_redirect", 100, 0, "")).findings:
            recs.append("Validate redirect destinations against a same-origin or explicit allowlist.")
        if by_name.get("hardcoded_config", SecurityScanCategory("hardcoded_config", 100, 0, "")).findings:
            recs.append("Move hardcoded URLs, IPs, and DB URLs to environment variables or config files.")
        if by_name.get("timing_attack", SecurityScanCategory("timing_attack", 100, 0, "")).findings:
            recs.append("Use hmac.compare_digest() for secret comparisons instead of == or !=.")
        if by_name.get("nosql_injection", SecurityScanCategory("nosql_injection", 100, 0, "")).findings:
            recs.append("Use parameterized NoSQL filters instead of dynamic query construction.")
        if by_name.get("insecure_cookies", SecurityScanCategory("insecure_cookies", 100, 0, "")).findings:
            recs.append("Set secure=True, httponly=True, and samesite='Lax' on session cookies.")
        if by_name.get("jwt_security", SecurityScanCategory("jwt_security", 100, 0, "")).findings:
            recs.append("Store JWT secrets in environment variables and always verify signatures.")
        if by_name.get("cors", SecurityScanCategory("cors", 100, 0, "")).findings:
            recs.append("Restrict CORS origins to trusted domains instead of wildcard (*).")
        if by_name.get("csrf", SecurityScanCategory("csrf", 100, 0, "")).findings:
            recs.append("Add CSRF tokens to state-changing form submissions and API endpoints.")
        if by_name.get("redos", SecurityScanCategory("redos", 100, 0, "")).findings:
            recs.append("Simplify regex patterns to avoid nested quantifiers that cause ReDoS.")
        if by_name.get("xss", SecurityScanCategory("xss", 100, 0, "")).findings:
            recs.append("Escape or sanitize user input before rendering in HTML responses.")
        if by_name.get("xxe", SecurityScanCategory("xxe", 100, 0, "")).findings:
            recs.append("Use defusedxml and disable external entity resolution when parsing XML.")
        if by_name.get("ldap_injection", SecurityScanCategory("ldap_injection", 100, 0, "")).findings:
            recs.append("Use parameterized LDAP filters instead of string-built search filters.")
        if by_name.get("debug_exposure", SecurityScanCategory("debug_exposure", 100, 0, "")).findings:
            recs.append("Disable DEBUG mode and avoid exposing tracebacks in production.")
        if by_name.get("tls_verification", SecurityScanCategory("tls_verification", 100, 0, "")).findings:
            recs.append("Enable TLS certificate verification — never use verify=False in production.")
        if by_name.get("ssti", SecurityScanCategory("ssti", 100, 0, "")).findings:
            recs.append("Use static templates with auto-escaping instead of rendering user-supplied template strings.")
        if by_name.get("file_permissions", SecurityScanCategory("file_permissions", 100, 0, "")).findings:
            recs.append("Use restrictive file permissions (e.g. 0o600) instead of world-readable modes.")
        if by_name.get("information_disclosure", SecurityScanCategory("information_disclosure", 100, 0, "")).findings:
            recs.append("Remove sensitive fields from API responses and avoid exposing stack traces to users.")
        if by_name.get("header_injection", SecurityScanCategory("header_injection", 100, 0, "")).findings:
            recs.append("Never place user-controlled data in HTTP response headers.")
        if by_name.get("mass_assignment", SecurityScanCategory("mass_assignment", 100, 0, "")).findings:
            recs.append("Use explicit field allowlists when updating models from request data.")
        if by_name.get("clickjacking", SecurityScanCategory("clickjacking", 100, 0, "")).findings:
            recs.append("Set X-Frame-Options: DENY or CSP frame-ancestors to prevent clickjacking.")
        if by_name.get("host_header", SecurityScanCategory("host_header", 100, 0, "")).findings:
            recs.append("Validate Host headers against an allowlist before building redirect URLs.")
        if by_name.get("session_fixation", SecurityScanCategory("session_fixation", 100, 0, "")).findings:
            recs.append("Regenerate session IDs after successful authentication.")
        if by_name.get("insecure_file_upload", SecurityScanCategory("insecure_file_upload", 100, 0, "")).findings:
            recs.append("Validate file type, extension, and size on all upload handlers.")
        if by_name.get("weak_password", SecurityScanCategory("weak_password", 100, 0, "")).findings:
            recs.append("Hash passwords with bcrypt/argon2 and enforce minimum length of 8+ characters.")
        if by_name.get("idor", SecurityScanCategory("idor", 100, 0, "")).findings:
            recs.append("Verify object ownership before returning resources by user-supplied IDs.")
        if by_name.get("race_condition", SecurityScanCategory("race_condition", 100, 0, "")).findings:
            recs.append("Use file locks or atomic operations instead of check-then-write patterns.")
        if by_name.get("insecure_tempfile", SecurityScanCategory("insecure_tempfile", 100, 0, "")).findings:
            recs.append("Use tempfile.mkstemp() or NamedTemporaryFile instead of mktemp/tempnam.")
        if by_name.get("graphql_injection", SecurityScanCategory("graphql_injection", 100, 0, "")).findings:
            recs.append("Use GraphQL variables instead of string interpolation in queries.")
        if by_name.get("broken_auth", SecurityScanCategory("broken_auth", 100, 0, "")).findings:
            recs.append("Enforce authentication on sensitive routes and avoid hardcoded credential checks.")
        if by_name.get("insecure_http", SecurityScanCategory("insecure_http", 100, 0, "")).findings:
            recs.append("Use https:// for external URLs and never disable TLS certificate verification.")
        if by_name.get("zip_slip", SecurityScanCategory("zip_slip", 100, 0, "")).findings:
            recs.append(
                "Validate archive member paths before extraction — reject '..' and absolute paths."
            )
        if by_name.get("dynamic_import", SecurityScanCategory("dynamic_import", 100, 0, "")).findings:
            recs.append("Avoid dynamic imports from user input — use an allowlist of module names.")
        if by_name.get("assert_security", SecurityScanCategory("assert_security", 100, 0, "")).findings:
            recs.append(
                "Replace security assert checks with explicit raises — asserts are removed when "
                "Python runs with -O or PYTHONOPTIMIZE."
            )
        if by_name.get("sensitive_logging", SecurityScanCategory("sensitive_logging", 100, 0, "")).findings:
            recs.append(
                "Never log passwords, tokens, or secrets — redact sensitive values before logging."
            )
        if by_name.get("proxy_trust", SecurityScanCategory("proxy_trust", 100, 0, "")).findings:
            recs.append(
                "Validate proxy headers only from trusted reverse proxies — never use "
                "X-Forwarded-For for access control without hop validation."
            )
        if by_name.get("wildcard_hosts", SecurityScanCategory("wildcard_hosts", 100, 0, "")).findings:
            recs.append(
                "Set ALLOWED_HOSTS to explicit domain names — never use '*' in production."
            )
        if by_name.get(
            "insecure_secret_key", SecurityScanCategory("insecure_secret_key", 100, 0, "")
        ).findings:
            recs.append(
                "Generate a strong random SECRET_KEY from environment variables — never use defaults."
            )
        if by_name.get("insecure_bind", SecurityScanCategory("insecure_bind", 100, 0, "")).findings:
            recs.append(
                "Bind services to 127.0.0.1 or a specific interface — avoid 0.0.0.0 unless behind a firewall."
            )
        if by_name.get("missing_timeout", SecurityScanCategory("missing_timeout", 100, 0, "")).findings:
            recs.append(
                "Add timeout=<seconds> to HTTP requests, socket connections, and subprocess calls."
            )
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

        if "nosql_injection" in self.checks:
            analyzer = self._nosql_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="nosql_injection",
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

        if "jwt_security" in self.checks:
            analyzer = self._jwt_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="jwt_security",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "cors" in self.checks:
            analyzer = self._cors_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="cors",
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

        if "xxe" in self.checks:
            analyzer = self._xxe_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="xxe",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "ldap_injection" in self.checks:
            analyzer = self._ldap_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="ldap_injection",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "debug_exposure" in self.checks:
            analyzer = self._debug_exposure_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="debug_exposure",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "tls_verification" in self.checks:
            analyzer = self._tls_verification_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="tls_verification",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "ssti" in self.checks:
            analyzer = self._ssti_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="ssti",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "file_permissions" in self.checks:
            analyzer = self._file_permissions_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="file_permissions",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "information_disclosure" in self.checks:
            analyzer = self._information_disclosure_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="information_disclosure",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "header_injection" in self.checks:
            analyzer = self._header_injection_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="header_injection",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "mass_assignment" in self.checks:
            analyzer = self._mass_assignment_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="mass_assignment",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "clickjacking" in self.checks:
            analyzer = self._clickjacking_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="clickjacking",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "host_header" in self.checks:
            analyzer = self._host_header_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="host_header",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "session_fixation" in self.checks:
            analyzer = self._session_fixation_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="session_fixation",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "insecure_file_upload" in self.checks:
            analyzer = self._insecure_file_upload_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_file_upload",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "weak_password" in self.checks:
            analyzer = self._weak_password_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="weak_password",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "idor" in self.checks:
            analyzer = self._idor_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="idor",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "race_condition" in self.checks:
            analyzer = self._race_condition_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="race_condition",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "insecure_tempfile" in self.checks:
            analyzer = self._insecure_tempfile_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_tempfile",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "graphql_injection" in self.checks:
            analyzer = self._graphql_injection_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="graphql_injection",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "broken_auth" in self.checks:
            analyzer = self._broken_auth_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="broken_auth",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "insecure_http" in self.checks:
            analyzer = self._insecure_http_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_http",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "zip_slip" in self.checks:
            analyzer = self._zip_slip_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="zip_slip",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "dynamic_import" in self.checks:
            analyzer = self._dynamic_import_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="dynamic_import",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "assert_security" in self.checks:
            analyzer = self._assert_security_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="assert_security",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "sensitive_logging" in self.checks:
            analyzer = self._sensitive_logging_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="sensitive_logging",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "proxy_trust" in self.checks:
            analyzer = self._proxy_trust_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="proxy_trust",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )

        if "wildcard_hosts" in self.checks:
            analyzer = self._wildcard_hosts_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="wildcard_hosts",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )
        if "insecure_secret_key" in self.checks:
            analyzer = self._insecure_secret_key_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_secret_key",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )
        if "insecure_bind" in self.checks:
            analyzer = self._insecure_bind_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="insecure_bind",
                    score=analyzer.health_score(),
                    findings=len(findings),
                    summary=analyzer.summary().splitlines()[0],
                )
            )
        if "missing_timeout" in self.checks:
            analyzer = self._missing_timeout_analyzer()
            findings = analyzer.analyze()
            categories.append(
                SecurityScanCategory(
                    name="missing_timeout",
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
        if "unsafe_deserialization" in self.checks:
            lines.extend(
                ["## Unsafe deserialization", self._deserialization_analyzer().to_context(limit=limit), ""]
            )
        if "open_redirect" in self.checks:
            lines.extend(["## Open redirect", self._redirect_analyzer().to_context(limit=limit), ""])
        if "hardcoded_config" in self.checks:
            lines.extend(
                ["## Hardcoded config", self._hardcoded_config_analyzer().to_context(limit=limit), ""]
            )
        if "timing_attack" in self.checks:
            lines.extend(["## Timing attack", self._timing_attack_analyzer().to_context(limit=limit), ""])
        if "nosql_injection" in self.checks:
            lines.extend(["## NoSQL injection", self._nosql_analyzer().to_context(limit=limit), ""])
        if "insecure_cookies" in self.checks:
            lines.extend(["## Insecure cookies", self._cookies_analyzer().to_context(limit=limit), ""])
        if "jwt_security" in self.checks:
            lines.extend(["## JWT security", self._jwt_analyzer().to_context(limit=limit), ""])
        if "cors" in self.checks:
            lines.extend(["## CORS", self._cors_analyzer().to_context(limit=limit), ""])
        if "csrf" in self.checks:
            lines.extend(["## CSRF", self._csrf_analyzer().to_context(limit=limit), ""])
        if "redos" in self.checks:
            lines.extend(["## ReDoS", self._redos_analyzer().to_context(limit=limit), ""])
        if "xss" in self.checks:
            lines.extend(["## XSS", self._xss_analyzer().to_context(limit=limit), ""])
        if "xxe" in self.checks:
            lines.extend(["## XXE", self._xxe_analyzer().to_context(limit=limit), ""])
        if "ldap_injection" in self.checks:
            lines.extend(["## LDAP injection", self._ldap_analyzer().to_context(limit=limit), ""])
        if "debug_exposure" in self.checks:
            lines.extend(["## Debug exposure", self._debug_exposure_analyzer().to_context(limit=limit), ""])
        if "tls_verification" in self.checks:
            lines.extend(["## TLS verification", self._tls_verification_analyzer().to_context(limit=limit), ""])
        if "ssti" in self.checks:
            lines.extend(["## SSTI", self._ssti_analyzer().to_context(limit=limit), ""])
        if "file_permissions" in self.checks:
            lines.extend(["## File permissions", self._file_permissions_analyzer().to_context(limit=limit), ""])
        if "information_disclosure" in self.checks:
            lines.extend(
                ["## Information disclosure", self._information_disclosure_analyzer().to_context(limit=limit), ""]
            )
        if "header_injection" in self.checks:
            lines.extend(["## Header injection", self._header_injection_analyzer().to_context(limit=limit), ""])
        if "mass_assignment" in self.checks:
            lines.extend(["## Mass assignment", self._mass_assignment_analyzer().to_context(limit=limit), ""])
        if "clickjacking" in self.checks:
            lines.extend(["## Clickjacking", self._clickjacking_analyzer().to_context(limit=limit), ""])
        if "host_header" in self.checks:
            lines.extend(["## Host header", self._host_header_analyzer().to_context(limit=limit), ""])
        if "session_fixation" in self.checks:
            lines.extend(["## Session fixation", self._session_fixation_analyzer().to_context(limit=limit), ""])
        if "insecure_file_upload" in self.checks:
            lines.extend(
                ["## Insecure file upload", self._insecure_file_upload_analyzer().to_context(limit=limit), ""]
            )
        if "weak_password" in self.checks:
            lines.extend(["## Weak password", self._weak_password_analyzer().to_context(limit=limit), ""])
        if "idor" in self.checks:
            lines.extend(["## IDOR", self._idor_analyzer().to_context(limit=limit), ""])
        if "race_condition" in self.checks:
            lines.extend(["## Race condition", self._race_condition_analyzer().to_context(limit=limit), ""])
        if "insecure_tempfile" in self.checks:
            lines.extend(
                ["## Insecure tempfile", self._insecure_tempfile_analyzer().to_context(limit=limit), ""]
            )
        if "graphql_injection" in self.checks:
            lines.extend(
                ["## GraphQL injection", self._graphql_injection_analyzer().to_context(limit=limit), ""]
            )
        if "broken_auth" in self.checks:
            lines.extend(["## Broken auth", self._broken_auth_analyzer().to_context(limit=limit), ""])
        if "insecure_http" in self.checks:
            lines.extend(["## Insecure HTTP", self._insecure_http_analyzer().to_context(limit=limit), ""])
        if "zip_slip" in self.checks:
            lines.extend(["## Zip slip", self._zip_slip_analyzer().to_context(limit=limit), ""])
        if "dynamic_import" in self.checks:
            lines.extend(
                ["## Dynamic import", self._dynamic_import_analyzer().to_context(limit=limit), ""]
            )
        if "assert_security" in self.checks:
            lines.extend(
                ["## Assert security", self._assert_security_analyzer().to_context(limit=limit), ""]
            )
        if "sensitive_logging" in self.checks:
            lines.extend(
                ["## Sensitive logging", self._sensitive_logging_analyzer().to_context(limit=limit), ""]
            )
        if "proxy_trust" in self.checks:
            lines.extend(
                ["## Proxy trust", self._proxy_trust_analyzer().to_context(limit=limit), ""]
            )
        if "wildcard_hosts" in self.checks:
            lines.extend(
                ["## Wildcard hosts", self._wildcard_hosts_analyzer().to_context(limit=limit), ""]
            )
        if "insecure_secret_key" in self.checks:
            lines.extend(
                [
                    "## Insecure secret keys",
                    self._insecure_secret_key_analyzer().to_context(limit=limit),
                    "",
                ]
            )
        if "insecure_bind" in self.checks:
            lines.extend(
                [
                    "## Insecure bind addresses",
                    self._insecure_bind_analyzer().to_context(limit=limit),
                    "",
                ]
            )
        if "missing_timeout" in self.checks:
            lines.extend(
                [
                    "## Missing timeouts",
                    self._missing_timeout_analyzer().to_context(limit=limit),
                    "",
                ]
            )
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
    def unsafe_deserialization(self) -> UnsafeDeserializationAnalyzer:
        """Underlying unsafe-deserialization analyzer."""
        return self._deserialization_analyzer()

    @property
    def open_redirect(self) -> OpenRedirectAnalyzer:
        """Underlying open-redirect analyzer."""
        return self._redirect_analyzer()

    @property
    def hardcoded_config(self) -> HardcodedConfigAnalyzer:
        """Underlying hardcoded-config analyzer."""
        return self._hardcoded_config_analyzer()

    @property
    def timing_attack(self) -> TimingAttackAnalyzer:
        """Underlying timing-attack analyzer."""
        return self._timing_attack_analyzer()

    @property
    def nosql_injection(self) -> NoSQLInjectionAnalyzer:
        """Underlying NoSQL injection analyzer."""
        return self._nosql_analyzer()

    @property
    def insecure_cookies(self) -> InsecureCookieAnalyzer:
        """Underlying insecure-cookie analyzer."""
        return self._cookies_analyzer()

    @property
    def jwt_security(self) -> JWTSecurityAnalyzer:
        """Underlying JWT security analyzer."""
        return self._jwt_analyzer()

    @property
    def cors(self) -> CORSAnalyzer:
        """Underlying CORS analyzer."""
        return self._cors_analyzer()

    @property
    def csrf(self) -> CSRFAnalyzer:
        """Underlying CSRF analyzer."""
        return self._csrf_analyzer()

    @property
    def redos(self) -> ReDoSAnalyzer:
        """Underlying ReDoS analyzer."""
        return self._redos_analyzer()

    @property
    def xss(self) -> XSSAnalyzer:
        """Underlying XSS analyzer."""
        return self._xss_analyzer()

    @property
    def xxe(self) -> XXEAnalyzer:
        """Underlying XXE analyzer."""
        return self._xxe_analyzer()

    @property
    def ldap_injection(self) -> LDAPInjectionAnalyzer:
        """Underlying LDAP injection analyzer."""
        return self._ldap_analyzer()

    @property
    def debug_exposure(self) -> DebugExposureAnalyzer:
        """Underlying debug-exposure analyzer."""
        return self._debug_exposure_analyzer()

    @property
    def tls_verification(self) -> TLSVerificationAnalyzer:
        """Underlying TLS verification analyzer."""
        return self._tls_verification_analyzer()

    @property
    def ssti(self) -> SSTIAnalyzer:
        """Underlying SSTI analyzer."""
        return self._ssti_analyzer()

    @property
    def file_permissions(self) -> FilePermissionAnalyzer:
        """Underlying file-permissions analyzer."""
        return self._file_permissions_analyzer()

    @property
    def information_disclosure(self) -> InformationDisclosureAnalyzer:
        """Underlying information-disclosure analyzer."""
        return self._information_disclosure_analyzer()

    @property
    def header_injection(self) -> HeaderInjectionAnalyzer:
        """Underlying header-injection analyzer."""
        return self._header_injection_analyzer()

    @property
    def mass_assignment(self) -> MassAssignmentAnalyzer:
        """Underlying mass-assignment analyzer."""
        return self._mass_assignment_analyzer()

    @property
    def clickjacking(self) -> ClickjackingAnalyzer:
        """Underlying clickjacking analyzer."""
        return self._clickjacking_analyzer()

    @property
    def host_header(self) -> HostHeaderAnalyzer:
        """Underlying host-header analyzer."""
        return self._host_header_analyzer()

    @property
    def session_fixation(self) -> SessionFixationAnalyzer:
        """Underlying session-fixation analyzer."""
        return self._session_fixation_analyzer()

    @property
    def insecure_file_upload(self) -> InsecureFileUploadAnalyzer:
        """Underlying insecure-file-upload analyzer."""
        return self._insecure_file_upload_analyzer()

    @property
    def weak_password(self) -> WeakPasswordAnalyzer:
        """Underlying weak-password analyzer."""
        return self._weak_password_analyzer()

    @property
    def idor(self) -> IDORAnalyzer:
        """Underlying IDOR analyzer."""
        return self._idor_analyzer()

    @property
    def race_condition(self) -> RaceConditionAnalyzer:
        """Underlying race-condition analyzer."""
        return self._race_condition_analyzer()

    @property
    def insecure_tempfile(self) -> InsecureTempfileAnalyzer:
        """Underlying insecure-tempfile analyzer."""
        return self._insecure_tempfile_analyzer()

    @property
    def graphql_injection(self) -> GraphQLInjectionAnalyzer:
        """Underlying GraphQL injection analyzer."""
        return self._graphql_injection_analyzer()

    @property
    def broken_auth(self) -> BrokenAuthAnalyzer:
        """Underlying broken-auth analyzer."""
        return self._broken_auth_analyzer()

    @property
    def insecure_http(self) -> InsecureHTTPAnalyzer:
        """Underlying insecure-HTTP analyzer."""
        return self._insecure_http_analyzer()

    @property
    def zip_slip(self) -> ZipSlipAnalyzer:
        """Underlying zip-slip analyzer."""
        return self._zip_slip_analyzer()

    @property
    def dynamic_import(self) -> DynamicImportAnalyzer:
        """Underlying dynamic-import analyzer."""
        return self._dynamic_import_analyzer()

    @property
    def assert_security(self) -> AssertSecurityAnalyzer:
        """Underlying assert-security analyzer."""
        return self._assert_security_analyzer()

    @property
    def sensitive_logging(self) -> SensitiveLoggingAnalyzer:
        """Underlying sensitive-logging analyzer."""
        return self._sensitive_logging_analyzer()

    @property
    def proxy_trust(self) -> ProxyTrustAnalyzer:
        """Underlying proxy-trust analyzer."""
        return self._proxy_trust_analyzer()

    @property
    def wildcard_hosts(self) -> WildcardHostsAnalyzer:
        """Underlying wildcard-hosts analyzer."""
        return self._wildcard_hosts_analyzer()

    @property
    def insecure_secret_key(self) -> InsecureSecretKeyAnalyzer:
        """Underlying insecure-secret-key analyzer."""
        return self._insecure_secret_key_analyzer()

    @property
    def insecure_bind(self) -> InsecureBindAnalyzer:
        """Underlying insecure-bind analyzer."""
        return self._insecure_bind_analyzer()

    @property
    def missing_timeout(self) -> MissingTimeoutAnalyzer:
        """Underlying missing-timeout analyzer."""
        return self._missing_timeout_analyzer()
