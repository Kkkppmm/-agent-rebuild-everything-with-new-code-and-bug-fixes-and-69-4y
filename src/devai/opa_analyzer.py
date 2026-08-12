"""OPAAnalyzer — audit Open Policy Agent (Rego) policy files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PACKAGE_PATTERN = re.compile(r"^\s*package\s+[\w.]+", re.IGNORECASE)
DEFAULT_ALLOW_TRUE_PATTERN = re.compile(
    r"^\s*default\s+allow\s*(?:=|:=)\s*true\s*$",
    re.IGNORECASE,
)
ALLOW_TRUE_PATTERN = re.compile(
    r"^\s*allow\s*(?:\{|if\s*\{)\s*true\s*\}?\s*$",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|xox[baprs]-)[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INSECURE_TLS_PATTERN = re.compile(
    r"(?:[\"']?(?:tls_insecure_skip_verify|insecure_skip_verify|skip_tls_verify)[\"']?\s*:\s*true)",
    re.IGNORECASE,
)
HTTP_SEND_PATTERN = re.compile(r"\bhttp\.send\s*\(", re.IGNORECASE)
NET_LOOKUP_PATTERN = re.compile(r"\bnet\.lookup_host\s*\(", re.IGNORECASE)
WILDCARD_GLOB_PATTERN = re.compile(
    r"glob\.match\s*\(\s*[\"']\*[\"']",
    re.IGNORECASE,
)
WILDCARD_INPUT_PATTERN = re.compile(
    r"^\s*(?:input|data)\s*==\s*[\"']?\*[\"']?\s*$",
    re.IGNORECASE,
)
TRACE_PATTERN = re.compile(r"^\s*(?:trace|print)\s*\(", re.IGNORECASE)
DISABLED_CRYPTO_PATTERN = re.compile(
    r"(?:crypto\.x509\.parse_and_verify|tls\.verify)\s*\([^)]*\)\s*;\s*false",
    re.IGNORECASE,
)
BYPASS_VERIFICATION_PATTERN = re.compile(
    r"(?:verify|validate|check)\s*:\s*false",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|endpoint|host)\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
EMPTY_RULE_PATTERN = re.compile(
    r"^\s*(?:allow|deny)\s*(?:\{|if\s*\{)\s*\}\s*$",
    re.IGNORECASE,
)
IMPORT_UNSAFE_PATTERN = re.compile(
    r"^\s*import\s+(?:data\.|input\.)",
    re.IGNORECASE,
)


@dataclass
class OPAFinding:
    """A security or best-practice issue in an OPA Rego policy file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class OPAInfo:
    """Parsed metadata about an OPA policy file."""

    path: str
    package: str = ""
    rule_count: int = 0
    deny_count: int = 0
    has_default_deny: bool = False
    lines: int = 0


@dataclass
class OPAStats:
    """Aggregate OPA analysis statistics."""

    policies: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_opa_file(path: Path) -> bool:
    if path.suffix.lower() != ".rego":
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(PACKAGE_PATTERN.search(text) or re.search(r"\b(?:allow|deny)\b", text))


class OPAAnalyzer:
    """Audit OPA Rego policies for permissive defaults, insecure http.send, and wildcard matches.

    Scans ``.rego`` files for ``default allow = true``, unconditional allow rules, TLS bypass,
    hardcoded secrets, debug trace/print statements, and overly broad glob patterns.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[OPAFinding] | None = None
        self._stats: OPAStats | None = None
        self._infos: list[OPAInfo] | None = None

    def files(self) -> list[Path]:
        """Return OPA Rego policy files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_opa_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[OPAFinding], OPAInfo]:
        findings: list[OPAFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, OPAInfo(path=rel)

        info = OPAInfo(path=rel, lines=len(raw_lines))
        has_allow_rules = False
        has_default_allow = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            pkg_match = re.match(r"^\s*package\s+([\w.]+)", line, re.IGNORECASE)
            if pkg_match:
                info.package = pkg_match.group(1)

            if re.search(r"^\s*(?:allow|deny)\b", line, re.IGNORECASE):
                if re.search(r"\bdeny\b", line, re.IGNORECASE):
                    info.deny_count += 1
                else:
                    has_allow_rules = True
                    info.rule_count += 1

            if re.search(r"^\s*default\s+allow\b", line, re.IGNORECASE):
                has_default_allow = True
                if DEFAULT_ALLOW_TRUE_PATTERN.search(line):
                    findings.append(
                        OPAFinding(
                            kind="default_allow_true",
                            severity="high",
                            message="default allow = true permits all requests — use default allow = false and explicit allow rules",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif re.search(r"default\s+allow\s*(?:=|:=)\s*false", line, re.IGNORECASE):
                    info.has_default_deny = True

            if ALLOW_TRUE_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="unconditional_allow",
                        severity="high",
                        message="unconditional allow { true } grants access to all inputs — add explicit constraints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_TLS_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="insecure_tls",
                        severity="high",
                        message="TLS verification disabled in OPA policy — remove tls_insecure_skip_verify or insecure_skip_verify",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HTTP_SEND_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="http_send",
                        severity="medium",
                        message="http.send in Rego policy — validate URLs and avoid user-controlled endpoints to prevent SSRF",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if NET_LOOKUP_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="net_lookup",
                        severity="medium",
                        message="net.lookup_host in Rego policy — validate hostnames to prevent DNS rebinding or SSRF",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_GLOB_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="wildcard_glob",
                        severity="medium",
                        message="wildcard glob.match(\"*\") matches all values — scope patterns to specific prefixes or suffixes",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_INPUT_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="wildcard_input",
                        severity="high",
                        message="wildcard input match bypasses authorization — use specific attribute checks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if TRACE_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="debug_trace",
                        severity="low",
                        message="trace/print statement in policy — remove debug output from production policies",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BYPASS_VERIFICATION_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="bypass_verification",
                        severity="high",
                        message="verification disabled in OPA policy — enable signature or certificate validation",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in OPA policy — use OPA secrets or environment-backed data",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="hardcoded_token",
                        severity="high",
                        message="hardcoded token in OPA policy — use Secret references or OPA bundles",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP endpoint in OPA policy — use HTTPS for remote data sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EMPTY_RULE_PATTERN.search(line):
                findings.append(
                    OPAFinding(
                        kind="empty_rule",
                        severity="low",
                        message="empty allow/deny rule block — remove or implement policy logic",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if has_allow_rules and not has_default_allow and not info.has_default_deny:
            findings.append(
                OPAFinding(
                    kind="missing_default_deny",
                    severity="medium",
                    message="allow rules without default allow = false — undefined inputs may be denied unexpectedly or allowed by engine defaults",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        if info.rule_count == 0 and info.deny_count == 0 and info.package:
            findings.append(
                OPAFinding(
                    kind="empty_policy",
                    severity="low",
                    message="OPA policy file defines a package but no allow or deny rules",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        return findings, info

    def analyze(self) -> list[OPAFinding]:
        """Scan OPA Rego policy files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[OPAFinding] = []
        infos: list[OPAInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = OPAStats(
            policies=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> OPAStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[OPAInfo]:
        """Return parsed policy file metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no policy files)."""
        self.analyze()
        stats = self.stats
        if stats.policies == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened OPA Rego policy template."""
        return """\
package example.authz

import rego.v1

default allow := false

allow if {
    input.method == "GET"
    input.path == "/health"
    input.user in data.allowed_users
}

deny contains msg if {
    not input.user
    msg := "authentication required"
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.policies == 0:
            return "OPA: none found"
        return (
            f"OPA: {stats.policies} policy file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "OPA policy analysis:",
            f"  policy files: {stats.policies}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: package={info.package or 'unknown'}, "
                f"allow_rules={info.rule_count}, deny_rules={info.deny_count}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
