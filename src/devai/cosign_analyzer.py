"""CosignAnalyzer — audit Cosign signing configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

COSIGN_CONFIG_NAMES = (
    ".cosign.yaml",
    ".cosign.yml",
    "cosign.yaml",
    "cosign.yml",
    "cosign-policy.yaml",
    "cosign-policy.yml",
)
COSIGN_CONFIG_DIRS = ("cosign", "policy")
COSIGN_POLICY_NAMES = (
    "policy.cue",
    "policy.rego",
    "cosign-policy.cue",
    "cosign-policy.rego",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|COSIGN_[A-Z0-9]{20,}|npm_[A-Za-z0-9]{20,})[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INLINE_PRIVATE_KEY_PATTERN = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|private[_-]?key\s*[:=])",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:repository|registry|url|endpoint|mirror|proxy|http-proxy)\s*[:=]\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
INSECURE_TLS_PATTERN = re.compile(
    r"^\s*(?:insecure-skip-tls-verify|insecureSkipTLSVerify|skip-tls-verify|skip_tls_verify)\s*:\s*true\s*$",
    re.IGNORECASE,
)
INLINE_REGISTRY_AUTH_PATTERN = re.compile(
    r"^\s*(?:auth|credentials|token|username|password)\s*:\s*[\"']?[^\"'\s{][^\s\"']*[\"']?\s*$",
    re.IGNORECASE,
)
IGNORE_TLOG_PATTERN = re.compile(
    r"(?:insecure-ignore-tlog|insecureIgnoreTlog|ignore-tlog|ignoreTlog)\s*[:=]\s*true",
    re.IGNORECASE,
)
IGNORE_SCT_PATTERN = re.compile(
    r"(?:insecure-ignore-sct|insecureIgnoreSct|ignore-sct|ignoreSct)\s*[:=]\s*true",
    re.IGNORECASE,
)
ALLOW_INSECURE_REGISTRY_PATTERN = re.compile(
    r"(?:allow-insecure-registry|allowInsecureRegistry|allow-http-registry|allowHttpRegistry)\s*[:=]\s*true",
    re.IGNORECASE,
)
DISABLE_SIGNATURE_PATTERN = re.compile(
    r"(?:require-signature|requireSignature|verify-signature|verifySignature)\s*[:=]\s*false",
    re.IGNORECASE,
)
DISABLE_ATTEST_PATTERN = re.compile(
    r"(?:attest|attestation|use-sct|useSct)\s*[:=]\s*false",
    re.IGNORECASE,
)
DEV_REGISTRY_PATTERN = re.compile(
    r"(?:registry|repository|url|endpoint)\s*[:=]\s*[\"']?"
    r"(?:localhost|127\.0\.0\.1|host\.docker\.internal|registry\.local)[^\s\"']*",
    re.IGNORECASE,
)
WEAK_KEY_ALGORITHM_PATTERN = re.compile(
    r"(?:algorithm|key-algorithm|keyAlgorithm)\s*[:=]\s*[\"']?(?:rsa-1024|rsa1024|md5|sha1)[\"']?",
    re.IGNORECASE,
)
PERMISSIVE_POLICY_PATTERN = re.compile(
    r"(?:deny|reject|enforce)\s*[:=]\s*false",
    re.IGNORECASE,
)
WILDCARD_POLICY_PATTERN = re.compile(
    r"(?:match|pattern|image|subject)\s*[:=]\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
SKIP_REKOR_PATTERN = re.compile(
    r"(?:rekor-url|rekorUrl|tlog-url|tlogUrl)\s*[:=]\s*[\"']?\s*[\"']?",
    re.IGNORECASE,
)


@dataclass
class CosignFinding:
    """A security or best-practice issue in a Cosign config."""

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
class CosignInfo:
    """Parsed metadata about a Cosign config file."""

    path: str
    has_registry_config: bool = False
    has_policy_config: bool = False
    has_key_config: bool = False
    lines: int = 0


@dataclass
class CosignStats:
    """Aggregate Cosign analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cosign_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in COSIGN_CONFIG_NAMES or lower in COSIGN_POLICY_NAMES:
        return True
    if path.parent.name.lower() in COSIGN_CONFIG_DIRS and lower in (
        "config.yaml",
        "config.yml",
        ".cosign.yaml",
        ".cosign.yml",
        "policy.cue",
        "policy.rego",
    ):
        return True
    return False


class CosignAnalyzer:
    """Audit Cosign signing configs for hardcoded keys, disabled verification, and weak defaults.

    Scans `.cosign.yaml`, policy files, and related configs for embedded private keys,
    disabled transparency log verification, permissive signing policies, and insecure registry settings.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[CosignFinding] | None = None
        self._stats: CosignStats | None = None
        self._infos: list[CosignInfo] | None = None

    def files(self) -> list[Path]:
        """Return Cosign config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cosign_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[CosignFinding], CosignInfo]:
        findings: list[CosignFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CosignInfo(path=rel)

        info = CosignInfo(path=rel, lines=len(raw_lines))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Cosign config — use COSIGN_PASSWORD or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_PRIVATE_KEY_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="inline_private_key",
                        severity="high",
                        message="private key embedded in config — store keys in KMS, Vault, or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP registry URL — use HTTPS for Cosign registry mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_TLS_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="insecure_tls",
                        severity="high",
                        message="TLS verification disabled — do not skip TLS verify for registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_REGISTRY_AUTH_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="registry_credentials",
                        severity="high",
                        message="inline registry credentials — use COSIGN_REGISTRY_AUTH or Docker config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if IGNORE_TLOG_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="ignore_tlog",
                        severity="high",
                        message="transparency log verification disabled — always verify Rekor/Sigstore tlog entries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if IGNORE_SCT_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="ignore_sct",
                        severity="high",
                        message="SCT verification disabled — enable certificate transparency checks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALLOW_INSECURE_REGISTRY_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="insecure_registry",
                        severity="high",
                        message="insecure registry allowed — restrict Cosign to trusted HTTPS registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_SIGNATURE_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="disabled_signature",
                        severity="high",
                        message="signature verification disabled — require signatures for all signed artifacts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_ATTEST_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="disabled_attest",
                        severity="medium",
                        message="attestation disabled — enable SCT/attestation for supply chain verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DEV_REGISTRY_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="dev_registry",
                        severity="low",
                        message="local/dev registry in Cosign config — ensure production signing uses trusted registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WEAK_KEY_ALGORITHM_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="weak_key_algorithm",
                        severity="high",
                        message="weak signing key algorithm — use ECDSA P-256 or RSA-2048+ for Cosign keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PERMISSIVE_POLICY_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="permissive_policy",
                        severity="high",
                        message="permissive signing policy — enforce deny-by-default policy for image signatures",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_POLICY_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="wildcard_policy",
                        severity="medium",
                        message="wildcard policy match — scope Cosign policies to specific image patterns",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_REKOR_PATTERN.search(line):
                findings.append(
                    CosignFinding(
                        kind="missing_rekor",
                        severity="medium",
                        message="empty Rekor/tlog URL — configure Sigstore transparency log endpoint",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if re.search(r"^\s*registry\s*:", line, re.IGNORECASE):
                info.has_registry_config = True

            if re.search(r"^\s*(?:policy|authorities|images)\s*:", line, re.IGNORECASE):
                info.has_policy_config = True

            if re.search(r"^\s*(?:key|private-key|privateKey|kms)\s*:", line, re.IGNORECASE):
                info.has_key_config = True

        return findings, info

    def analyze(self) -> list[CosignFinding]:
        """Scan Cosign config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CosignFinding] = []
        infos: list[CosignInfo] = []
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
        self._stats = CosignStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CosignStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CosignInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
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
        """Scaffold a hardened Cosign config template."""
        return """\
# Cosign config — https://docs.sigstore.dev/cosign/overview/
# Use COSIGN_PASSWORD or KMS for key management — never commit private keys
registry:
  insecure-skip-tls-verify: false
# require-signature: true
# attest: true
# rekor-url: https://rekor.sigstore.dev
# policy:
#   authorities:
#     - key:
#         data: |
#           -----BEGIN PUBLIC KEY-----
#           # paste your Cosign public key here
#           -----END PUBLIC KEY-----
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Cosign: none found"
        return (
            f"Cosign: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Cosign config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: registry={info.has_registry_config}, "
                f"policy={info.has_policy_config}, key={info.has_key_config}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
