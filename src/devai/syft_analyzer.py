"""SyftAnalyzer — audit Syft SBOM configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SYFT_CONFIG_NAMES = (
    ".syft.yaml",
    ".syft.yml",
    "syft.yaml",
    "syft.yml",
)
SYFT_CONFIG_DIRS = ("syft",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|SYFT_[A-Z0-9]{20,}|npm_[A-Za-z0-9]{20,})[^\"'\s]*[\"']?",
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
BROAD_EXCLUDE_PATTERN = re.compile(
    r"^\s*-\s*(?:\*\*?|/\*\*?|\*\*/\*|/\*\*/\*)\s*(?:#.*)?$",
)
EXCLUDE_EVERYTHING_PATTERN = re.compile(
    r"^\s*(?:exclude-everything|excludeEverything)\s*:\s*true\s*$",
    re.IGNORECASE,
)
DISABLE_ATTEST_PATTERN = re.compile(
    r"^\s*(?:attest|attestation)\s*:\s*false\s*$",
    re.IGNORECASE,
)
DISABLE_SIGNATURE_PATTERN = re.compile(
    r"^\s*(?:verify-signature|verifySignature|signature-verification)\s*:\s*false\s*$",
    re.IGNORECASE,
)
DEV_REGISTRY_PATTERN = re.compile(
    r"(?:registry|repository|url|endpoint)\s*[:=]\s*[\"']?"
    r"(?:localhost|127\.0\.0\.1|host\.docker\.internal|registry\.local)[^\s\"']*",
    re.IGNORECASE,
)
CATALOGER_NONE_PATTERN = re.compile(
    r"^\s*(?:catalogers|default-catalogers|defaultCatalogers)\s*:\s*(?:\[\s*\]|none|null)\s*$",
    re.IGNORECASE,
)
PLAIN_OUTPUT_PATTERN = re.compile(
    r"^\s*(?:output|format)\s*:\s*[\"']?(?:table|text|template)[\"']?\s*$",
    re.IGNORECASE,
)


@dataclass
class SyftFinding:
    """A security or best-practice issue in a Syft config."""

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
class SyftInfo:
    """Parsed metadata about a Syft config file."""

    path: str
    exclude_entries: int = 0
    has_registry_config: bool = False
    has_attest_config: bool = False
    lines: int = 0


@dataclass
class SyftStats:
    """Aggregate Syft analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_syft_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in SYFT_CONFIG_NAMES:
        return True
    if path.parent.name.lower() in SYFT_CONFIG_DIRS and lower in (
        "config.yaml",
        "config.yml",
        ".syft.yaml",
        ".syft.yml",
    ):
        return True
    return False


class SyftAnalyzer:
    """Audit Syft SBOM configs for hardcoded tokens, broad exclusions, and weak defaults.

    Scans `.syft.yaml` and related configs for embedded credentials, wildcard exclusions,
    disabled attestation/signature verification, and insecure registry settings.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[SyftFinding] | None = None
        self._stats: SyftStats | None = None
        self._infos: list[SyftInfo] | None = None

    def files(self) -> list[Path]:
        """Return Syft config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_syft_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[SyftFinding], SyftInfo]:
        findings: list[SyftFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, SyftInfo(path=rel)

        info = SyftInfo(path=rel, lines=len(raw_lines))
        in_exclude_block = False
        exclude_entries = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"^\s*exclude\s*:", line, re.IGNORECASE):
                in_exclude_block = True
            elif in_exclude_block and re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                in_exclude_block = False

            if in_exclude_block and re.match(r"^\s*-\s*", line):
                exclude_entries += 1
                if BROAD_EXCLUDE_PATTERN.match(stripped):
                    findings.append(
                        SyftFinding(
                            kind="broad_exclude",
                            severity="high",
                            message="wildcard exclude hides packages from SBOM — scope exclusions to specific paths",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Syft config — use SYFT_REGISTRY_AUTH or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="insecure_http",
                        severity="high",
                        message="cleartext HTTP registry URL — use HTTPS for Syft registry mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_TLS_PATTERN.search(line):
                findings.append(
                    SyftFinding(
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
                    SyftFinding(
                        kind="registry_credentials",
                        severity="high",
                        message="inline registry credentials — use SYFT_REGISTRY_AUTH or Docker config",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EXCLUDE_EVERYTHING_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="broad_exclude",
                        severity="high",
                        message="exclude-everything produces empty SBOMs — remove or scope exclusions",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_ATTEST_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="disabled_attest",
                        severity="medium",
                        message="attestation disabled — enable SBOM attestations for supply chain verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_SIGNATURE_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="disabled_signature",
                        severity="high",
                        message="signature verification disabled — verify image/package signatures in SBOM pipelines",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DEV_REGISTRY_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="dev_registry",
                        severity="low",
                        message="local/dev registry in Syft config — ensure production SBOMs use trusted registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CATALOGER_NONE_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="empty_catalogers",
                        severity="medium",
                        message="catalogers disabled — SBOM will miss package metadata; use default catalogers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PLAIN_OUTPUT_PATTERN.search(line):
                findings.append(
                    SyftFinding(
                        kind="non_machine_output",
                        severity="low",
                        message="human-readable output format — use spdx-json or cyclonedx-json for CI and compliance",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if re.search(r"^\s*registry\s*:", line, re.IGNORECASE):
                info.has_registry_config = True

            if re.search(r"^\s*(?:attest|attestation)\s*:", line, re.IGNORECASE):
                info.has_attest_config = True

        info.exclude_entries = exclude_entries
        return findings, info

    def analyze(self) -> list[SyftFinding]:
        """Scan Syft config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SyftFinding] = []
        infos: list[SyftInfo] = []
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
        self._stats = SyftStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SyftStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SyftInfo]:
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
        """Scaffold a hardened Syft config template."""
        return """\
# Syft config — https://github.com/anchore/syft#configuration
output: cyclonedx-json
file:
  metadata:
    selection: all
# Use SYFT_REGISTRY_AUTH or Docker config for registry credentials
# registry:
#   insecure-skip-tls-verify: false
# attest:
#   enabled: true
# exclude:
#   - path: /tmp/build-cache
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Syft: none found"
        return (
            f"Syft: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Syft config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: excludes={info.exclude_entries}, "
                f"registry={info.has_registry_config}, attest={info.has_attest_config}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
