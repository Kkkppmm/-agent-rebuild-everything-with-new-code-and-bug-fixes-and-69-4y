"""HadolintAnalyzer — audit Hadolint configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".hadolint.yaml",
    ".hadolint.yml",
    "hadolint.yaml",
    "hadolint.yml",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
IGNORED_LINE_PATTERN = re.compile(
    r"^\s*-\s*(DL\d{4}|SC\d{4}|\*|DL\*|SC\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
ALLOWED_LINE_PATTERN = re.compile(
    r"^\s*-\s*(DL\d{4}|SC\d{4}|\*|DL\*|SC\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_IGNORE_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*ignore\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_STYLE_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*style\s*(?:#.*)?$",
    re.IGNORECASE,
)
OVERRIDE_IGNORE_PATTERN = re.compile(
    r"^\s*severity\s*:\s*ignore\s*(?:#.*)?$",
    re.IGNORECASE,
)
OVERRIDE_FOR_ALL_PATTERN = re.compile(
    r"^\s*for\s*:\s*all\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
)
TRUSTED_REGISTRY_HTTP_PATTERN = re.compile(
    r"^\s*-\s*[\"']?http://",
    re.IGNORECASE,
)
INLINE_HADOLINT_IGNORE_PATTERN = re.compile(
    r"#\s*hadolint\s+ignore\s*=\s*(?:DL|SC)\d{4}",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
ROOT_USER_CODES = frozenset({"DL3002"})
VERSION_PIN_CODES = frozenset({"DL3001", "DL3006", "DL3007", "DL3008", "DL3013", "DL3018"})
CLEANUP_CODES = frozenset({"DL3009", "DL3059"})
PRIVILEGE_CODES = frozenset({"DL3044"})
COPY_CODES = frozenset({"DL3045"})
SHELLCHECK_CODES = frozenset({"SC2086", "SC2046", "SC2166"})


@dataclass
class HadolintFinding:
    """A security or best-practice issue in a Hadolint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HadolintInfo:
    """Parsed metadata about a Hadolint configuration file."""

    path: str
    lines: int = 0
    ignored_codes: list[str] = field(default_factory=list)
    allowed_codes: list[str] = field(default_factory=list)
    trusted_registries: list[str] = field(default_factory=list)
    failure_threshold: str = ""
    has_override: bool = False


@dataclass
class HadolintStats:
    """Aggregate Hadolint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_hadolint_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


def _normalize_code(raw: str) -> str:
    code = raw.strip().upper()
    if code.startswith("DL") or code.startswith("SC"):
        return code
    return code


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml` and related config files for ignored security rules,
    wildcard suppressions, permissive failure thresholds, and untrusted registries.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[HadolintFinding] | None = None
        self._stats: HadolintStats | None = None
        self._infos: list[HadolintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Hadolint configuration paths found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_hadolint_config(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[HadolintFinding], HadolintInfo]:
        findings: list[HadolintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HadolintInfo(path=rel)

        info = HadolintInfo(path=rel, lines=len(raw_lines))
        section = ""
        override_ignore_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                if INLINE_HADOLINT_IGNORE_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="inline_ignore",
                            severity="medium",
                            message="inline hadolint ignore suppresses Dockerfile checks in source",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                continue

            section_match = re.match(r"^(\w[\w-]*)\s*:", line)
            if section_match and not line.startswith(" "):
                section = section_match.group(1).lower()

            threshold_match = re.match(
                r"^\s*failure-threshold\s*:\s*(\S+)", line, re.IGNORECASE
            )
            if threshold_match:
                info.failure_threshold = threshold_match.group(1).lower()

            if FAILURE_THRESHOLD_IGNORE_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_ignore",
                        severity="high",
                        message="failure-threshold=ignore suppresses all Hadolint findings",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FAILURE_THRESHOLD_STYLE_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_style",
                        severity="medium",
                        message="failure-threshold=style hides warning-level Dockerfile issues",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if OVERRIDE_FOR_ALL_PATTERN.search(line):
                info.has_override = True

            if OVERRIDE_IGNORE_PATTERN.search(line):
                override_ignore_count += 1
                info.has_override = True

            if section == "ignored":
                ignored_match = IGNORED_LINE_PATTERN.match(line)
                if ignored_match:
                    code = _normalize_code(ignored_match.group(1))
                    info.ignored_codes.append(code)
                    if code in ("*", "DL*", "SC*"):
                        findings.append(
                            HadolintFinding(
                                kind="wildcard_ignore",
                                severity="high",
                                message="wildcard ignore pattern hides Hadolint warnings — scope to specific DL/SC codes",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )
                    elif code in ROOT_USER_CODES:
                        findings.append(
                            HadolintFinding(
                                kind="root_user_ignored",
                                severity="high",
                                message="DL3002 (root user) ignored — avoid running containers as root",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )
                    elif code in VERSION_PIN_CODES:
                        findings.append(
                            HadolintFinding(
                                kind="version_pin_ignored",
                                severity="high",
                                message=f"{code} (version pinning) ignored — pin base image and package versions",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )
                    elif code in PRIVILEGE_CODES:
                        findings.append(
                            HadolintFinding(
                                kind="privilege_ignored",
                                severity="medium",
                                message=f"{code} (sudo/privilege) ignored — avoid sudo in Dockerfiles",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )
                    elif code in SHELLCHECK_CODES:
                        findings.append(
                            HadolintFinding(
                                kind="shellcheck_ignored",
                                severity="medium",
                                message=f"{code} (shell quoting) ignored — keep shellcheck rules enabled",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )

            if section == "allowed":
                allowed_match = ALLOWED_LINE_PATTERN.match(line)
                if allowed_match:
                    info.allowed_codes.append(_normalize_code(allowed_match.group(1)))

            if section == "trustedregistries":
                registry_match = re.match(r"^\s*-\s*[\"']?([^\"'#]+)[\"']?\s*(?:#.*)?$", line)
                if registry_match:
                    registry = registry_match.group(1).strip()
                    info.trusted_registries.append(registry)

                if TRUSTED_REGISTRY_WILDCARD_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_wildcard",
                            severity="high",
                            message="trustedRegistries wildcard trusts all image sources — list explicit registries",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

                if TRUSTED_REGISTRY_HTTP_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_http",
                            severity="medium",
                            message="insecure HTTP registry in trustedRegistries — use HTTPS registries",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Hadolint config — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL in Hadolint config — use HTTPS endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl|wget piped to shell in Hadolint config — avoid remote code execution",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if override_ignore_count >= 3:
            findings.append(
                HadolintFinding(
                    kind="many_override_ignores",
                    severity="medium",
                    message=f"{override_ignore_count} override severity=ignore entries — minimize rule suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        security_ignored = [
            c
            for c in info.ignored_codes
            if c in ROOT_USER_CODES
            or c in VERSION_PIN_CODES
            or c in PRIVILEGE_CODES
            or c.endswith("*")
        ]
        if len(security_ignored) >= 4:
            findings.append(
                HadolintFinding(
                    kind="many_security_ignored",
                    severity="high",
                    message=f"{len(security_ignored)} security-related rules ignored — review Hadolint suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[HadolintFinding]:
        """Scan Hadolint config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HadolintFinding] = []
        infos: list[HadolintInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = HadolintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HadolintStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HadolintInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
        """Scaffold a hardened Hadolint configuration template."""
        return """\
# Generated by DevAI HadolintAnalyzer
# Hadolint config — https://github.com/hadolint/hadolint
# Run: hadolint Dockerfile

failure-threshold: warning

ignored: []

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Hadolint configs: none found"
        return (
            f"Hadolint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Hadolint config analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: ignored={len(info.ignored_codes)}, "
                f"threshold={info.failure_threshold or 'default'}, "
                f"trusted_registries={len(info.trusted_registries)}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
