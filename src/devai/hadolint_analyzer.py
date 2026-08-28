"""HadolintAnalyzer — audit Hadolint Dockerfile lint configs for hygiene and security risks."""

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
FAILURE_THRESHOLD_NONE_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:none|style|info)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORED_RULE_PATTERN = re.compile(
    r"^\s*-\s*(DL\d{4}|\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORED_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*DL\*\s*(?:#.*)?$|^\s*-\s*\*\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
OVERRIDE_DOWNGRADE_PATTERN = re.compile(
    r"^\s*(?:warning|info|style)\s*:\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
ROOT_USER_CODES = frozenset({"DL3002"})
LATEST_TAG_CODES = frozenset({"DL3007"})
PIN_VERSION_CODES = frozenset({"DL3008", "DL3013", "DL3018", "DL4001"})
CACHE_CLEANUP_CODES = frozenset({"DL3009", "DL3047"})
HEALTHCHECK_CODES = frozenset({"DL3045", "DL4000"})
SECURITY_CODES = ROOT_USER_CODES | LATEST_TAG_CODES | PIN_VERSION_CODES | CACHE_CLEANUP_CODES | HEALTHCHECK_CODES


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
    failure_threshold: str = ""
    ignored_rules: list[str] = field(default_factory=list)
    trusted_registries: list[str] = field(default_factory=list)
    override_sections: list[str] = field(default_factory=list)


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


def _normalize_rule_code(raw: str) -> str:
    code = raw.strip().upper()
    if code.startswith("DL"):
        return code
    if re.fullmatch(r"\d{4}", code):
        return f"DL{code}"
    return code


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml` and related config files for permissive failure thresholds,
    ignored security rules (DL3002/DL3007/DL3008), wildcard ignores, broad trusted
    registries, override downgrades, and hardcoded secrets.
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

    def _record_ignored_rule(
        self,
        rule: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
    ) -> None:
        normalized = _normalize_rule_code(rule)
        info.ignored_rules.append(normalized)

        if normalized in ("*", "DL*"):
            findings.append(
                HadolintFinding(
                    kind="wildcard_ignore",
                    severity="high",
                    message="wildcard ignored rule suppresses all Hadolint checks — scope to specific DL codes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
            return

        if normalized in ROOT_USER_CODES:
            findings.append(
                HadolintFinding(
                    kind="root_user_ignored",
                    severity="high",
                    message="DL3002 ignored — do not disable root-user container checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in LATEST_TAG_CODES:
            findings.append(
                HadolintFinding(
                    kind="latest_tag_ignored",
                    severity="high",
                    message="DL3007 ignored — pin image tags instead of using :latest",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in PIN_VERSION_CODES:
            findings.append(
                HadolintFinding(
                    kind="pin_version_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — keep package version pinning checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in CACHE_CLEANUP_CODES:
            findings.append(
                HadolintFinding(
                    kind="cache_cleanup_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — keep apt/apk cache cleanup checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in HEALTHCHECK_CODES:
            findings.append(
                HadolintFinding(
                    kind="healthcheck_ignored",
                    severity="low",
                    message=f"{normalized} ignored — keep Dockerfile healthcheck hygiene checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[HadolintFinding], HadolintInfo]:
        findings: list[HadolintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HadolintInfo(path=rel)

        info = HadolintInfo(path=rel, lines=len(raw_lines))
        in_ignored = False
        in_trusted = False
        in_override = False
        override_section = ""

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            threshold_match = re.match(
                r"^\s*failure-threshold\s*:\s*(\S+)",
                line,
                re.IGNORECASE,
            )
            if threshold_match:
                info.failure_threshold = threshold_match.group(1).lower()

            if FAILURE_THRESHOLD_NONE_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_permissive",
                        severity="high",
                        message="failure-threshold is permissive — use error or warning to catch Dockerfile issues",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if re.match(r"^\s*ignored\s*:\s*$", line, re.IGNORECASE):
                in_ignored = True
                in_trusted = False
                in_override = False
                continue

            if re.match(r"^\s*trustedregistries\s*:\s*$", line, re.IGNORECASE):
                in_trusted = True
                in_ignored = False
                in_override = False
                continue

            if re.match(r"^\s*override\s*:\s*$", line, re.IGNORECASE):
                in_override = True
                in_ignored = False
                in_trusted = False
                continue

            if OVERRIDE_DOWNGRADE_PATTERN.search(line):
                override_section = stripped.rstrip(":").lower()
                info.override_sections.append(override_section)
                if override_section in ("warning", "info", "style"):
                    findings.append(
                        HadolintFinding(
                            kind="override_downgrade",
                            severity="medium",
                            message=f"override.{override_section} downgrades Hadolint severities — avoid weakening Dockerfile checks",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                continue

            if in_ignored:
                ignored_match = re.match(r"^\s*-\s*(.+?)\s*(?:#.*)?$", line)
                if ignored_match:
                    self._record_ignored_rule(
                        ignored_match.group(1).strip().strip("\"'"),
                        lineno,
                        rel,
                        line,
                        findings,
                        info,
                    )
                    continue
                if stripped and not stripped.startswith("-"):
                    in_ignored = False

            if in_trusted:
                registry_match = re.match(r"^\s*-\s*(.+?)\s*(?:#.*)?$", line)
                if registry_match:
                    registry = registry_match.group(1).strip().strip("\"'")
                    info.trusted_registries.append(registry)
                    if registry in ("*", "''", '""'):
                        findings.append(
                            HadolintFinding(
                                kind="trusted_registry_wildcard",
                                severity="high",
                                message="trustedRegistries includes wildcard — restrict trusted image registries",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )
                    continue
                if stripped and not stripped.startswith("-"):
                    in_trusted = False

            if IGNORED_WILDCARD_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="wildcard_ignore",
                        severity="high",
                        message="wildcard ignored rule suppresses Hadolint checks — scope to specific DL codes",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if TRUSTED_REGISTRY_WILDCARD_PATTERN.search(line) and "trusted" in line.lower():
                findings.append(
                    HadolintFinding(
                        kind="trusted_registry_wildcard",
                        severity="high",
                        message="trustedRegistries includes wildcard — restrict trusted image registries",
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

        security_ignored = [
            code for code in info.ignored_rules if code in SECURITY_CODES or code.endswith("*")
        ]
        if len(security_ignored) >= 3:
            findings.append(
                HadolintFinding(
                    kind="many_security_ignored",
                    severity="medium",
                    message=f"{len(security_ignored)} security-related Hadolint rules ignored — minimize suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[HadolintFinding]:
        """Scan Hadolint configs and return findings."""
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HadolintInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
# Hadolint — https://github.com/hadolint/hadolint
failure-threshold: error

ignored: []

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

# override:
#   error:
#     - DL3007
"""

    def summary(self) -> str:
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
        self.analyze()
        stats = self.stats
        lines = [
            "Hadolint config analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            threshold = info.failure_threshold or "default"
            lines.append(
                f"  - {info.path}: failure_threshold={threshold}, "
                f"ignored={len(info.ignored_rules)}, "
                f"trusted_registries={len(info.trusted_registries)}"
            )
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
