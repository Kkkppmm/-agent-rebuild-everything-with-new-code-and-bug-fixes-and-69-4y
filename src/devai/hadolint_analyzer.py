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
FAILURE_THRESHOLD_PERMISSIVE_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:info|style)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_RULE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?(DL\d{4})[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
OVERRIDE_SECTION_PATTERN = re.compile(
    r"^\s*(error|warning|info|style)\s*:\s*$",
    re.IGNORECASE,
)
OVERRIDE_RULE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?(DL\d{4})[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_PATTERN = re.compile(
    r"^\s*-\s*[\"']?([^\"'\s#]+)[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
ROOT_USER_RULES = frozenset({"DL3002"})
LATEST_TAG_RULES = frozenset({"DL3007"})
SECRET_RULES = frozenset({"DL3044", "DL3045"})
VERSION_PIN_RULES = frozenset({"DL3006", "DL3008", "DL3013", "DL3018", "DL3016", "DL3028"})
ADD_COPY_RULES = frozenset({"DL3019", "DL3020"})
PRIVILEGE_RULES = frozenset({"DL3004", "DL3005"})
CMD_JSON_RULES = frozenset({"DL3025"})


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
    override_levels: dict[str, list[str]] = field(default_factory=dict)


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


def _normalize_rule(rule: str) -> str:
    return rule.upper()


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml`, `.hadolint.yml`, and `hadolint.yaml` for ignored root-user,
    latest-tag, and secret rules, permissive failure thresholds, wildcard ignores,
  insecure trusted registries, and hardcoded credentials.
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
        normalized = _normalize_rule(rule)
        info.ignored_rules.append(normalized)

        if normalized in ROOT_USER_RULES:
            findings.append(
                HadolintFinding(
                    kind="root_user_ignored",
                    severity="high",
                    message=f"{normalized} ignored — containers should not run as root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in LATEST_TAG_RULES:
            findings.append(
                HadolintFinding(
                    kind="latest_tag_ignored",
                    severity="high",
                    message=f"{normalized} ignored — pin image tags instead of using :latest",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in SECRET_RULES:
            findings.append(
                HadolintFinding(
                    kind="secret_rule_ignored",
                    severity="high",
                    message=f"{normalized} ignored — do not embed secrets in Dockerfile ARG/ENV",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in VERSION_PIN_RULES:
            findings.append(
                HadolintFinding(
                    kind="version_pin_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — pin package versions in Dockerfile installs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in ADD_COPY_RULES:
            findings.append(
                HadolintFinding(
                    kind="add_copy_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — prefer COPY over ADD for local files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in PRIVILEGE_RULES:
            findings.append(
                HadolintFinding(
                    kind="privilege_rule_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — avoid sudo and apt-get upgrade in images",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in CMD_JSON_RULES:
            findings.append(
                HadolintFinding(
                    kind="cmd_json_ignored",
                    severity="low",
                    message=f"{normalized} ignored — use JSON array notation for CMD/ENTRYPOINT",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _record_override_rule(
        self,
        level: str,
        rule: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
    ) -> None:
        normalized = _normalize_rule(rule)
        info.override_levels.setdefault(level.lower(), []).append(normalized)

        if level.lower() in {"info", "style"}:
            if normalized in ROOT_USER_RULES | LATEST_TAG_RULES | SECRET_RULES:
                findings.append(
                    HadolintFinding(
                        kind="security_rule_demoted",
                        severity="high",
                        message=(
                            f"{normalized} demoted to {level.lower()} — "
                            "keep root-user, tag, and secret rules at error severity"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif normalized in VERSION_PIN_RULES | ADD_COPY_RULES | PRIVILEGE_RULES:
                findings.append(
                    HadolintFinding(
                        kind="hygiene_rule_demoted",
                        severity="medium",
                        message=(
                            f"{normalized} demoted to {level.lower()} — "
                            "keep Dockerfile hygiene rules at error severity"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
        elif level.lower() == "warning":
            if normalized in ROOT_USER_RULES | LATEST_TAG_RULES | SECRET_RULES:
                findings.append(
                    HadolintFinding(
                        kind="security_rule_demoted",
                        severity="high",
                        message=(
                            f"{normalized} demoted to warning — "
                            "keep root-user, tag, and secret rules at error severity"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
        *,
        section: str | None,
        override_level: str | None,
    ) -> tuple[str | None, str | None]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section, override_level

        threshold_match = re.match(
            r"^\s*failure-threshold\s*:\s*(\S+)",
            line,
            re.IGNORECASE,
        )
        if threshold_match:
            info.failure_threshold = threshold_match.group(1).lower()

        if FAILURE_THRESHOLD_PERMISSIVE_PATTERN.search(line):
            findings.append(
                HadolintFinding(
                    kind="failure_threshold_permissive",
                    severity="high",
                    message="failure-threshold info/style weakens Dockerfile linting — prefer error or warning",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if line.lower().startswith("ignored:"):
            return "ignored", override_level

        if line.lower().startswith("trustedregistries:"):
            return "trustedregistries", override_level

        if line.lower().startswith("override:"):
            return "override", None

        override_section = OVERRIDE_SECTION_PATTERN.match(line)
        if override_section and section == "override":
            return section, override_section.group(1).lower()

        if section == "ignored":
            if IGNORE_WILDCARD_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="ignore_wildcard",
                        severity="high",
                        message="wildcard ignored rule disables all Hadolint checks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            ignore_match = IGNORE_RULE_PATTERN.match(line)
            if ignore_match:
                self._record_ignored_rule(
                    ignore_match.group(1),
                    lineno,
                    rel,
                    line,
                    findings,
                    info,
                )

        if section == "trustedregistries":
            registry_match = TRUSTED_REGISTRY_PATTERN.match(line)
            if registry_match:
                registry = registry_match.group(1)
                info.trusted_registries.append(registry)
                if registry.lower().startswith("http://"):
                    findings.append(
                        HadolintFinding(
                            kind="insecure_registry",
                            severity="high",
                            message="trusted registry uses insecure HTTP — use HTTPS registries",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        if section == "override" and override_level:
            override_match = OVERRIDE_RULE_PATTERN.match(line)
            if override_match:
                self._record_override_rule(
                    override_level,
                    override_match.group(1),
                    lineno,
                    rel,
                    line,
                    findings,
                    info,
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

        return section, override_level

    def _analyze_file(self, path: Path) -> tuple[list[HadolintFinding], HadolintInfo]:
        findings: list[HadolintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HadolintInfo(path=rel)

        info = HadolintInfo(path=rel, lines=len(raw_lines))
        section: str | None = None
        override_level: str | None = None

        for lineno, line in enumerate(raw_lines, start=1):
            section, override_level = self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                section=section,
                override_level=override_level,
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
failure-threshold: warning

ignored: []

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

override:
  error:
    - DL3002
    - DL3006
    - DL3007
    - DL3019
    - DL3044
    - DL3045
  warning:
    - DL3008
    - DL3013
    - DL3018
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "hadolint configs: none found"
        return (
            f"hadolint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "hadolint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            threshold = info.failure_threshold or "default"
            ignored = len(info.ignored_rules)
            lines.append(f"  - {info.path}: failure_threshold={threshold}, ignored_rules={ignored}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
