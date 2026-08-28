"""HadolintAnalyzer — audit Hadolint configuration files for Dockerfile lint hygiene and security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".hadolint.yaml",
    ".hadolint.yml",
    ".hadolint.json",
    "hadolint.yaml",
    "hadolint.yml",
    "hadolint.json",
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
    r"^\s*-\s*(DL\d{4}|SC\d{4})\b",
    re.IGNORECASE,
)
IGNORED_JSON_PATTERN = re.compile(
    r"[\"'](DL\d{4}|SC\d{4})[\"']",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(info|style)\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_JSON_PATTERN = re.compile(
    r"[\"']failure-threshold[\"']\s*:\s*[\"'](info|style)[\"']",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_BROAD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*\.[^\"'\s]+[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
DISABLE_ALL_PATTERN = re.compile(
    r"^\s*ignored\s*:\s*\[\s*\]\s*(?:#.*)?$",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
ROOT_USER_RULES = frozenset({"DL3002", "DL3004"})
TAG_RULES = frozenset({"DL3006", "DL3007"})
PIN_VERSION_RULES = frozenset({"DL3008", "DL3013", "DL3016", "DL3027"})
HEALTHCHECK_RULES = frozenset({"DL3045", "DL3057"})
SHELL_RULES = frozenset({"DL4006", "SC2016", "SC2086"})
CMD_RULES = frozenset({"DL3001", "DL3025"})
APT_RULES = frozenset({"DL3009", "DL3015", "DL3008"})


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
    format: str = "yaml"
    ignored_rules: list[str] = field(default_factory=list)
    failure_threshold: str = ""
    trusted_registries: list[str] = field(default_factory=list)


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


def _rule_category(rule: str) -> str | None:
    upper = rule.upper()
    if upper in ROOT_USER_RULES:
        return "root_user"
    if upper in TAG_RULES:
        return "tag_pinning"
    if upper in PIN_VERSION_RULES:
        return "version_pinning"
    if upper in HEALTHCHECK_RULES:
        return "healthcheck"
    if upper in SHELL_RULES:
        return "shell_safety"
    if upper in CMD_RULES:
        return "cmd_entrypoint"
    if upper in APT_RULES:
        return "apt_hygiene"
    return None


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml`, `.hadolint.yml`, and `.hadolint.json` for ignored
    security rules, permissive failure thresholds, broad trusted registries,
    and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HadolintFinding] | None = None
        self._stats: HadolintStats | None = None
        self._infos: list[HadolintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Hadolint configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".hadolint.*")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _add_ignored_rule_finding(
        self,
        rule: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
    ) -> None:
        upper = rule.upper()
        if upper in info.ignored_rules:
            return
        info.ignored_rules.append(upper)
        category = _rule_category(upper)
        if category == "root_user":
            findings.append(
                HadolintFinding(
                    kind="ignored_root_user_rule",
                    severity="high",
                    message=f"ignored {upper} — running containers as root is a security risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif category == "tag_pinning":
            findings.append(
                HadolintFinding(
                    kind="ignored_tag_rule",
                    severity="medium",
                    message=f"ignored {upper} — unpinned image tags cause supply-chain drift",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif category == "version_pinning":
            findings.append(
                HadolintFinding(
                    kind="ignored_version_pin_rule",
                    severity="medium",
                    message=f"ignored {upper} — unpinned package versions reduce reproducibility",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif category == "healthcheck":
            findings.append(
                HadolintFinding(
                    kind="ignored_healthcheck_rule",
                    severity="medium",
                    message=f"ignored {upper} — missing HEALTHCHECK hides container failures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif category == "shell_safety":
            findings.append(
                HadolintFinding(
                    kind="ignored_shell_rule",
                    severity="high",
                    message=f"ignored {upper} — shell quoting/pipefail issues can cause runtime failures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif category == "cmd_entrypoint":
            findings.append(
                HadolintFinding(
                    kind="ignored_cmd_rule",
                    severity="medium",
                    message=f"ignored {upper} — CMD/ENTRYPOINT issues affect container startup",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif category == "apt_hygiene":
            findings.append(
                HadolintFinding(
                    kind="ignored_apt_rule",
                    severity="low",
                    message=f"ignored {upper} — apt hygiene rules help keep images lean and secure",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _scan_security_patterns(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HadolintFinding],
    ) -> None:
        if HARDCODED_SECRET_PATTERN.search(line):
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

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                HadolintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Hadolint config — rotate and use secret stores",
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

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
        section: str = "",
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        self._scan_security_patterns(line, lineno, rel, findings)

        if re.match(r"^\s*ignored\s*:", stripped, re.IGNORECASE):
            return "ignored"
        if re.match(r"^\s*trustedRegistries\s*:", stripped, re.IGNORECASE):
            return "trustedRegistries"
        if re.match(r"^\s*(?:override|label)\s*:", stripped, re.IGNORECASE):
            return "override"

        if FAILURE_THRESHOLD_PATTERN.match(stripped):
            threshold = stripped.split(":", 1)[1].strip().split("#", 1)[0].strip()
            info.failure_threshold = threshold
            findings.append(
                HadolintFinding(
                    kind="permissive_failure_threshold",
                    severity="medium",
                    message=f"failure-threshold is '{threshold}' — use 'warning' or 'error' for CI gates",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
            return ""

        if stripped and not stripped.startswith("-") and ":" in stripped and not stripped.startswith("{"):
            return ""

        ignored_match = IGNORED_LINE_PATTERN.match(stripped)
        if ignored_match and section == "ignored":
            self._add_ignored_rule_finding(
                ignored_match.group(1), lineno, rel, line, findings, info
            )

        if TRUSTED_REGISTRY_WILDCARD_PATTERN.match(stripped) and section == "trustedRegistries":
            info.trusted_registries.append("*")
            findings.append(
                HadolintFinding(
                    kind="trusted_registry_wildcard",
                    severity="high",
                    message="trustedRegistries includes '*' — trusts all registries without verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif TRUSTED_REGISTRY_BROAD_PATTERN.match(stripped) and section == "trustedRegistries":
            registry = stripped.lstrip("- ").strip().strip("\"'")
            info.trusted_registries.append(registry)
            findings.append(
                HadolintFinding(
                    kind="trusted_registry_broad",
                    severity="medium",
                    message=f"trustedRegistries includes broad pattern '{registry}' — prefer explicit hosts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif (
            stripped.startswith("- ")
            and section == "trustedRegistries"
            and "trusted" not in stripped.lower()
        ):
            registry = stripped.lstrip("- ").strip().strip("\"'")
            if registry and not registry.startswith("DL") and not registry.startswith("SC"):
                if registry not in info.trusted_registries:
                    info.trusted_registries.append(registry)

        return section

    def _scan_json_content(
        self,
        content: str,
        rel: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
    ) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            for lineno, line in enumerate(content.splitlines(), start=1):
                self._scan_line(line, lineno, rel, findings, info)
            return

        threshold = data.get("failure-threshold", "")
        if isinstance(threshold, str) and threshold.lower() in ("info", "style"):
            info.failure_threshold = threshold
            findings.append(
                HadolintFinding(
                    kind="permissive_failure_threshold",
                    severity="medium",
                    message=f"failure-threshold is '{threshold}' — use 'warning' or 'error' for CI gates",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        ignored = data.get("ignored", [])
        if isinstance(ignored, list):
            for rule in ignored:
                if isinstance(rule, str):
                    self._add_ignored_rule_finding(rule, 1, rel, str(rule), findings, info)

        registries = data.get("trustedRegistries", [])
        if isinstance(registries, list):
            for idx, registry in enumerate(registries, start=1):
                if not isinstance(registry, str):
                    continue
                info.trusted_registries.append(registry)
                if registry == "*":
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_wildcard",
                            severity="high",
                            message="trustedRegistries includes '*' — trusts all registries without verification",
                            path=rel,
                            lineno=idx,
                            line=registry,
                        )
                    )
                elif registry.startswith("*."):
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_broad",
                            severity="medium",
                            message=f"trustedRegistries includes broad pattern '{registry}' — prefer explicit hosts",
                            path=rel,
                            lineno=idx,
                            line=registry,
                        )
                    )

        for lineno, line in enumerate(content.splitlines(), start=1):
            self._scan_security_patterns(line, lineno, rel, findings)

    def _analyze_file(self, path: Path) -> tuple[list[HadolintFinding], HadolintInfo]:
        findings: list[HadolintFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw_lines = raw.splitlines()
        fmt = "json" if path.suffix.lower() == ".json" else "yaml"
        info = HadolintInfo(path=rel, lines=len(raw_lines), format=fmt)

        if fmt == "json":
            self._scan_json_content(raw, rel, findings, info)
        else:
            current_section = ""
            for lineno, line in enumerate(raw_lines, start=1):
                current_section = self._scan_line(
                    line, lineno, rel, findings, info, section=current_section
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
# hadolint — https://github.com/hadolint/hadolint
failure-threshold: warning

# Only ignore rules with documented justification
ignored: []

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

override:
  error:
    - DL3002
    - DL3004
    - DL3006
    - DL3007
    - DL3013
    - DL3016
    - DL3045
    - DL4006
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
            lines.append(
                f"  - {info.path}: format={info.format}, "
                f"failure_threshold={threshold}, ignored_rules={ignored}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
