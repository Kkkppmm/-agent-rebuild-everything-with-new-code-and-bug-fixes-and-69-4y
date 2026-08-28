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
IGNORED_RULE_PATTERN = re.compile(
    r"^\s*-\s*(DL\d{4}|SC\d{4}|\*|DL\*|SC\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORED_INLINE_PATTERN = re.compile(
    r"^\s*ignored\s*:\s*\[(?:[^\]]*\*|DL\*|SC\*)[^\]]*\]",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_LOW_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:style|info)\s*(?:#.*)?$",
    re.IGNORECASE,
)
STRICT_LABELS_FALSE_PATTERN = re.compile(
    r"^\s*strict-labels\s*:\s*false\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?[\*\.]+[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_HTTP_PATTERN = re.compile(
    r"^\s*-\s*http://",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
TAGGING_RULES = frozenset({"DL3006", "DL3007"})
PINNING_RULES = frozenset({"DL3008", "DL3013", "DL3018", "DL3027", "DL3015"})
COPY_RULES = frozenset({"DL3025"})
USER_RULES = frozenset({"DL3002", "DL3004"})
SHELL_RULES = frozenset({"DL4006", "DL4001"})
SHELLCHECK_RULES = frozenset({"SC2086", "SC2046", "SC1090", "SC1091", "SC2154"})


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
    ignored_rules: list[str] = field(default_factory=list)
    trusted_registries: list[str] = field(default_factory=list)
    failure_threshold: str = ""
    strict_labels: bool | None = None


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
    return rule.strip().upper()


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml`, `.hadolint.yml`, and `hadolint.yaml` for ignored
    tagging/pinning rules, permissive failure thresholds, broad trusted registries,
    and hardcoded secrets.
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

        if normalized in {"*", "DL*", "SC*"}:
            findings.append(
                HadolintFinding(
                    kind="ignore_wildcard",
                    severity="high",
                    message="wildcard ignored rule disables all Hadolint checks — remove blanket ignores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
            return

        if normalized in TAGGING_RULES:
            findings.append(
                HadolintFinding(
                    kind="tagging_rule_ignored",
                    severity="high",
                    message=f"{normalized} ignored — always pin Docker image tags explicitly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in PINNING_RULES:
            findings.append(
                HadolintFinding(
                    kind="pinning_rule_ignored",
                    severity="high",
                    message=f"{normalized} ignored — pin package manager versions in Dockerfiles",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in COPY_RULES:
            findings.append(
                HadolintFinding(
                    kind="copy_rule_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — prefer COPY over ADD for files and archives",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in USER_RULES:
            findings.append(
                HadolintFinding(
                    kind="user_rule_ignored",
                    severity="high",
                    message=f"{normalized} ignored — avoid running containers as root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in SHELL_RULES:
            findings.append(
                HadolintFinding(
                    kind="shell_rule_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — keep shell hardening checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in SHELLCHECK_RULES:
            findings.append(
                HadolintFinding(
                    kind="shellcheck_rule_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — keep ShellCheck integration checks enabled",
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
        in_ignored: bool,
        in_trusted: bool,
    ) -> tuple[bool, bool]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return in_ignored, in_trusted

        if re.match(r"^\s*ignored\s*:\s*$", line, re.IGNORECASE):
            return True, in_trusted

        if re.match(r"^\s*trustedRegistries\s*:\s*$", line, re.IGNORECASE):
            return in_ignored, True

        if re.match(r"^\s*allowedRegistries\s*:\s*$", line, re.IGNORECASE):
            return in_ignored, True

        if re.match(r"^\s*\w", line) and not line.startswith(" "):
            in_ignored = False
            in_trusted = False

        threshold_match = re.match(
            r"^\s*failure-threshold\s*:\s*(\S+)",
            line,
            re.IGNORECASE,
        )
        if threshold_match:
            info.failure_threshold = threshold_match.group(1).lower()

        if FAILURE_THRESHOLD_LOW_PATTERN.search(line):
            findings.append(
                HadolintFinding(
                    kind="failure_threshold_low",
                    severity="medium",
                    message="failure-threshold=style/info hides warnings — use warning or error",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_LABELS_FALSE_PATTERN.search(line):
            info.strict_labels = False
            findings.append(
                HadolintFinding(
                    kind="strict_labels_disabled",
                    severity="low",
                    message="strict-labels=false weakens OCI label validation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORED_INLINE_PATTERN.search(line):
            findings.append(
                HadolintFinding(
                    kind="ignore_wildcard",
                    severity="high",
                    message="inline wildcard ignored rules disable Hadolint checks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_ignored:
            ignored_match = IGNORED_RULE_PATTERN.match(line)
            if ignored_match:
                self._record_ignored_rule(
                    ignored_match.group(1),
                    lineno,
                    rel,
                    line,
                    findings,
                    info,
                )

        if in_trusted:
            registry_match = re.match(r"^\s*-\s*(\S+)", line)
            if registry_match:
                registry = registry_match.group(1)
                info.trusted_registries.append(registry)
                if TRUSTED_REGISTRY_WILDCARD_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_wildcard",
                            severity="high",
                            message="wildcard trusted registry allows any image source",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                if TRUSTED_REGISTRY_HTTP_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_http",
                            severity="high",
                            message="HTTP trusted registry — use HTTPS for image pulls",
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

        return in_ignored, in_trusted

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

        for lineno, line in enumerate(raw_lines, start=1):
            in_ignored, in_trusted = self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                in_ignored=in_ignored,
                in_trusted=in_trusted,
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
strict-labels: true

allowedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

trustedRegistries:
  - docker.io
  - gcr.io
  - ghcr.io

ignored: []
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
            threshold = info.failure_threshold or "warning"
            ignored = len(info.ignored_rules)
            lines.append(
                f"  - {info.path}: failure_threshold={threshold}, ignored_rules={ignored}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
