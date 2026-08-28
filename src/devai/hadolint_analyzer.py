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
IGNORE_ALL_PATTERN = re.compile(
    r"^\s*-\s*(?:\*|all|ALL)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*(?:DL\*|SC\*|\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_SECURITY_RULE_PATTERN = re.compile(
    r"^\s*-\s*(?:DL3002|DL3006|DL3007|DL3008|DL3013|DL3018|DL3025|DL3027|"
    r"SC2086|SC2046|SC2154)\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_LOW_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:info|style|ignore)\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_HTTP_PATTERN = re.compile(
    r"^\s*-\s*[\"']?http://",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
IGNORED_BLOCK_PATTERN = re.compile(
    r"^\s*ignored\s*:\s*$",
    re.IGNORECASE,
)
TRUSTED_BLOCK_PATTERN = re.compile(
    r"^\s*trustedRegistries\s*:\s*$",
    re.IGNORECASE,
)
IGNORED_INLINE_PATTERN = re.compile(
    r"^\s*-\s*(DL\d{4}|SC\d{4})\b",
    re.IGNORECASE,
)
TRUSTED_INLINE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?[^\"'\s#]+",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
USER_ROOT_RULES = frozenset({"DL3002"})
PINNING_RULES = frozenset({"DL3006", "DL3007", "DL3008", "DL3013", "DL3018"})
OWNERSHIP_RULES = frozenset({"DL3025"})
SHELL_QUOTING_RULES = frozenset({"SC2086", "SC2046", "SC2154"})


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


def _extract_rule_code(line: str) -> str | None:
    match = IGNORED_INLINE_PATTERN.match(line)
    if not match:
        return None
    return match.group(1).upper()


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml`, `.hadolint.yml`, and related config files for
    broad rule ignores, disabled security checks, permissive failure thresholds,
    insecure trusted registries, and hardcoded credentials.
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
            if path.is_file() and path not in found and _is_hadolint_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("hadolint.y*ml")):
            if path.is_file() and path not in found and _is_hadolint_config(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
        *,
        in_ignored: bool = False,
        in_trusted: bool = False,
    ) -> tuple[bool, bool]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return in_ignored, in_trusted

        if IGNORED_BLOCK_PATTERN.match(line):
            return True, False
        if TRUSTED_BLOCK_PATTERN.match(line):
            return False, True

        if re.match(r"^\s*\w", line) and not line.startswith(" "):
            in_ignored = False
            in_trusted = False

        threshold_match = re.match(
            r"^\s*failure-threshold\s*:\s*(\w+)\s*(?:#.*)?$",
            line,
            re.IGNORECASE,
        )
        if threshold_match:
            info.failure_threshold = threshold_match.group(1).lower()

        if FAILURE_THRESHOLD_LOW_PATTERN.match(line):
            findings.append(
                HadolintFinding(
                    kind="failure_threshold_low",
                    severity="medium",
                    message="permissive failure-threshold — use 'warning' or 'error' to catch Dockerfile issues",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )

        if in_ignored:
            rule = _extract_rule_code(line)
            if rule:
                info.ignored_rules.append(rule)
            if IGNORE_ALL_PATTERN.match(line) or IGNORE_WILDCARD_PATTERN.match(line):
                findings.append(
                    HadolintFinding(
                        kind="ignore_all",
                        severity="high",
                        message="ignoring all Hadolint rules — remove wildcard ignores",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            elif IGNORE_SECURITY_RULE_PATTERN.match(line):
                findings.append(
                    HadolintFinding(
                        kind="ignore_security_rule",
                        severity="high",
                        message="security-sensitive Hadolint rule ignored — re-enable pinning, USER, and shell quoting checks",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            elif rule and rule in USER_ROOT_RULES:
                findings.append(
                    HadolintFinding(
                        kind="ignore_user_root",
                        severity="high",
                        message="DL3002 (non-root USER) ignored — containers should not run as root",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            elif rule and rule in PINNING_RULES:
                findings.append(
                    HadolintFinding(
                        kind="ignore_pinning",
                        severity="medium",
                        message="version pinning rule ignored — pin base images and package versions",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if in_trusted and TRUSTED_INLINE_PATTERN.match(line):
            registry = stripped.lstrip("- ").strip().strip("\"'")
            if registry:
                info.trusted_registries.append(registry)
            if TRUSTED_REGISTRY_WILDCARD_PATTERN.match(line):
                findings.append(
                    HadolintFinding(
                        kind="trusted_registry_wildcard",
                        severity="high",
                        message="wildcard trusted registry — restrict to known registries only",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )
            if TRUSTED_REGISTRY_HTTP_PATTERN.match(line):
                findings.append(
                    HadolintFinding(
                        kind="trusted_registry_http",
                        severity="medium",
                        message="insecure HTTP trusted registry — use HTTPS registries",
                        path=rel,
                        lineno=lineno,
                        line=stripped,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                HadolintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in Hadolint config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
                )
            )
        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                HadolintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Hadolint config — rotate and use secrets management",
                    path=rel,
                    lineno=lineno,
                    line=stripped,
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
                    line=stripped,
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
                    line=stripped,
                )
            )

        return in_ignored, in_trusted

    def _analyze_file(self, path: Path) -> tuple[list[HadolintFinding], HadolintInfo]:
        findings: list[HadolintFinding] = []
        rel = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
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

        if len(info.ignored_rules) >= 10:
            findings.append(
                HadolintFinding(
                    kind="many_ignored_rules",
                    severity="medium",
                    message=f"{len(info.ignored_rules)} ignored rules — review whether security checks are disabled",
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
# hadolint — https://github.com/hadolint/hadolint
failure-threshold: warning

# Only ignore rules with documented justification:
# ignored:
#   - DL3008  # apt pinning handled in multi-stage build

trustedRegistries:
  - docker.io
  - ghcr.io
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
