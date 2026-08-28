"""HadolintAnalyzer — audit Hadolint Dockerfile lint configuration files."""

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
    r"^\s*-\s*(?:\*|['\"]?\*['\"]?|all|DL\d{4}\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_SECURITY_RULE_PATTERN = re.compile(
    r"^\s*-\s*DL(?:3002|3006|3008|3013|3015|3018|3025|3027|3029|3030|3045|3059)\b",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_WILDCARD_PATTERN = re.compile(
    r"trustedRegistries\s*:\s*[^\n]*\*",
    re.IGNORECASE,
)
TRUSTED_REGISTRY_ALL_PATTERN = re.compile(
    r"^\s*-\s*(?:\*|['\"]?\*['\"]?|all)\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_HIGH_PATTERN = re.compile(
    r"failure-threshold\s*:\s*(?:error|warning|info|style)\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_STYLE_PATTERN = re.compile(
    r"failure-threshold\s*:\s*style\s*(?:#.*)?$",
    re.IGNORECASE,
)
ALLOWED_REGISTRY_INSECURE_PATTERN = re.compile(
    r"^\s*-\s*[\"']?http://",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
OVERRIDE_ERROR_PATTERN = re.compile(
    r"override\s*:\s*error\s*(?:#.*)?$",
    re.IGNORECASE,
)

SECURITY_RULE_CODES = frozenset({
    "DL3002", "DL3006", "DL3008", "DL3013", "DL3015", "DL3018",
    "DL3025", "DL3027", "DL3029", "DL3030", "DL3045", "DL3059",
})


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


def _extract_list_item(line: str) -> str | None:
    match = re.match(r"^\s*-\s*(.+?)(?:\s*#.*)?$", line)
    if not match:
        return None
    return match.group(1).strip().strip("\"'")


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml` and related config files for ignored security rules,
    wildcard trusted registries, permissive failure thresholds, and hardcoded secrets.
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
        in_ignored_block = False
        in_registry_block = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^\s*ignored\s*:\s*$", line, re.IGNORECASE):
                in_ignored_block = True
                in_registry_block = False
                continue
            if re.match(r"^\s*trustedRegistries\s*:\s*$", line, re.IGNORECASE):
                in_registry_block = True
                in_ignored_block = False
                continue
            if in_ignored_block and not line.startswith(" ") and not line.startswith("\t"):
                in_ignored_block = False
            if in_registry_block and not line.startswith(" ") and not line.startswith("\t"):
                in_registry_block = False

            threshold_match = re.search(
                r"failure-threshold\s*:\s*(\w+)", line, re.IGNORECASE
            )
            if threshold_match:
                info.failure_threshold = threshold_match.group(1).lower()

            if FAILURE_THRESHOLD_STYLE_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_style",
                        severity="medium",
                        message="failure-threshold:style allows style issues in CI — use warning or error",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif FAILURE_THRESHOLD_HIGH_PATTERN.search(line) and info.failure_threshold == "info":
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_info",
                        severity="low",
                        message="failure-threshold:info is permissive — use warning or error for CI",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if OVERRIDE_ERROR_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="override_error",
                        severity="medium",
                        message="override:error downgrades all rules — avoid blanket severity override",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_ignored_block:
                item = _extract_list_item(line)
                if item:
                    info.ignored_rules.append(item.upper())
                if IGNORE_ALL_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="ignore_all",
                            severity="high",
                            message="ignored list contains wildcard — do not suppress all Hadolint rules",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                if IGNORE_SECURITY_RULE_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="security_rule_ignored",
                            severity="high",
                            message="security-sensitive Hadolint rule ignored — remove from ignored list",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_registry_block:
                item = _extract_list_item(line)
                if item:
                    info.trusted_registries.append(item)
                if TRUSTED_REGISTRY_ALL_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="trusted_registry_all",
                            severity="high",
                            message="trustedRegistries allows all registries — restrict to known image sources",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                if ALLOWED_REGISTRY_INSECURE_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="insecure_registry",
                            severity="high",
                            message="insecure HTTP registry in trustedRegistries — use HTTPS registries only",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if TRUSTED_REGISTRY_WILDCARD_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="trusted_registry_wildcard",
                        severity="medium",
                        message="trustedRegistries uses wildcard — scope to specific registries",
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
                        message="curl|sh pattern in Hadolint config — avoid piping remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        security_ignored = [r for r in info.ignored_rules if r in SECURITY_RULE_CODES]
        if len(security_ignored) >= 2:
            findings.append(
                HadolintFinding(
                    kind="many_security_ignored",
                    severity="medium",
                    message=f"{len(security_ignored)} security Hadolint rules ignored — minimize suppressions",
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
                f"  - {info.path}: ignored={len(info.ignored_rules)}, "
                f"trusted_registries={len(info.trusted_registries)}, "
                f"threshold={info.failure_threshold or 'default'}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
