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
    r"^\s*-\s*(?:all|\*|DL\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*DL\d*\*\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_LINE_PATTERN = re.compile(r"^\s*-\s*(DL\d{4})\s*(?:#.*)?$", re.IGNORECASE)
FAILURE_THRESHOLD_NONE_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:none|info)\s*(?:#.*)?$",
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
BROAD_IGNORE_BLOCK_PATTERN = re.compile(
    r"^\s*ignored\s*:\s*$",
    re.IGNORECASE,
)

# Security-sensitive Hadolint rules grouped by concern.
ROOT_USER_CODES = frozenset({"DL3002", "DL3046"})
VERSION_PIN_CODES = frozenset({"DL3006", "DL3007", "DL3008", "DL3013", "DL3018", "DL3028", "DL3044"})
ADD_COPY_CODES = frozenset({"DL3020", "DL3021", "DL3045"})
UPGRADE_CODES = frozenset({"DL3027"})
SUDO_CODES = frozenset({"DL3004"})


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


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml` and related config files for ignored root-user/pinning
    rules, wildcard ignores, permissive failure thresholds, and hardcoded secrets.
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

    def _record_ignored_code(
        self,
        code: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[HadolintFinding],
        info: HadolintInfo,
    ) -> None:
        info.ignored_codes.append(code)
        if code in ROOT_USER_CODES:
            findings.append(
                HadolintFinding(
                    kind="root_user_ignored",
                    severity="high",
                    message=f"{code} ignored — do not suppress root-user checks",
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
                    message=f"{code} ignored — keep version pinning rules enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif code in ADD_COPY_CODES:
            findings.append(
                HadolintFinding(
                    kind="add_copy_ignored",
                    severity="medium",
                    message=f"{code} ignored — keep ADD/COPY safety checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif code in UPGRADE_CODES:
            findings.append(
                HadolintFinding(
                    kind="upgrade_ignored",
                    severity="medium",
                    message=f"{code} ignored — avoid apt upgrade in Docker images",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif code in SUDO_CODES:
            findings.append(
                HadolintFinding(
                    kind="sudo_ignored",
                    severity="medium",
                    message=f"{code} ignored — do not use sudo in Dockerfiles",
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
        in_ignored_block = False
        in_trusted_registries = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if BROAD_IGNORE_BLOCK_PATTERN.search(line):
                in_ignored_block = True
                in_trusted_registries = False
                continue

            threshold_match = re.match(
                r"^\s*failure-threshold\s*:\s*(\S+)",
                line,
                re.IGNORECASE,
            )
            if threshold_match:
                in_ignored_block = False
                in_trusted_registries = False
                info.failure_threshold = threshold_match.group(1).lower()
                if FAILURE_THRESHOLD_NONE_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="permissive_threshold",
                            severity="medium",
                            message="failure-threshold=none/info is too permissive — use warning or error",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                continue

            if re.match(r"^\s*trustedRegistries\s*:\s*$", line, re.IGNORECASE):
                in_trusted_registries = True
                in_ignored_block = False
                continue

            if re.match(r"^\s*\w[\w-]*\s*:", line) and not line.strip().startswith("-"):
                in_ignored_block = False
                in_trusted_registries = False

            if in_trusted_registries and stripped.startswith("-"):
                registry = stripped.lstrip("- ").strip().strip("\"'")
                info.trusted_registries.append(registry)
                if TRUSTED_REGISTRY_HTTP_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="insecure_registry",
                            severity="high",
                            message="HTTP trusted registry — use HTTPS registries only",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                continue

            if in_ignored_block:
                if IGNORE_ALL_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="ignore_all",
                            severity="high",
                            message="ignored=all/* disables all Hadolint checks — remove blanket ignore",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                    continue

                if IGNORE_WILDCARD_PATTERN.search(line):
                    findings.append(
                        HadolintFinding(
                            kind="wildcard_ignore",
                            severity="high",
                            message="wildcard ignore pattern hides Hadolint warnings — scope to specific DL codes",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                    continue

                code_match = IGNORE_LINE_PATTERN.search(line)
                if code_match:
                    self._record_ignored_code(
                        code_match.group(1).upper(),
                        lineno,
                        rel,
                        line,
                        findings,
                        info,
                    )
                continue

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

        if len(info.ignored_codes) >= 10:
            findings.append(
                HadolintFinding(
                    kind="many_ignored",
                    severity="medium",
                    message=f"{len(info.ignored_codes)} rules ignored — review suppressed Hadolint codes regularly",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        security_ignored = [
            c
            for c in info.ignored_codes
            if c in ROOT_USER_CODES | VERSION_PIN_CODES | ADD_COPY_CODES
        ]
        if len(security_ignored) >= 3:
            findings.append(
                HadolintFinding(
                    kind="many_security_ignored",
                    severity="high",
                    message=f"{len(security_ignored)} security-related rules ignored — minimize suppressions",
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
# Hadolint — https://github.com/hadolint/hadolint
# Run: hadolint Dockerfile

failure-threshold: warning
format: tty
ignored: []
# trustedRegistries:
#   - docker.io
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
                f"failure_threshold={info.failure_threshold or 'default'}, "
                f"trusted_registries={len(info.trusted_registries)}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
