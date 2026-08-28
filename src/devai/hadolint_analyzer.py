"""HadolintAnalyzer — audit Hadolint Dockerfile lint configuration for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".hadolint.yaml",
    ".hadolint.yml",
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
IGNORED_LINE_PATTERN = re.compile(
    r"^\s*-\s*(DL\d{4}|SC\d{4}|\S+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORED_INLINE_PATTERN = re.compile(
    r"^\s*ignored\s*:\s*\[(.+)\]\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r"^\s*-\s*(?:DL\*|SC\*|\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
NO_FAIL_TRUE_PATTERN = re.compile(
    r"^\s*no-fail\s*:\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_IGNORE_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:ignore|none)\s*(?:#.*)?$",
    re.IGNORECASE,
)
FAILURE_THRESHOLD_LOW_PATTERN = re.compile(
    r"^\s*failure-threshold\s*:\s*(?:style|info)\s*(?:#.*)?$",
    re.IGNORECASE,
)
ALLOW_DEPRECATED_PARENT_PATTERN = re.compile(
    r"^\s*allow-deprecated-parent-images\s*:\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
STRICT_LABELS_FALSE_PATTERN = re.compile(
    r"^\s*strict-labels\s*:\s*false\s*(?:#.*)?$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
HADOLINT_CODE_PATTERN = re.compile(r"\b(DL\d{4}|SC\d{4})\b", re.IGNORECASE)

# Security-sensitive Hadolint rules grouped by concern.
ROOT_USER_CODES = frozenset({"DL3002"})
SUDO_CODES = frozenset({"DL3004"})
TAGGING_CODES = frozenset({"DL3006", "DL3007"})
PACKAGE_PIN_CODES = frozenset({"DL3008", "DL3013", "DL3018"})
INSTALL_HYGIENE_CODES = frozenset({"DL3015", "DL3009"})
CMD_JSON_CODES = frozenset({"DL3025"})
DEPRECATED_APT_CODES = frozenset({"DL3027"})
CURL_BASH_CODES = frozenset({"DL3040"})
HEALTHCHECK_CODES = frozenset({"DL3044"})
SECURITY_CODES = (
    ROOT_USER_CODES
    | SUDO_CODES
    | TAGGING_CODES
    | PACKAGE_PIN_CODES
    | INSTALL_HYGIENE_CODES
    | CMD_JSON_CODES
    | DEPRECATED_APT_CODES
    | CURL_BASH_CODES
    | HEALTHCHECK_CODES
)


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
    no_fail: bool = False
    allow_deprecated_parent_images: bool = False
    strict_labels: bool | None = None
    trusted_registries: int = 0


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


def _normalize_code(code: str) -> str:
    code = code.strip().upper()
    if code.startswith("DL") or code.startswith("SC"):
        return code
    return code


class HadolintAnalyzer:
    """Audit Hadolint configuration for Dockerfile lint hygiene and security risks.

    Scans `.hadolint.yaml` and `.hadolint.yml` for ignored security rules,
    permissive failure thresholds, deprecated parent images, and hardcoded secrets.
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

    def _append_ignored_code_finding(
        self,
        findings: list[HadolintFinding],
        rel: str,
        lineno: int,
        line: str,
        code: str,
    ) -> None:
        normalized = _normalize_code(code)
        if normalized in ROOT_USER_CODES:
            findings.append(
                HadolintFinding(
                    kind="root_user_ignored",
                    severity="high",
                    message=f"{normalized} ignored — do not run containers as root",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in SUDO_CODES:
            findings.append(
                HadolintFinding(
                    kind="sudo_ignored",
                    severity="high",
                    message=f"{normalized} ignored — avoid sudo in Dockerfiles",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in TAGGING_CODES:
            findings.append(
                HadolintFinding(
                    kind="tagging_ignored",
                    severity="high",
                    message=f"{normalized} ignored — pin image tags instead of using latest",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in PACKAGE_PIN_CODES:
            findings.append(
                HadolintFinding(
                    kind="package_pin_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — pin package versions in install commands",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in INSTALL_HYGIENE_CODES:
            findings.append(
                HadolintFinding(
                    kind="install_hygiene_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — keep install hygiene checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in CMD_JSON_CODES:
            findings.append(
                HadolintFinding(
                    kind="cmd_json_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — use JSON array form for CMD/ENTRYPOINT",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in DEPRECATED_APT_CODES:
            findings.append(
                HadolintFinding(
                    kind="deprecated_apt_ignored",
                    severity="medium",
                    message=f"{normalized} ignored — avoid deprecated apt alias usage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in CURL_BASH_CODES:
            findings.append(
                HadolintFinding(
                    kind="curl_bash_ignored",
                    severity="high",
                    message=f"{normalized} ignored — do not pipe curl/wget into shell",
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
                    message=f"{normalized} ignored — consider adding HEALTHCHECK instructions",
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

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^\s*ignored\s*:\s*$", line, re.IGNORECASE):
                in_ignored_block = True
                continue

            if in_ignored_block and not line.startswith((" ", "\t")):
                in_ignored_block = False

            threshold_match = re.match(
                r"^\s*failure-threshold\s*:\s*(\S+)",
                line,
                re.IGNORECASE,
            )
            if threshold_match:
                info.failure_threshold = threshold_match.group(1).lower()

            registry_match = re.match(
                r"^\s*-\s*[\"']?([^\"'\s#]+)[\"']?\s*(?:#.*)?$",
                line,
            )
            if registry_match and re.search(
                r"trustedRegistries\s*:", "\n".join(raw_lines[: lineno - 1][-5:]), re.IGNORECASE
            ):
                info.trusted_registries += 1

            if NO_FAIL_TRUE_PATTERN.search(line):
                info.no_fail = True
                findings.append(
                    HadolintFinding(
                        kind="no_fail_enabled",
                        severity="high",
                        message="no-fail=true suppresses Hadolint failures — remove for CI enforcement",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FAILURE_THRESHOLD_IGNORE_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_ignore",
                        severity="high",
                        message="failure-threshold ignores all Hadolint findings — use warning or error",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FAILURE_THRESHOLD_LOW_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="failure_threshold_low",
                        severity="medium",
                        message="failure-threshold is too permissive — prefer warning or error",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALLOW_DEPRECATED_PARENT_PATTERN.search(line):
                info.allow_deprecated_parent_images = True
                findings.append(
                    HadolintFinding(
                        kind="deprecated_parent_allowed",
                        severity="medium",
                        message="allow-deprecated-parent-images=true — avoid deprecated base images",
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
                        message="strict-labels=false — enforce label schema for image metadata",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if IGNORE_WILDCARD_PATTERN.search(line):
                findings.append(
                    HadolintFinding(
                        kind="wildcard_ignore",
                        severity="high",
                        message="wildcard ignored rule hides Dockerfile lint warnings — scope to specific codes",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            ignored_codes: list[str] = []
            ignored_match = IGNORED_LINE_PATTERN.search(line)
            if ignored_match:
                ignored_codes.append(ignored_match.group(1))
            inline_match = IGNORED_INLINE_PATTERN.search(line)
            if inline_match:
                for part in re.split(r"[,;\s]+", inline_match.group(1)):
                    part = part.strip().strip("\"'")
                    if part:
                        ignored_codes.append(part)

            for code in ignored_codes:
                normalized = _normalize_code(code)
                info.ignored_codes.append(normalized)
                self._append_ignored_code_finding(findings, rel, lineno, line, normalized)

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

        security_ignored = [c for c in info.ignored_codes if c in SECURITY_CODES]
        if len(security_ignored) >= 5:
            findings.append(
                HadolintFinding(
                    kind="many_security_ignored",
                    severity="medium",
                    message=f"{len(security_ignored)} security-related rules ignored — minimize suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if len(info.ignored_codes) >= 12:
            findings.append(
                HadolintFinding(
                    kind="broad_ignore_list",
                    severity="medium",
                    message=f"{len(info.ignored_codes)} ignored rules — review Hadolint suppressions regularly",
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
no-fail: false
strict-labels: true
allow-deprecated-parent-images: false

# ignored:
#   - DL3007

# trustedRegistries:
#   - docker.io

# label-schema:
#   author: text
#   version: semver
#   license: spdx
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
                f"no_fail={info.no_fail}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
