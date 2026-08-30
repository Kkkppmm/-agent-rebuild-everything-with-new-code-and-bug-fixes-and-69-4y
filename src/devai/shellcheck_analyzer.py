"""ShellcheckAnalyzer — audit ShellCheck configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".shellcheckrc",
    "shellcheckrc",
    ".shellcheckrc.local",
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
DISABLE_ALL_PATTERN = re.compile(
    r"^\s*disable\s*=\s*(?:all|\*|SC\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
DISABLE_WILDCARD_PATTERN = re.compile(
    r"^\s*disable\s*=\s*[^#\n]*(?:SC\d{4}\*|SC\*|\*)",
    re.IGNORECASE,
)
DISABLE_QUOTING_PATTERN = re.compile(
    r"^\s*disable\s*=\s*[^#\n]*\bSC(?:2086|2046|2166|2038|2207|2068|2206)\b",
    re.IGNORECASE,
)
DISABLE_SOURCE_PATTERN = re.compile(
    r"^\s*disable\s*=\s*[^#\n]*\bSC(?:1090|1091|2154|2164)\b",
    re.IGNORECASE,
)
DISABLE_EVAL_PATTERN = re.compile(
    r"^\s*disable\s*=\s*[^#\n]*\bSC(?:2048|2090|2091|2154)\b",
    re.IGNORECASE,
)
DISABLE_PIPEFAIL_PATTERN = re.compile(
    r"^\s*disable\s*=\s*[^#\n]*\bSC(?:2154|2181)\b",
    re.IGNORECASE,
)
EXTERNAL_SOURCES_TRUE_PATTERN = re.compile(
    r"^\s*external-sources\s*=\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
SOURCE_PATH_MISSING_PATTERN = re.compile(
    r"^\s*source-path\s*=",
    re.IGNORECASE,
)
SHELL_DASH_PATTERN = re.compile(
    r"^\s*shell\s*=\s*dash\s*(?:#.*)?$",
    re.IGNORECASE,
)
SHELL_SH_PATTERN = re.compile(
    r"^\s*shell\s*=\s*sh\s*(?:#.*)?$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CHECKED_SC_PATTERN = re.compile(r"\bSC(\d{4})\b", re.IGNORECASE)
BROAD_DISABLE_LINE_PATTERN = re.compile(
    r"^\s*disable\s*=\s*[^#\n]{80,}",
    re.IGNORECASE,
)
ENABLE_NONE_PATTERN = re.compile(
    r"^\s*enable\s*=\s*(?:none|false)\s*(?:#.*)?$",
    re.IGNORECASE,
)
INLINE_DISABLE_ALL_PATTERN = re.compile(
    r"#\s*shellcheck\s+disable\s*=\s*(?:all|\*)",
    re.IGNORECASE,
)

# Security-sensitive ShellCheck codes grouped by concern.
QUOTING_CODES = frozenset({"2086", "2046", "2166", "2038", "2207", "2068", "2206"})
SOURCE_CODES = frozenset({"1090", "1091", "2154", "2164"})
EVAL_CODES = frozenset({"2048", "2090", "2091"})


@dataclass
class ShellcheckFinding:
    """A security or best-practice issue in a ShellCheck configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ShellcheckInfo:
    """Parsed metadata about a ShellCheck configuration file."""

    path: str
    lines: int = 0
    shell: str = ""
    disabled_codes: list[str] = field(default_factory=list)
    external_sources: bool = False
    has_source_path: bool = False


@dataclass
class ShellcheckStats:
    """Aggregate ShellCheck analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_shellcheck_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


def _parse_disabled_codes(line: str) -> list[str]:
    match = re.search(r"disable\s*=\s*(.+?)(?:\s*#.*)?$", line, re.IGNORECASE)
    if not match:
        return []
    raw = match.group(1).strip()
    codes: list[str] = []
    for part in re.split(r"[,;\s]+", raw):
        part = part.strip().upper()
        if part.startswith("SC"):
            part = part[2:]
        if re.fullmatch(r"\d{4}", part):
            codes.append(part)
        elif part.endswith("*") and part[:-1].isdigit():
            codes.append(part)
    return codes


class ShellcheckAnalyzer:
    """Audit ShellCheck configuration for lint hygiene and security risks.

    Scans `.shellcheckrc` and related config files for disabled quoting/source
    checks, wildcard disables, external-sources without source-path, and hardcoded
    secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[ShellcheckFinding] | None = None
        self._stats: ShellcheckStats | None = None
        self._infos: list[ShellcheckInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return ShellCheck configuration paths found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_shellcheck_config(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[ShellcheckFinding], ShellcheckInfo]:
        findings: list[ShellcheckFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ShellcheckInfo(path=rel)

        info = ShellcheckInfo(path=rel, lines=len(raw_lines))
        has_source_path_line = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                if INLINE_DISABLE_ALL_PATTERN.search(line):
                    findings.append(
                        ShellcheckFinding(
                            kind="inline_disable_all",
                            severity="high",
                            message="inline shellcheck disable=all suppresses all checks in script",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                continue

            shell_match = re.match(r"^\s*shell\s*=\s*(\S+)", line, re.IGNORECASE)
            if shell_match:
                info.shell = shell_match.group(1).lower()

            if SOURCE_PATH_MISSING_PATTERN.search(line):
                has_source_path_line = True
                info.has_source_path = True

            if EXTERNAL_SOURCES_TRUE_PATTERN.search(line):
                info.external_sources = True

            disabled = _parse_disabled_codes(line)
            if disabled:
                info.disabled_codes.extend(disabled)

            if DISABLE_ALL_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="disable_all",
                        severity="high",
                        message="disable=all turns off all ShellCheck checks — remove blanket disable",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_WILDCARD_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="wildcard_disable",
                        severity="high",
                        message="wildcard disable pattern hides ShellCheck warnings — scope to specific SC codes",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_QUOTING_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="quoting_check_disabled",
                        severity="high",
                        message="quoting/word-splitting checks disabled — do not disable SC2086/SC2046 without reason",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_SOURCE_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="source_check_disabled",
                        severity="medium",
                        message="source/sourcing checks disabled — keep SC1090/SC1091 enabled for script safety",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLE_EVAL_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="eval_check_disabled",
                        severity="medium",
                        message="eval-related checks disabled — avoid eval and keep SC2048/SC2090 enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BROAD_DISABLE_LINE_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="broad_disable",
                        severity="medium",
                        message="very long disable list — review suppressed ShellCheck codes regularly",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ENABLE_NONE_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="enable_none",
                        severity="high",
                        message="enable=none disables optional checks — use explicit enable list instead",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SHELL_DASH_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="shell_dash",
                        severity="low",
                        message="shell=dash — verify scripts are POSIX-compatible and tested on target shells",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in ShellCheck config — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL in ShellCheck config — use HTTPS endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    ShellcheckFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl|sh pattern in ShellCheck config — avoid piping remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if info.external_sources and not has_source_path_line:
            findings.append(
                ShellcheckFinding(
                    kind="external_sources_unrestricted",
                    severity="medium",
                    message="external-sources=true without source-path — restrict sourced file locations",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        quoting_disabled = [
            c for c in info.disabled_codes if c in QUOTING_CODES or c.endswith("*")
        ]
        if len(quoting_disabled) >= 3:
            findings.append(
                ShellcheckFinding(
                    kind="many_quoting_disabled",
                    severity="medium",
                    message=f"{len(quoting_disabled)} quoting-related checks disabled — minimize suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[ShellcheckFinding]:
        """Scan ShellCheck config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ShellcheckFinding] = []
        infos: list[ShellcheckInfo] = []
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
        self._stats = ShellcheckStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ShellcheckStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ShellcheckInfo]:
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
        """Scaffold a hardened ShellCheck configuration template."""
        return """\
# Generated by DevAI ShellcheckAnalyzer
# ShellCheck config — https://www.shellcheck.net/
# Run: shellcheck scripts/*.sh

shell=bash
external-sources=false
# source-path=SCRIPTDIR
# enable=all
disable=
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "ShellCheck configs: none found"
        return (
            f"ShellCheck configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "ShellCheck config analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: shell={info.shell or 'default'}, "
                f"disabled={len(info.disabled_codes)}, "
                f"external_sources={info.external_sources}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
