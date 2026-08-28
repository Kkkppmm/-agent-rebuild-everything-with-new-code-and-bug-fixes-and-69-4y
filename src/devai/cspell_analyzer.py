"""CspellAnalyzer — audit CSpell configuration files for hygiene and security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "cspell.json",
    ".cspell.json",
    "cspell.config.json",
    "cspell.config.yaml",
    "cspell.config.yml",
    ".cspell.yaml",
    ".cspell.yml",
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
ENABLED_FALSE_PATTERN = re.compile(
    r'["\']?enabled["\']?\s*:\s*(?:false|0|"off")',
    re.IGNORECASE,
)
ENABLED_FALSE_YAML_PATTERN = re.compile(
    r"^\s*enabled\s*:\s*(?:false|0|off)\s*(?:#.*)?$",
    re.IGNORECASE,
)
MIN_WORD_LENGTH_HIGH_PATTERN = re.compile(
    r'["\']?min[_-]?word[_-]?length["\']?\s*:\s*(?:1[5-9]|[2-9][0-9]|[1-9][0-9]{2,})\b',
    re.IGNORECASE,
)
MIN_WORD_LENGTH_YAML_PATTERN = re.compile(
    r"^\s*min[_-]?word[_-]?length\s*:\s*(?:1[5-9]|[2-9][0-9]|[1-9][0-9]{2,})\s*(?:#.*)?$",
    re.IGNORECASE,
)
MAX_PROBLEMS_ZERO_PATTERN = re.compile(
    r'["\']?(?:max[_-]?number[_-]?of[_-]?problems|num[_-]?errors)["\']?\s*:\s*0\b',
    re.IGNORECASE,
)
CHECK_LIMIT_ZERO_PATTERN = re.compile(
    r'["\']?check[_-]?limit["\']?\s*:\s*0\b',
    re.IGNORECASE,
)
IGNORE_PATHS_PATTERN = re.compile(
    r'["\']?ignore[_-]?paths?["\']?\s*:',
    re.IGNORECASE,
)
IGNORE_REGEXP_PATTERN = re.compile(
    r'["\']?ignore[_-]?regexp[_-]?list["\']?\s*:',
    re.IGNORECASE,
)
BROAD_IGNORE_REGEXP_PATTERN = re.compile(
    r'["\']?\.\*["\']?|["\']?\^?\.\*\$?["\']?',
)
IGNORE_SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'])(?:security|docs/security|\.github|policies|compliance|"
    r"audit|legal)(?:/|[\s\"']|$)",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r'["\']?ignore[_-]?paths?["\']?\s*:\s*[^\n]*\*\*',
    re.IGNORECASE,
)
REMOTE_IMPORT_PATTERN = re.compile(
    r'["\']?import["\']?\s*:\s*[^\n]*https?://',
    re.IGNORECASE,
)
REMOTE_DICTIONARY_PATTERN = re.compile(
    r'["\']?(?:path|uri|url)["\']?\s*:\s*["\']?https?://',
    re.IGNORECASE,
)


@dataclass
class CspellFinding:
    """A security or best-practice issue in a CSpell configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CspellInfo:
    """Parsed metadata about a CSpell configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    enabled: bool | None = None
    min_word_length: int | None = None
    has_ignore_paths: bool = False
    has_ignore_regexp: bool = False


@dataclass
class CspellStats:
    """Aggregate CSpell analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cspell_config(path: Path) -> bool:
    name = path.name.lower()
    return name in CONFIG_NAMES or name.startswith("cspell.config.")


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".json") or name == "cspell.json" or name == ".cspell.json":
        return "json"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return "unknown"


def _extract_min_word_length(line: str) -> int | None:
    match = re.search(
        r'["\']?min[_-]?word[_-]?length["\']?\s*:\s*(\d+)\b',
        line,
        re.IGNORECASE,
    )
    if match:
        return int(match.group(1))
    match = re.search(
        r"^\s*min[_-]?word[_-]?length\s*:\s*(\d+)\s*(?:#.*)?$",
        line,
        re.IGNORECASE,
    )
    if match:
        return int(match.group(1))
    return None


class CspellAnalyzer:
    """Audit CSpell configuration for spelling hygiene and security risks.

    Scans `cspell.json`, `.cspell.yaml`, and package.json cspell blocks for
    disabled checks, broad ignore patterns on security docs, remote dictionary
    imports, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[CspellFinding] | None = None
        self._stats: CspellStats | None = None
        self._infos: list[CspellInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return CSpell configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("cspell*")):
            if path.is_file() and path not in found and _is_cspell_config(path):
                found.append(path)
        for path in sorted(self.root.rglob(".cspell*")):
            if path.is_file() and path not in found and _is_cspell_config(path):
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "cspell" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CspellFinding],
        info: CspellInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if ENABLED_FALSE_PATTERN.search(line) or ENABLED_FALSE_YAML_PATTERN.match(line):
            info.enabled = False
            findings.append(
                CspellFinding(
                    kind="spellcheck_disabled",
                    severity="high",
                    message="enabled=false disables CSpell — prefer narrow ignorePaths instead",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        enabled_true = re.search(
            r'["\']?enabled["\']?\s*:\s*(?:true|1|"on")',
            line,
            re.IGNORECASE,
        )
        if enabled_true:
            info.enabled = True

        min_length = _extract_min_word_length(line)
        if min_length is not None:
            info.min_word_length = min_length
            if min_length >= 15:
                findings.append(
                    CspellFinding(
                        kind="min_word_length_high",
                        severity="medium",
                        message=(
                            f"minWordLength={min_length} is very high — "
                            "most typos in identifiers will be skipped"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if MAX_PROBLEMS_ZERO_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="max_problems_zero",
                    severity="high",
                    message="maxNumberOfProblems=0 suppresses all spelling errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CHECK_LIMIT_ZERO_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="check_limit_zero",
                    severity="medium",
                    message="checkLimit=0 disables file scanning — remove or raise the limit",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_PATHS_PATTERN.search(line) or line.lower().startswith("ignorepaths:"):
            info.has_ignore_paths = True

        if IGNORE_REGEXP_PATTERN.search(line) or line.lower().startswith("ignoreregexplist:"):
            info.has_ignore_regexp = True

        if IGNORE_SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="ignore_sensitive_path",
                    severity="high",
                    message="ignorePaths skips security/compliance docs — spell-check policy files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_WILDCARD_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="ignore_wildcard",
                    severity="medium",
                    message="wildcard ignorePaths may hide spelling issues — scope ignores narrowly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_REGEXP_PATTERN.search(line) and BROAD_IGNORE_REGEXP_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="broad_ignore_regexp",
                    severity="high",
                    message="ignoreRegExpList contains .* — disables spelling checks broadly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_IMPORT_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="remote_import",
                    severity="medium",
                    message="remote import URL in CSpell config — pin local dictionaries for supply-chain safety",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REMOTE_DICTIONARY_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="remote_dictionary",
                    severity="medium",
                    message="remote dictionary URL — vendor dictionaries locally when possible",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in CSpell config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in CSpell config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                CspellFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in CSpell config — avoid remote code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[CspellFinding], CspellInfo]:
        findings: list[CspellFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CspellInfo(path=rel)

        info = CspellInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[CspellFinding]:
        """Scan CSpell configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CspellFinding] = []
        infos: list[CspellInfo] = []
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
        self._stats = CspellStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CspellStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CspellInfo]:
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
        """Scaffold a hardened CSpell configuration template."""
        return """\
{
  "version": "0.2",
  "language": "en",
  "enabled": true,
  "useGitignore": true,
  "minWordLength": 4,
  "maxNumberOfProblems": 100,
  "ignorePaths": [
    "node_modules",
    "dist",
    "build",
    ".git"
  ],
  "flagWords": [
    "hte",
    "teh"
  ],
  "words": []
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "cspell configs: none found"
        return (
            f"cspell configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "cspell config analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            enabled = (
                "default"
                if info.enabled is None
                else ("true" if info.enabled else "false")
            )
            length = info.min_word_length if info.min_word_length is not None else "default"
            lines.append(f"  - {info.path}: enabled={enabled}, min_word_length={length}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
