"""TyAnalyzer — audit Astral ty pyproject.toml and ty.toml for type-safety risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "ty.toml",
    "pyproject.toml",
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
RULE_IGNORE_PATTERN = re.compile(
    r"^[a-zA-Z0-9_-]+\s*=\s*[\"']?ignore[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
RULE_WARN_PATTERN = re.compile(
    r"^[a-zA-Z0-9_-]+\s*=\s*[\"']?warn[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
WILDCARD_RULE_IGNORE_PATTERN = re.compile(
    r"^\*\s*=\s*[\"']?ignore[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r'(?:["\']?exclude["\']?|["\']?ignore["\']?)\s*[=:\[][^\n]*(?:\"src\"|\'src\'|\"lib\'|\'lib\'|\"app\'|\'app\'|'
    r"\bsrc/|\blib/|\bapp/)",
    re.IGNORECASE,
)
INSECURE_EXTRA_PATH_PATTERN = re.compile(
    r'(?:["\']?extraPaths["\']?|["\']?stubPath["\']?|["\']?search-path["\']?)\s*[=:\[][^\n]*(?:/tmp/|/etc/|\.\./)',
    re.IGNORECASE,
)
TY_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]ty(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
TY_RULES_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]ty[.:]rules|rules)\]",
    re.IGNORECASE,
)
PYTHON_VERSION_LOOSE_PATTERN = re.compile(
    r'python[-_]version\s*=\s*["\']?\*["\']?',
    re.IGNORECASE,
)


@dataclass
class TyFinding:
    """A security or best-practice issue in a ty configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TyInfo:
    """Parsed metadata about a ty configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    ignored_rules: list[str] = field(default_factory=list)


@dataclass
class TyStats:
    """Aggregate ty analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "ty.toml":
        return "ty_config"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class TyAnalyzer:
    """Audit Astral ty configuration for type-safety and security hygiene risks.

    Scans ty.toml and pyproject.toml [tool.ty] for ignored rules, wildcard
    suppressions, broad exclude patterns, insecure search paths, and hardcoded
    secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TyFinding] | None = None
        self._stats: TyStats | None = None
        self._infos: list[TyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return ty configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if not path.is_file():
                continue
            if name == "pyproject.toml":
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "[tool.ty" not in text and "[tool:ty" not in text:
                    continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TyFinding],
        info: TyInfo,
        in_rules_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in ty config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in ty config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in ty config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_rules_section and WILDCARD_RULE_IGNORE_PATTERN.match(stripped):
            findings.append(
                TyFinding(
                    kind="wildcard_rule_ignore",
                    severity="high",
                    message="wildcard rule ignore suppresses all ty diagnostics — remove '* = ignore'",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_rules_section and RULE_IGNORE_PATTERN.match(stripped):
            rule_name = stripped.split("=")[0].strip()
            info.ignored_rules.append(rule_name)
            findings.append(
                TyFinding(
                    kind="rule_ignored",
                    severity="medium",
                    message=f"ty rule '{rule_name}' set to ignore — prefer warn or fix underlying issues",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_rules_section and RULE_WARN_PATTERN.match(stripped):
            rule_name = stripped.split("=")[0].strip()
            findings.append(
                TyFinding(
                    kind="rule_warn_only",
                    severity="low",
                    message=f"ty rule '{rule_name}' set to warn only — consider enforcing errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude/ignore skips source directories — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_EXTRA_PATH_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="insecure_extra_path",
                    severity="high",
                    message="search-path/extraPaths points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PYTHON_VERSION_LOOSE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="loose_python_version",
                    severity="low",
                    message="python-version set to wildcard — pin a supported Python version",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_ty_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == "ty.toml":
            return True
        if path.name == "pyproject.toml":
            if TY_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not TY_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        return True

    def _in_rules_section(self, line: str, in_section: bool, path: Path) -> bool:
        if path.name == "ty.toml":
            if TY_RULES_SECTION_PATTERN.match(line.strip()):
                return True
            if line.strip().startswith("[") and not TY_RULES_SECTION_PATTERN.match(line.strip()):
                return False
            return in_section
        if path.name == "pyproject.toml":
            if re.match(r"^\[(?:tool[.:]ty[.:]rules)\]", line.strip(), re.IGNORECASE):
                return True
            if line.strip().startswith("[") and not re.match(
                r"^\[(?:tool[.:]ty[.:]rules)\]", line.strip(), re.IGNORECASE
            ):
                return False
            return in_section
        return False

    def _analyze_file(self, path: Path) -> tuple[list[TyFinding], TyInfo]:
        findings: list[TyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TyInfo(path=rel, file_kind=_file_kind(path))

        info = TyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_ty_section = path.name == "ty.toml"
        in_rules_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                in_ty_section = self._in_ty_section(line, in_ty_section, path)
                if not in_ty_section:
                    in_rules_section = False
                    continue
            in_rules_section = self._in_rules_section(line, in_rules_section, path)
            self._scan_line(line, lineno, rel, findings, info, in_rules_section)

        return findings, info

    def analyze(self) -> list[TyFinding]:
        """Scan ty configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TyFinding] = []
        infos: list[TyInfo] = []
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
        self._stats = TyStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TyStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TyInfo]:
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
        """Scaffold a hardened ty configuration template."""
        return """\
# Generated by DevAI TyAnalyzer
[tool.ty]
# Pin the Python version used for type checking
python-version = "3.12"

[tool.ty.src]
include = ["src"]
exclude = [
    "**/__pycache__",
    ".venv",
    "build",
    "dist",
]

# Keep rules at default severity — only ignore with documented justification
# [tool.ty.rules]
# index-out-of-bounds = "warn"
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Ty configs: none found"
        return (
            f"Ty configs: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Ty analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            ignored = ", ".join(info.ignored_rules[:8]) if info.ignored_rules else "none"
            lines.append(f"  - {info.path} ({info.file_kind}): {len(info.ignored_rules)} ignored rule(s)")
            lines.append(f"    ignored rules: {ignored}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
