"""TyAnalyzer — audit Astral ty type checker configs for type-safety risks."""

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
TY_SECTION_PATTERN = re.compile(r"^\[(?:tool[.:]ty(?:\.[^\]]+)?)\]", re.IGNORECASE)
TY_STANDALONE_SECTION_PATTERN = re.compile(r"^\[(?:rules|src|analysis|environment|overrides)(?:\.[^\]]+)?\]", re.IGNORECASE)
ALL_IGNORE_PATTERN = re.compile(r"^\s*all\s*=\s*[\"']ignore[\"']", re.IGNORECASE)
ALL_WARN_PATTERN = re.compile(r"^\s*all\s*=\s*[\"']warn[\"']", re.IGNORECASE)
CRITICAL_RULE_IGNORE_PATTERN = re.compile(
    r"^\s*(?:possibly-missing-import|possibly-unresolved-reference|"
    r"unresolved-import|division-by-zero|index-out-of-bounds)\s*=\s*[\"']ignore[\"']",
    re.IGNORECASE,
)
RESPECT_TYPE_IGNORE_FALSE_PATTERN = re.compile(
    r"respect-type-ignore-comments\s*=\s*false\b",
    re.IGNORECASE,
)
RESPECT_IGNORE_FILES_FALSE_PATTERN = re.compile(
    r"respect-ignore-files\s*=\s*false\b",
    re.IGNORECASE,
)
ERROR_ON_WARNING_FALSE_PATTERN = re.compile(
    r"error-on-warning\s*=\s*false\b",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"exclude\s*=\s*\[[^\]]*[\"'](?:src|lib|app)[\"']",
    re.IGNORECASE,
)
UNRESOLVED_IMPORT_IGNORE_PATTERN = re.compile(
    r"unresolved-import\s*=\s*[\"']ignore[\"']",
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
    rules_all: str = ""
    sections: list[str] = field(default_factory=list)


@dataclass
class TyStats:
    """Aggregate ty analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.name == "ty.toml":
        return "ty_toml"
    if path.name == "pyproject.toml":
        return "toml"
    return "unknown"


class TyAnalyzer:
    """Audit Astral ty configuration for type-safety and security hygiene risks.

    Scans ty.toml and pyproject.toml [tool.ty] sections for disabled rules,
    broad exclude patterns, relaxed error-on-warning settings, and hardcoded
    secrets in type-checker configuration.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TyFinding] | None = None
        self._stats: TyStats | None = None
        self._infos: list[TyInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return ty configuration paths found in the project."""
        found: list[Path] = []
        ty_toml = self.root / "ty.toml"
        if ty_toml.is_file():
            found.append(ty_toml)
            return found

        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return found
            if "[tool.ty" in text.lower():
                found.append(pyproject)
        return found

    def _in_ty_section(self, line: str, in_section: bool, standalone: bool) -> bool:
        stripped = line.strip()
        if standalone:
            if TY_STANDALONE_SECTION_PATTERN.match(stripped):
                return True
            if stripped.startswith("[") and not TY_STANDALONE_SECTION_PATTERN.match(stripped):
                return False
            return in_section

        if TY_SECTION_PATTERN.match(stripped):
            return True
        if stripped.startswith("[") and not TY_SECTION_PATTERN.match(stripped):
            return False
        return in_section

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TyFinding],
        info: TyInfo,
        in_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if in_section:
            section_match = (
                TY_SECTION_PATTERN.match(stripped)
                or TY_STANDALONE_SECTION_PATTERN.match(stripped)
            )
            if section_match:
                info.sections.append(section_match.group(0))

            if ALL_IGNORE_PATTERN.search(line):
                info.rules_all = "ignore"
                findings.append(
                    TyFinding(
                        kind="all_rules_ignored",
                        severity="high",
                        message="all ty rules set to ignore — type checking is effectively disabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALL_WARN_PATTERN.search(line):
                info.rules_all = "warn"
                findings.append(
                    TyFinding(
                        kind="all_rules_warn",
                        severity="medium",
                        message="all ty rules set to warn — prefer error severity for CI gates",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CRITICAL_RULE_IGNORE_PATTERN.search(line):
                findings.append(
                    TyFinding(
                        kind="critical_rule_ignored",
                        severity="medium",
                        message="critical ty rule disabled — re-enable for safer type checking",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNRESOLVED_IMPORT_IGNORE_PATTERN.search(line):
                findings.append(
                    TyFinding(
                        kind="unresolved_import_ignored",
                        severity="medium",
                        message="unresolved-import ignored globally — use per-module analysis overrides instead",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if RESPECT_TYPE_IGNORE_FALSE_PATTERN.search(line):
                findings.append(
                    TyFinding(
                        kind="type_ignore_disabled",
                        severity="low",
                        message="respect-type-ignore-comments=false — keep explicit ignores honored",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if RESPECT_IGNORE_FILES_FALSE_PATTERN.search(line):
                findings.append(
                    TyFinding(
                        kind="ignore_files_disabled",
                        severity="low",
                        message="respect-ignore-files=false — ty will type-check ignored paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ERROR_ON_WARNING_FALSE_PATTERN.search(line):
                findings.append(
                    TyFinding(
                        kind="error_on_warning_disabled",
                        severity="medium",
                        message="error-on-warning=false — warnings will not fail CI",
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
                        message="ty excludes src/lib/app — verify application code is still type-checked",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if not in_section:
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
                    severity="high",
                    message="insecure HTTP URL in ty config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TyFinding], TyInfo]:
        findings: list[TyFinding] = []
        rel = str(path.relative_to(self.root))
        standalone = path.name == "ty.toml"
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TyInfo(path=rel, file_kind=_file_kind(path))

        info = TyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_section = standalone

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_section = self._in_ty_section(line, in_section, standalone)
            self._scan_line(line, lineno, rel, findings, info, in_section)

        return findings, info

    def analyze(self) -> list[TyFinding]:
        """Scan ty config files and return findings."""
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
# Add to pyproject.toml or save as ty.toml (without [tool.ty] prefix)

[tool.ty.environment]
python-version = "3.12"

[tool.ty.src]
include = ["src"]
exclude = ["**/tests", "**/__pycache__"]

[tool.ty.rules]
all = "error"
possibly-missing-import = "error"
possibly-unresolved-reference = "error"
unresolved-import = "warn"

[tool.ty.terminal]
error-on-warning = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "ty configs: none found"
        return (
            f"ty configs: {stats.config_files} file(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "ty configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            rules = info.rules_all or "unspecified"
            sections = ", ".join(info.sections) or "default"
            lines.append(f"  - {info.path}: rules.all={rules}, sections={sections}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
