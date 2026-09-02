"""TyAnalyzer — audit ty.toml and pyproject.toml [tool.ty] for type-safety risks."""

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
TY_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]ty(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
RULES_ALL_IGNORE_PATTERN = re.compile(
    r'(?:^|\s)all\s*=\s*["\']ignore["\']',
    re.IGNORECASE,
)
RULE_IGNORE_PATTERN = re.compile(
    r"(?:unresolved-import|possibly-unresolved-reference|possibly-missing-import|"
    r"division-by-zero|invalid-argument-type|invalid-return-type|"
    r"invalid-assignment|call-non-callable)\s*=\s*[\"']ignore[\"']",
    re.IGNORECASE,
)
ERROR_ON_WARNING_FALSE_PATTERN = re.compile(
    r"error-on-warning\s*=\s*false\b",
    re.IGNORECASE,
)
RESPECT_TYPE_IGNORE_FALSE_PATTERN = re.compile(
    r"respect-type-ignore-comments\s*=\s*false\b",
    re.IGNORECASE,
)
BROAD_ALLOWED_IMPORTS_PATTERN = re.compile(
    r"allowed-unresolved-imports\s*=\s*\[[^\]]*(?:\"\*\"|\'\*\'|\"\*\*\"|\'\*\*\')",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"(?:^|\s)exclude\s*=\s*\[[^\]]*(?:\"src\"|\'src\'|\"lib\"|\'lib\'|\"app\"|\'app\')",
    re.IGNORECASE,
)
INSECURE_EXTRA_PATH_PATTERN = re.compile(
    r"extra-paths\s*=\s*\[[^\]]*(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
OVERRIDE_RULE_IGNORE_PATTERN = re.compile(
    r"\[\[tool\.ty\.overrides\]\][\s\S]*?(?:all|unresolved-import|possibly-unresolved-reference)\s*=\s*[\"']ignore[\"']",
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
    rules_all: str | None = None


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
        return "ty"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class TyAnalyzer:
    """Audit Astral ty configuration for type-safety and security hygiene risks.

    Scans ty.toml and pyproject.toml [tool.ty] for disabled rules, broad import
    allowances, fail-open terminal settings, insecure extra-paths, and hardcoded
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
        ty_toml = self.root / "ty.toml"
        if ty_toml.is_file():
            found.append(ty_toml)
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return found
            if "[tool.ty" in text or "[tool:ty" in text:
                found.append(pyproject)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TyFinding],
        info: TyInfo,
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
                    message="insecure HTTP URL in ty config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RULES_ALL_IGNORE_PATTERN.search(stripped):
            info.rules_all = "ignore"
            findings.append(
                TyFinding(
                    kind="rules_all_ignore",
                    severity="high",
                    message='all = "ignore" disables every ty rule — remove or set to "error"',
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RULE_IGNORE_PATTERN.search(stripped):
            findings.append(
                TyFinding(
                    kind="critical_rule_ignored",
                    severity="high",
                    message="critical type-safety rule set to ignore — enable error severity",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ERROR_ON_WARNING_FALSE_PATTERN.search(stripped):
            findings.append(
                TyFinding(
                    kind="error_on_warning_false",
                    severity="medium",
                    message="error-on-warning=false allows CI to pass with type warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RESPECT_TYPE_IGNORE_FALSE_PATTERN.search(stripped):
            findings.append(
                TyFinding(
                    kind="respect_type_ignore_false",
                    severity="low",
                    message="respect-type-ignore-comments=false may hide intentional suppressions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BROAD_ALLOWED_IMPORTS_PATTERN.search(stripped):
            findings.append(
                TyFinding(
                    kind="broad_allowed_imports",
                    severity="medium",
                    message="allowed-unresolved-imports uses wildcard — narrow to specific modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(stripped):
            findings.append(
                TyFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_EXTRA_PATH_PATTERN.search(stripped):
            findings.append(
                TyFinding(
                    kind="insecure_extra_path",
                    severity="high",
                    message="extra-paths points outside the project — restrict to trusted paths",
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

    def _scan_overrides(self, text: str, rel: str, findings: list[TyFinding]) -> None:
        if OVERRIDE_RULE_IGNORE_PATTERN.search(text):
            findings.append(
                TyFinding(
                    kind="override_rules_ignore",
                    severity="high",
                    message="[[tool.ty.overrides]] disables critical rules — review override blocks",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TyFinding], TyInfo]:
        findings: list[TyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, TyInfo(path=rel, file_kind=_file_kind(path))

        info = TyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_ty_section = path.name == "ty.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                in_ty_section = self._in_ty_section(line, in_ty_section, path)
                if not in_ty_section:
                    continue
            self._scan_line(line, lineno, rel, findings, info)

        if path.name == "pyproject.toml":
            self._scan_overrides(raw_text, rel, findings)

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
[tool.ty.rules]
all = "error"
possibly-unresolved-reference = "error"
possibly-missing-import = "error"
division-by-zero = "error"

[tool.ty.analysis]
respect-type-ignore-comments = true

[tool.ty.src]
include = ["src", "tests"]
exclude = ["**/__pycache__", ".venv", "build", "dist"]

[tool.ty.terminal]
error-on-warning = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "ty configs: none found"
        return (
            f"ty configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "ty analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            rules_all = info.rules_all or "default"
            lines.append(f"  - {info.path}: rules.all={rules_all}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
