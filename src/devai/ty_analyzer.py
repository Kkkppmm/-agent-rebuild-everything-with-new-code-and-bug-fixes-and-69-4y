"""TyAnalyzer — audit Astral ty type checker configs for type-safety and hygiene risks."""

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
RULES_ALL_IGNORE_PATTERN = re.compile(
    r"(?:^|\s)(?:all|rules\.all)\s*=\s*[\"']ignore[\"']",
    re.IGNORECASE,
)
RULE_IGNORE_IMPORT_PATTERN = re.compile(
    r"(?:unresolved-import|possibly-unresolved-reference|possibly-missing-import|"
    r"missing-dependency)\s*=\s*[\"']ignore[\"']",
    re.IGNORECASE,
)
RULE_IGNORE_ASSIGNMENT_PATTERN = re.compile(
    r"(?:invalid-assignment|invalid-argument-type|invalid-return-type|"
    r"unresolved-attribute)\s*=\s*[\"']ignore[\"']",
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
REPLACE_IMPORTS_WITH_ANY_PATTERN = re.compile(
    r"replace-imports-with-any\s*=\s*\[[^\]]+[\"']",
    re.IGNORECASE,
)
ALLOWED_UNRESOLVED_BROAD_PATTERN = re.compile(
    r"allowed-unresolved-imports\s*=\s*\[[^\]]*(?:\"\*\"|\'\*\'|\"\*\*\"|\'\*\*\'|\"\.\*\"|\'\.\*\')",
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r"(?:exclude|include)\s*=\s*\[[^\]]*[\"'](?:src|lib|app)[\"']",
    re.IGNORECASE,
)
OVERRIDE_IGNORE_RULES_PATTERN = re.compile(
    r"(?:\[\[?(?:tool[.:]ty\.)?overrides\]\]?|include\s*=\s*\[[^\]]*\])\s*"
    r"[^\n]*rules\s*=\s*\{[^\}]*[\"']ignore[\"']",
    re.IGNORECASE,
)
EXCLUDE_SCRIPTS_TRUE_PATTERN = re.compile(
    r"exclude-scripts\s*=\s*true\b",
    re.IGNORECASE,
)
STRICT_EQUALITY_FALSE_PATTERN = re.compile(
    r"strict-equality-semantics\s*=\s*false\b",
    re.IGNORECASE,
)
STRICT_GENERIC_FALSE_PATTERN = re.compile(
    r"strict-generic-narrowing\s*=\s*false\b",
    re.IGNORECASE,
)
INSECURE_EXTRA_PATH_PATTERN = re.compile(
    r"(?:extra-paths|python-path|root)\s*=\s*[\"']?(?:/tmp/|/etc/|\.\./)",
    re.IGNORECASE,
)
TY_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]ty(?:\.[^\]]+)?|rules|environment|analysis|src|terminal|overrides)\]",
    re.IGNORECASE,
)
TY_PYPROJECT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]ty(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)
TY_STANDALONE_SECTION_PATTERN = re.compile(
    r"^\[(?:rules|environment|analysis|src|terminal|overrides)\]",
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
    sections: list[str] = field(default_factory=list)
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
        return "toml"
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


def _extract_ignored_rules(line: str) -> list[str]:
    match = re.search(
        r"^([a-z][a-z0-9-]*)\s*=\s*[\"']ignore[\"']",
        line.strip(),
        re.IGNORECASE,
    )
    if match:
        return [match.group(1)]
    return []


class TyAnalyzer:
    """Audit Astral ty type checker configuration for type-safety hygiene risks.

    Scans ty.toml and pyproject.toml [tool.ty] sections for rules.all=ignore,
    disabled import/assignment rules, broad allowed-unresolved-imports patterns,
    replace-imports-with-any overrides, hardcoded secrets, and insecure paths.
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

        section_match = TY_SECTION_PATTERN.match(stripped)
        if section_match:
            section = section_match.group(0).strip("[]")
            if section not in info.sections:
                info.sections.append(section)

        for rule in _extract_ignored_rules(stripped):
            if rule not in info.ignored_rules:
                info.ignored_rules.append(rule)

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

        if RULES_ALL_IGNORE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="rules_all_ignore",
                    severity="high",
                    message='rules.all="ignore" disables all type checks — remove or narrow ignores',
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RULE_IGNORE_IMPORT_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="ignored_import_rules",
                    severity="high",
                    message="import resolution rules set to ignore — keep unresolved import checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RULE_IGNORE_ASSIGNMENT_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="ignored_assignment_rules",
                    severity="medium",
                    message="assignment/attribute rules set to ignore — keep core type checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ERROR_ON_WARNING_FALSE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="error_on_warning_false",
                    severity="medium",
                    message="error-on-warning=false allows warnings in CI — keep warnings failing in CI",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RESPECT_TYPE_IGNORE_FALSE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="respect_type_ignore_false",
                    severity="medium",
                    message="respect-type-ignore-comments=false disables # type: ignore handling",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPLACE_IMPORTS_WITH_ANY_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="replace_imports_with_any",
                    severity="high",
                    message="replace-imports-with-any silences import errors — remove broad any replacements",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOWED_UNRESOLVED_BROAD_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="allowed_unresolved_broad",
                    severity="medium",
                    message="allowed-unresolved-imports uses broad wildcards — narrow to specific modules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line) and "exclude" in stripped.lower():
            findings.append(
                TyFinding(
                    kind="exclude_source",
                    severity="medium",
                    message="exclude skips source directories from type checking — narrow exclusions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if OVERRIDE_IGNORE_RULES_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="override_ignore_rules",
                    severity="high",
                    message="override ignores type rules for matched files — avoid blanket relaxations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SCRIPTS_TRUE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="exclude_scripts",
                    severity="low",
                    message="exclude-scripts=true skips PEP 723 scripts — enable unless scripts are untrusted",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_EQUALITY_FALSE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="strict_equality_false",
                    severity="low",
                    message="strict-equality-semantics=false relaxes equality checks — keep strict mode",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_GENERIC_FALSE_PATTERN.search(line):
            findings.append(
                TyFinding(
                    kind="strict_generic_false",
                    severity="low",
                    message="strict-generic-narrowing=false relaxes generic narrowing — keep strict mode",
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
                    message="insecure extra path in ty environment — restrict to project-local paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TyFinding], TyInfo]:
        findings: list[TyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TyInfo(path=rel, file_kind=_file_kind(path))

        info = TyInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_ty_section = path.name == "ty.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            if path.name == "pyproject.toml":
                if TY_PYPROJECT_SECTION_PATTERN.match(line.strip()):
                    in_ty_section = True
                elif line.strip().startswith("[") and not TY_PYPROJECT_SECTION_PATTERN.match(
                    line.strip()
                ):
                    in_ty_section = False
                if not in_ty_section:
                    continue
            elif path.name == "ty.toml":
                if TY_STANDALONE_SECTION_PATTERN.match(line.strip()):
                    in_ty_section = True
                elif line.strip().startswith("[") and not TY_STANDALONE_SECTION_PATTERN.match(
                    line.strip()
                ):
                    in_ty_section = False
                if not in_ty_section and not line.strip().startswith("#"):
                    if "[[overrides]]" in line or "[[tool.ty.overrides]]" in line:
                        in_ty_section = True
                    elif line.strip().startswith("[[") and "overrides" in line:
                        in_ty_section = True
                    else:
                        continue
            self._scan_line(line, lineno, rel, findings, info)

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
[tool.ty.environment]
python-version = "3.12"

[tool.ty.rules]
possibly-unresolved-reference = "warn"
possibly-missing-import = "error"
unresolved-import = "error"
invalid-assignment = "error"
invalid-return-type = "error"

[tool.ty.terminal]
error-on-warning = true

[tool.ty.analysis]
respect-type-ignore-comments = true
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
            ignored = ", ".join(info.ignored_rules) if info.ignored_rules else "none"
            lines.append(f"  - {info.path}: ignored rules={ignored}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
