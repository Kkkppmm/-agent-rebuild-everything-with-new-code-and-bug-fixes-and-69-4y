"""BasedpyrightAnalyzer — audit pyproject.toml [tool.basedpyright] for type-safety risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
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


def _key_pattern(name: str) -> str:
    return rf'["\']?{name}["\']?\s*[=:]'


TYPE_CHECKING_OFF_PATTERN = re.compile(
    _key_pattern("typeCheckingMode") + r'\s*["\']?off["\']?(?:\s|,|$|\]|})',
    re.IGNORECASE,
)
TYPE_CHECKING_BASIC_PATTERN = re.compile(
    _key_pattern("typeCheckingMode") + r'\s*["\']?basic["\']?(?:\s|,|$|\]|})',
    re.IGNORECASE,
)
REPORT_MISSING_IMPORTS_FALSE_PATTERN = re.compile(
    _key_pattern("reportMissingImports") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_GENERAL_TYPE_ISSUES_FALSE_PATTERN = re.compile(
    _key_pattern("reportGeneralTypeIssues") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNKNOWN_MEMBER_FALSE_PATTERN = re.compile(
    _key_pattern("reportUnknownMemberType") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNKNOWN_ARGUMENT_FALSE_PATTERN = re.compile(
    _key_pattern("reportUnknownArgumentType") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNKNOWN_VARIABLE_FALSE_PATTERN = re.compile(
    _key_pattern("reportUnknownVariableType") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNTYPED_FUNCTION_DECORATOR_FALSE_PATTERN = re.compile(
    _key_pattern("reportUntypedFunctionDecorator") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNTYPED_CLASS_DECORATOR_FALSE_PATTERN = re.compile(
    _key_pattern("reportUntypedClassDecorator") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNTYPED_BASE_CLASS_FALSE_PATTERN = re.compile(
    _key_pattern("reportUntypedBaseClass") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
ANALYZE_UNANNOTATED_FUNCTIONS_FALSE_PATTERN = re.compile(
    _key_pattern("analyzeUnannotatedFunctions") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
STRICT_LIST_INFERENCE_FALSE_PATTERN = re.compile(
    _key_pattern("strictListInference") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
STRICT_DICTIONARY_INFERENCE_FALSE_PATTERN = re.compile(
    _key_pattern("strictDictionaryInference") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_MISSING_TYPE_STUBS_FALSE_PATTERN = re.compile(
    _key_pattern("reportMissingTypeStubs") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_ANY_FALSE_PATTERN = re.compile(
    _key_pattern("reportAny") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_EXPLICIT_ANY_FALSE_PATTERN = re.compile(
    _key_pattern("reportExplicitAny") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_UNUSED_CALL_RESULT_FALSE_PATTERN = re.compile(
    _key_pattern("reportUnusedCallResult") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_IMPLICIT_OVERRIDE_FALSE_PATTERN = re.compile(
    _key_pattern("reportImplicitOverride") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_PRIVATE_IMPORT_USAGE_FALSE_PATTERN = re.compile(
    _key_pattern("reportPrivateImportUsage") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_DEPRECATED_FALSE_PATTERN = re.compile(
    _key_pattern("reportDeprecated") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_INCOMPATIBLE_METHOD_OVERRIDE_FALSE_PATTERN = re.compile(
    _key_pattern("reportIncompatibleMethodOverride") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_INCOMPATIBLE_VARIABLE_OVERRIDE_FALSE_PATTERN = re.compile(
    _key_pattern("reportIncompatibleVariableOverride") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
REPORT_OVERLAPPING_OVERLOAD_FALSE_PATTERN = re.compile(
    _key_pattern("reportOverlappingOverload") + r'\s*(?:false|False)(?:\s|,|$|\]|})',
)
BASELINE_FILE_INSECURE_PATTERN = re.compile(
    r'(?:["\']?baselineFile["\']?)\s*[=:]\s*["\']?(?:/tmp/|\.\./|/etc/)',
    re.IGNORECASE,
)
EXCLUDE_SOURCE_PATTERN = re.compile(
    r'(?:["\']?exclude["\']?|["\']?ignore["\']?)\s*[=:\[][^\n]*(?:\"src\"|\'src\'|\"lib\'|\'lib\'|\"app\'|\'app\'|'
    r"\bsrc/|\blib/|\bapp/)",
    re.IGNORECASE,
)
INSECURE_EXTRA_PATH_PATTERN = re.compile(
    r'(?:["\']?extraPaths["\']?|["\']?stubPath["\']?)\s*[=:\[][^\n]*(?:/tmp/|/etc/|\.\./)',
    re.IGNORECASE,
)
BASEDPYRIGHT_SECTION_PATTERN = re.compile(
    r"^\[(?:tool[.:]basedpyright(?:\.[^\]]+)?)\]",
    re.IGNORECASE,
)


@dataclass
class BasedpyrightFinding:
    """A security or best-practice issue in a Basedpyright configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BasedpyrightInfo:
    """Parsed metadata about a Basedpyright configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    type_checking_mode: str | None = None


@dataclass
class BasedpyrightStats:
    """Aggregate Basedpyright analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "toml"
    return "unknown"


class BasedpyrightAnalyzer:
    """Audit Basedpyright configuration for type-safety and security hygiene risks.

    Scans pyproject.toml [tool.basedpyright] for relaxed type checking, disabled
    report rules (including Basedpyright-specific rules), broad exclude patterns,
    insecure extraPaths, baseline files outside the project, and hardcoded secrets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BasedpyrightFinding] | None = None
        self._stats: BasedpyrightStats | None = None
        self._infos: list[BasedpyrightInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Basedpyright configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "[tool.basedpyright" not in text and "[tool:basedpyright" not in text:
                continue
            found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BasedpyrightFinding],
        info: BasedpyrightInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Basedpyright config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Basedpyright config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Basedpyright config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TYPE_CHECKING_OFF_PATTERN.search(line):
            info.type_checking_mode = "off"
            findings.append(
                BasedpyrightFinding(
                    kind="type_checking_off",
                    severity="high",
                    message="typeCheckingMode=off disables Basedpyright — use standard or strict",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TYPE_CHECKING_BASIC_PATTERN.search(line):
            info.type_checking_mode = "basic"
            findings.append(
                BasedpyrightFinding(
                    kind="type_checking_basic",
                    severity="low",
                    message="typeCheckingMode=basic is less strict than standard — consider upgrading",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(
            _key_pattern("typeCheckingMode") + r'\s*["\']?strict["\']?(?:\s|,|$|\]|})',
            stripped,
            re.IGNORECASE,
        ):
            info.type_checking_mode = "strict"
        elif re.search(
            _key_pattern("typeCheckingMode") + r'\s*["\']?standard["\']?(?:\s|,|$|\]|})',
            stripped,
            re.IGNORECASE,
        ):
            info.type_checking_mode = "standard"

        if REPORT_MISSING_IMPORTS_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_missing_imports_false",
                    severity="medium",
                    message="reportMissingImports=false hides missing import errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_GENERAL_TYPE_ISSUES_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_general_type_issues_false",
                    severity="high",
                    message="reportGeneralTypeIssues=false suppresses core type errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNKNOWN_MEMBER_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_unknown_member_false",
                    severity="medium",
                    message="reportUnknownMemberType=false silences unknown attribute warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNKNOWN_ARGUMENT_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_unknown_argument_false",
                    severity="medium",
                    message="reportUnknownArgumentType=false silences unknown argument warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNKNOWN_VARIABLE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_unknown_variable_false",
                    severity="medium",
                    message="reportUnknownVariableType=false silences unknown variable warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNTYPED_FUNCTION_DECORATOR_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_untyped_function_decorator_false",
                    severity="medium",
                    message="reportUntypedFunctionDecorator=false allows untyped decorators",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNTYPED_CLASS_DECORATOR_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_untyped_class_decorator_false",
                    severity="medium",
                    message="reportUntypedClassDecorator=false allows untyped class decorators",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNTYPED_BASE_CLASS_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_untyped_base_class_false",
                    severity="medium",
                    message="reportUntypedBaseClass=false allows untyped base classes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ANALYZE_UNANNOTATED_FUNCTIONS_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="analyze_unannotated_functions_false",
                    severity="medium",
                    message="analyzeUnannotatedFunctions=false skips unannotated function bodies",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_LIST_INFERENCE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="strict_list_inference_false",
                    severity="low",
                    message="strictListInference=false weakens list type inference",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_DICTIONARY_INFERENCE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="strict_dictionary_inference_false",
                    severity="low",
                    message="strictDictionaryInference=false weakens dict type inference",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_MISSING_TYPE_STUBS_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_missing_type_stubs_false",
                    severity="low",
                    message="reportMissingTypeStubs=false hides missing stub warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_ANY_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_any_false",
                    severity="medium",
                    message="reportAny=false allows implicit Any without warnings",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_EXPLICIT_ANY_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_explicit_any_false",
                    severity="medium",
                    message="reportExplicitAny=false hides explicit Any annotations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_UNUSED_CALL_RESULT_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_unused_call_result_false",
                    severity="low",
                    message="reportUnusedCallResult=false hides ignored return values",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_IMPLICIT_OVERRIDE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_implicit_override_false",
                    severity="medium",
                    message="reportImplicitOverride=false hides missing @override decorators",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_PRIVATE_IMPORT_USAGE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_private_import_usage_false",
                    severity="low",
                    message="reportPrivateImportUsage=false hides private import usage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_DEPRECATED_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_deprecated_false",
                    severity="low",
                    message="reportDeprecated=false hides deprecated API usage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_INCOMPATIBLE_METHOD_OVERRIDE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_incompatible_method_override_false",
                    severity="medium",
                    message="reportIncompatibleMethodOverride=false hides unsafe method overrides",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_INCOMPATIBLE_VARIABLE_OVERRIDE_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_incompatible_variable_override_false",
                    severity="medium",
                    message="reportIncompatibleVariableOverride=false hides unsafe attribute overrides",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if REPORT_OVERLAPPING_OVERLOAD_FALSE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="report_overlapping_overload_false",
                    severity="medium",
                    message="reportOverlappingOverload=false hides conflicting overload signatures",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if BASELINE_FILE_INSECURE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
                    kind="baseline_file_insecure",
                    severity="high",
                    message="baselineFile points outside the project — keep baselines in-repo",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_SOURCE_PATTERN.search(line):
            findings.append(
                BasedpyrightFinding(
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
                BasedpyrightFinding(
                    kind="insecure_extra_path",
                    severity="high",
                    message="extraPaths/stubPath points outside the project — restrict to trusted paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _in_basedpyright_section(self, line: str, in_section: bool) -> bool:
        if BASEDPYRIGHT_SECTION_PATTERN.match(line.strip()):
            return True
        if line.strip().startswith("[") and not BASEDPYRIGHT_SECTION_PATTERN.match(line.strip()):
            return False
        return in_section

    def _analyze_file(self, path: Path) -> tuple[list[BasedpyrightFinding], BasedpyrightInfo]:
        findings: list[BasedpyrightFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, BasedpyrightInfo(path=rel, file_kind=_file_kind(path))

        info = BasedpyrightInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        in_section = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            in_section = self._in_basedpyright_section(line, in_section)
            if not in_section:
                continue
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[BasedpyrightFinding]:
        """Scan Basedpyright configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BasedpyrightFinding] = []
        infos: list[BasedpyrightInfo] = []
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
        self._stats = BasedpyrightStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BasedpyrightStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BasedpyrightInfo]:
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
        """Scaffold a hardened Basedpyright configuration template."""
        return """\
# Generated by DevAI BasedpyrightAnalyzer
[tool.basedpyright]
include = ["src"]
exclude = [
    "**/__pycache__",
    ".venv",
    "build",
    "dist",
]
typeCheckingMode = "strict"
reportMissingImports = true
reportMissingTypeStubs = true
reportGeneralTypeIssues = true
reportUnknownMemberType = true
reportUnknownArgumentType = true
reportUnknownVariableType = true
reportUntypedFunctionDecorator = true
reportUntypedClassDecorator = true
reportUntypedBaseClass = true
analyzeUnannotatedFunctions = true
strictListInference = true
strictDictionaryInference = true
reportAny = true
reportExplicitAny = true
reportUnusedCallResult = true
reportImplicitOverride = true
reportPrivateImportUsage = true
reportDeprecated = true
reportIncompatibleMethodOverride = true
reportIncompatibleVariableOverride = true
reportOverlappingOverload = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Basedpyright configs: none found"
        return (
            f"Basedpyright configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Basedpyright analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            mode = info.type_checking_mode or "default"
            lines.append(f"  - {info.path}: typeCheckingMode={mode}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
