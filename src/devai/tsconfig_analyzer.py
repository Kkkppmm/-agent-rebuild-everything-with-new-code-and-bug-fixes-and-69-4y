"""TsconfigAnalyzer — audit TypeScript/JavaScript compiler configs for security and strictness risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "tsconfig.json",
    "jsconfig.json",
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
STRICT_FALSE_PATTERN = re.compile(
    r'["\']?strict["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)
NO_IMPLICIT_ANY_FALSE_PATTERN = re.compile(
    r'["\']?noImplicitAny["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)
STRICT_NULL_CHECKS_FALSE_PATTERN = re.compile(
    r'["\']?strictNullChecks["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)
SKIP_LIB_CHECK_TRUE_PATTERN = re.compile(
    r'["\']?skipLibCheck["\']?\s*:\s*(?:true|1)',
    re.IGNORECASE,
)
NO_EMIT_ON_ERROR_FALSE_PATTERN = re.compile(
    r'["\']?noEmitOnError["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)
SOURCE_MAP_TRUE_PATTERN = re.compile(
    r'["\']?(?:sourceMap|inlineSourceMap|sourcemap)["\']?\s*:\s*(?:true|1)',
    re.IGNORECASE,
)
ALLOW_JS_TRUE_PATTERN = re.compile(
    r'["\']?allowJs["\']?\s*:\s*(?:true|1)',
    re.IGNORECASE,
)
CHECK_JS_FALSE_PATTERN = re.compile(
    r'["\']?checkJs["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)
SUPPRESS_INDEX_ERRORS_PATTERN = re.compile(
    r'["\']?suppressImplicitAnyIndexErrors["\']?\s*:\s*(?:true|1)',
    re.IGNORECASE,
)
IGNORE_DEPRECATIONS_PATTERN = re.compile(
    r'["\']?ignoreDeprecations["\']?\s*:\s*["\'][^"\']+["\']',
    re.IGNORECASE,
)
EXCLUDE_SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'])(?:src|lib|app|security|auth|api)(?:/|[\s\"']|$)",
    re.IGNORECASE,
)
EXCLUDE_WILDCARD_PATTERN = re.compile(
    r'["\']?exclude["\']?\s*:\s*[^\n]*\*',
    re.IGNORECASE,
)
FORCE_CONSISTENT_CASING_FALSE_PATTERN = re.compile(
    r'["\']?forceConsistentCasingInFileNames["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)

STRICTNESS_OPTIONS = frozenset(
    {
        "strict",
        "noImplicitAny",
        "strictNullChecks",
        "strictFunctionTypes",
        "strictBindCallApply",
        "strictPropertyInitialization",
        "noImplicitThis",
        "alwaysStrict",
    }
)


@dataclass
class TsconfigFinding:
    """A security or best-practice issue in a TypeScript/JavaScript compiler config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TsconfigInfo:
    """Parsed metadata about a tsconfig/jsconfig file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    strict: bool | None = None
    target: str | None = None
    module: str | None = None
    disabled_strictness: list[str] = field(default_factory=list)
    has_exclude: bool = False
    has_include: bool = False


@dataclass
class TsconfigStats:
    """Aggregate tsconfig analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    name = path.name.lower()
    return name in CONFIG_NAMES or (
        name.startswith("tsconfig.") and name.endswith(".json")
    )


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "jsconfig.json":
        return "jsconfig"
    if name.startswith("tsconfig."):
        return "tsconfig-variant"
    return "tsconfig"


def _extract_bool_option(line: str, key: str) -> bool | None:
    match = re.search(
        rf'["\']?{re.escape(key)}["\']?\s*:\s*(true|false|1|0)',
        line,
        re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1).lower() in ("true", "1")


def _extract_string_option(line: str, key: str) -> str | None:
    match = re.search(
        rf'["\']?{re.escape(key)}["\']?\s*:\s*["\']([^"\']+)["\']',
        line,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    return None


class TsconfigAnalyzer:
    """Audit TypeScript/JavaScript compiler configs for security and strictness risks.

    Scans ``tsconfig.json``, ``tsconfig.*.json``, and ``jsconfig.json`` for
    disabled strict mode, relaxed null checks, hardcoded secrets, broad exclude
    patterns on source directories, and source-map exposure in production configs.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[TsconfigFinding] | None = None
        self._stats: TsconfigStats | None = None
        self._infos: list[TsconfigInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return TypeScript/JavaScript compiler config paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("tsconfig*.json")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TsconfigFinding],
        info: TsconfigInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        strict_val = _extract_bool_option(stripped, "strict")
        if strict_val is not None:
            info.strict = strict_val

        target = _extract_string_option(stripped, "target")
        if target:
            info.target = target

        module = _extract_string_option(stripped, "module")
        if module:
            info.module = module

        if re.search(r'["\']?exclude["\']?\s*:', stripped, re.IGNORECASE):
            info.has_exclude = True
        if re.search(r'["\']?include["\']?\s*:', stripped, re.IGNORECASE):
            info.has_include = True

        for option in STRICTNESS_OPTIONS:
            if re.search(
                rf'["\']?{option}["\']?\s*:\s*(?:false|0)',
                stripped,
                re.IGNORECASE,
            ):
                if option not in info.disabled_strictness:
                    info.disabled_strictness.append(option)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in compiler config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in compiler config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in compiler config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="strict_disabled",
                    severity="medium",
                    message="strict mode disabled — weakens type safety across the project",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_IMPLICIT_ANY_FALSE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="no_implicit_any_disabled",
                    severity="medium",
                    message="noImplicitAny disabled — implicit any types can hide bugs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_NULL_CHECKS_FALSE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="strict_null_checks_disabled",
                    severity="medium",
                    message="strictNullChecks disabled — null/undefined errors may slip through",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SKIP_LIB_CHECK_TRUE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="skip_lib_check",
                    severity="medium",
                    message="skipLibCheck enabled — declaration file issues may go undetected",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NO_EMIT_ON_ERROR_FALSE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="no_emit_on_error_disabled",
                    severity="medium",
                    message="noEmitOnError disabled — builds may succeed with type errors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SOURCE_MAP_TRUE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="source_map_enabled",
                    severity="low",
                    message="source maps enabled — may expose source in production bundles",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SUPPRESS_INDEX_ERRORS_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="suppress_index_errors",
                    severity="medium",
                    message="suppressImplicitAnyIndexErrors enabled — index access bugs may be hidden",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_DEPRECATIONS_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="ignore_deprecations",
                    severity="low",
                    message="ignoreDeprecations set — compiler migration warnings are suppressed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORCE_CONSISTENT_CASING_FALSE_PATTERN.search(line):
            findings.append(
                TsconfigFinding(
                    kind="force_consistent_casing_disabled",
                    severity="low",
                    message="forceConsistentCasingInFileNames disabled — cross-platform import bugs possible",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EXCLUDE_WILDCARD_PATTERN.search(line) and EXCLUDE_SENSITIVE_PATH_PATTERN.search(
            line
        ):
            findings.append(
                TsconfigFinding(
                    kind="broad_exclude",
                    severity="medium",
                    message="broad exclude pattern on source paths — type checking may be skipped",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_options(
        self,
        options: dict,
        rel: str,
        findings: list[TsconfigFinding],
        info: TsconfigInfo,
    ) -> None:
        if not isinstance(options, dict):
            return

        if "strict" in options:
            info.strict = bool(options["strict"])
            if options["strict"] is False:
                findings.append(
                    TsconfigFinding(
                        kind="strict_disabled",
                        severity="medium",
                        message="strict mode disabled — weakens type safety across the project",
                        path=rel,
                        lineno=1,
                        line="strict",
                    )
                )

        for key in ("target", "module"):
            if key in options and isinstance(options[key], str):
                setattr(info, key, options[key])

        for option in STRICTNESS_OPTIONS:
            if option in options and options[option] is False:
                if option not in info.disabled_strictness:
                    info.disabled_strictness.append(option)
                if option in ("noImplicitAny", "strictNullChecks"):
                    kind = (
                        "no_implicit_any_disabled"
                        if option == "noImplicitAny"
                        else "strict_null_checks_disabled"
                    )
                    findings.append(
                        TsconfigFinding(
                            kind=kind,
                            severity="medium",
                            message=f"{option} disabled in compilerOptions",
                            path=rel,
                            lineno=1,
                            line=option,
                        )
                    )

        if options.get("skipLibCheck") is True:
            findings.append(
                TsconfigFinding(
                    kind="skip_lib_check",
                    severity="medium",
                    message="skipLibCheck enabled — declaration file issues may go undetected",
                    path=rel,
                    lineno=1,
                    line="skipLibCheck",
                )
            )

        if options.get("noEmitOnError") is False:
            findings.append(
                TsconfigFinding(
                    kind="no_emit_on_error_disabled",
                    severity="medium",
                    message="noEmitOnError disabled — builds may succeed with type errors",
                    path=rel,
                    lineno=1,
                    line="noEmitOnError",
                )
            )

        if options.get("allowJs") is True and options.get("checkJs") is False:
            findings.append(
                TsconfigFinding(
                    kind="allow_js_without_check",
                    severity="medium",
                    message="allowJs enabled without checkJs — JavaScript files bypass type checks",
                    path=rel,
                    lineno=1,
                    line="allowJs",
                )
            )

        if options.get("sourceMap") is True or options.get("inlineSourceMap") is True:
            findings.append(
                TsconfigFinding(
                    kind="source_map_enabled",
                    severity="low",
                    message="source maps enabled — may expose source in production bundles",
                    path=rel,
                    lineno=1,
                    line="sourceMap",
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TsconfigFinding], TsconfigInfo]:
        findings: list[TsconfigFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, TsconfigInfo(path=rel, file_kind=_file_kind(path))

        info = TsconfigInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        try:
            data = json.loads(raw_text)
            if isinstance(data, dict):
                compiler_options = data.get("compilerOptions", {})
                if isinstance(compiler_options, dict):
                    self._analyze_json_options(compiler_options, rel, findings, info)
                if "exclude" in data:
                    info.has_exclude = True
                if "include" in data:
                    info.has_include = True
        except json.JSONDecodeError:
            findings.append(
                TsconfigFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="compiler config is not valid JSON — fix syntax before relying on types",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if info.strict is False and ALLOW_JS_TRUE_PATTERN.search(raw_text):
            if CHECK_JS_FALSE_PATTERN.search(raw_text) or '"checkJs"' not in raw_text:
                if not any(f.kind == "allow_js_without_check" for f in findings):
                    findings.append(
                        TsconfigFinding(
                            kind="allow_js_without_check",
                            severity="medium",
                            message="allowJs enabled without checkJs — JavaScript files bypass type checks",
                            path=rel,
                            lineno=1,
                            line="allowJs",
                        )
                    )

        return findings, info

    def analyze(self) -> list[TsconfigFinding]:
        """Scan TypeScript/JavaScript compiler configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TsconfigFinding] = []
        infos: list[TsconfigInfo] = []
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
        self._stats = TsconfigStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TsconfigStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TsconfigInfo]:
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
        """Scaffold a hardened tsconfig.json template."""
        return """\
{
  // Generated by DevAI TsconfigAnalyzer
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noEmitOnError": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": false,
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": false,
    "inlineSourceMap": false
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "build"]
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "TypeScript: no compiler config files found"
        return (
            f"TypeScript: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "TypeScript compiler configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            strict = "enabled" if info.strict else "disabled" if info.strict is False else "unset"
            lines.append(
                f"  - {info.path} ({info.file_kind}): strict={strict}, "
                f"target={info.target or 'unset'}, module={info.module or 'unset'}"
            )
            if info.disabled_strictness:
                lines.append(
                    f"    disabled strictness: {', '.join(info.disabled_strictness)}"
                )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
