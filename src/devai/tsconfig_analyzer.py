"""TsconfigAnalyzer — audit TypeScript compiler configs for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "tsconfig.json",
    "tsconfig.app.json",
    "tsconfig.node.json",
    "tsconfig.build.json",
    "tsconfig.base.json",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:[\"']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']?)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(r'"strict"\s*:\s*false\b', re.IGNORECASE)
NO_IMPLICIT_ANY_FALSE_PATTERN = re.compile(
    r'"noImplicitAny"\s*:\s*false\b',
    re.IGNORECASE,
)
SKIP_LIB_CHECK_TRUE_PATTERN = re.compile(
    r'"skipLibCheck"\s*:\s*true\b',
    re.IGNORECASE,
)
ALLOW_JS_NO_CHECK_PATTERN = re.compile(
    r'"allowJs"\s*:\s*true\b',
    re.IGNORECASE,
)
CHECK_JS_FALSE_PATTERN = re.compile(
    r'"checkJs"\s*:\s*false\b',
    re.IGNORECASE,
)
SUPPRESS_EXCESSIVE_FALSE_POSITIVES_PATTERN = re.compile(
    r'"suppressExcessPropertyErrors"\s*:\s*true\b',
    re.IGNORECASE,
)
NO_UNUSED_LOCALS_FALSE_PATTERN = re.compile(
    r'"noUnusedLocals"\s*:\s*false\b',
    re.IGNORECASE,
)
NO_UNUSED_PARAMETERS_FALSE_PATTERN = re.compile(
    r'"noUnusedParameters"\s*:\s*false\b',
    re.IGNORECASE,
)
STRICT_NULL_CHECKS_FALSE_PATTERN = re.compile(
    r'"strictNullChecks"\s*:\s*false\b',
    re.IGNORECASE,
)
PATHS_WILDCARD_PATTERN = re.compile(
    r'"paths"\s*:\s*\{[^}]*"\*"\s*:',
    re.IGNORECASE | re.DOTALL,
)
TYPE_ACQUISITION_ALL_PATTERN = re.compile(
    r'"typeAcquisition"\s*:\s*\{[^}]*"enable"\s*:\s*true',
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class TsconfigFinding:
    """A security or best-practice issue in a TypeScript configuration file."""

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
    """Parsed metadata about a TypeScript configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "json"
    strict: bool | None = None
    target: str = ""
    module: str = ""
    extends: str = ""


@dataclass
class TsconfigStats:
    """Aggregate TypeScript config analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_tsconfig_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or (
        path.name.startswith("tsconfig.") and path.suffix == ".json"
    )


def _extract_json_string(line: str, key: str) -> str | None:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]+)"', line)
    return match.group(1) if match else None


def _extract_json_bool(line: str, key: str) -> bool | None:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*(true|false)\b', line, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).lower() == "true"


class TsconfigAnalyzer:
    """Audit TypeScript compiler configuration for security and type-safety risks.

    Scans tsconfig.json and variants for disabled strict checks, skipLibCheck,
    permissive path mappings, hardcoded secrets, and unsafe JS interop settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TsconfigFinding] | None = None
        self._stats: TsconfigStats | None = None
        self._infos: list[TsconfigInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return TypeScript configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.glob("tsconfig.*.json")):
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

        strict_val = _extract_json_bool(stripped, "strict")
        if strict_val is not None:
            info.strict = strict_val
        target = _extract_json_string(stripped, "target")
        if target:
            info.target = target
        module = _extract_json_string(stripped, "module")
        if module:
            info.module = module
        extends = _extract_json_string(stripped, "extends")
        if extends:
            info.extends = extends

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in tsconfig — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in tsconfig — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium",
             "insecure HTTP URL in tsconfig — use HTTPS endpoints"),
            (STRICT_FALSE_PATTERN, "strict_false", "high",
             "strict:false disables core type safety — enable strict mode"),
            (NO_IMPLICIT_ANY_FALSE_PATTERN, "no_implicit_any_false", "high",
             "noImplicitAny:false allows untyped values — enable for safety"),
            (STRICT_NULL_CHECKS_FALSE_PATTERN, "strict_null_checks_false", "high",
             "strictNullChecks:false allows null dereference bugs"),
            (SKIP_LIB_CHECK_TRUE_PATTERN, "skip_lib_check", "medium",
             "skipLibCheck:true skips dependency type validation"),
            (ALLOW_JS_NO_CHECK_PATTERN, "allow_js", "medium",
             "allowJs:true without checkJs — untyped JS can bypass checks"),
            (CHECK_JS_FALSE_PATTERN, "check_js_false", "medium",
             "checkJs:false skips type checking on JavaScript files"),
            (SUPPRESS_EXCESSIVE_FALSE_POSITIVES_PATTERN, "suppress_excess_errors", "medium",
             "suppressExcessPropertyErrors hides unsafe object literals"),
            (NO_UNUSED_LOCALS_FALSE_PATTERN, "no_unused_locals_false", "low",
             "noUnusedLocals:false allows dead code accumulation"),
            (NO_UNUSED_PARAMETERS_FALSE_PATTERN, "no_unused_parameters_false", "low",
             "noUnusedParameters:false hides unused API surface"),
            (PATHS_WILDCARD_PATTERN, "paths_wildcard", "medium",
             "paths wildcard mapping can resolve unexpected modules"),
            (TYPE_ACQUISITION_ALL_PATTERN, "type_acquisition", "low",
             "typeAcquisition may pull untrusted @types packages automatically"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    TsconfigFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[TsconfigFinding], TsconfigInfo]:
        findings: list[TsconfigFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TsconfigInfo(path=rel)

        info = TsconfigInfo(path=rel, lines=len(raw_lines))
        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if info.strict is False and not any(f.kind == "strict_false" for f in findings):
            findings.append(
                TsconfigFinding(
                    kind="strict_false",
                    severity="high",
                    message="strict:false disables core type safety — enable strict mode",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[TsconfigFinding]:
        """Scan TypeScript configs and return findings."""
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
        """Scaffold a hardened TypeScript configuration template."""
        return """\
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "skipLibCheck": false,
    "allowJs": false,
    "forceConsistentCasingInFileNames": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": true
  },
  "include": ["src"]
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "TypeScript configs: none found"
        return (
            f"TypeScript configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "TypeScript config analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            strict = info.strict if info.strict is not None else "unknown"
            lines.append(
                f"  - {info.path}: strict={strict}, target={info.target or 'default'}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
