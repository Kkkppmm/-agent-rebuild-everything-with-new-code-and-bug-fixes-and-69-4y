"""CheckovAnalyzer — audit Checkov IaC security scanner configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CHECKOV_CONFIG_NAMES = (
    ".checkov.yml",
    ".checkov.yaml",
    "checkov.yml",
    "checkov.yaml",
)
CHECKOV_BASELINE_NAMES = (
    ".checkov.baseline",
    "checkov.baseline",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|BC_API_KEY|bridgecrew|prisma)[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INLINE_API_KEY_PATTERN = re.compile(
    r"(?:BC_API_KEY|BRIDGECREW_API_KEY|PRISMA_CLOUD_API_TOKEN|CHECKOV_API_KEY)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
SOFT_FAIL_PATTERN = re.compile(
    r"^\s*(?:soft[-_]?fail|--soft-fail)\s*[:=]?\s*(?:true|yes|1)\s*$",
    re.IGNORECASE,
)
SOFT_FAIL_CLI_PATTERN = re.compile(r"--soft-fail\b", re.IGNORECASE)
SKIP_ALL_CHECKS_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:[\"']?\*[\"']?|\*\*?|CKV_\*|all)\s*(?:#.*)?$",
    re.IGNORECASE,
)
BROAD_SKIP_CHECK_PATTERN = re.compile(
    r"^\s*(?:-\s*)?CKV_[A-Z0-9]+_\*\s*(?:#.*)?$",
    re.IGNORECASE,
)
BROAD_SKIP_PATH_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:\*\*?|/\*\*?|\*\*/\*|/\*\*/\*|/|\.)\s*(?:#.*)?$",
)
DOWNLOAD_EXTERNAL_MODULES_PATTERN = re.compile(
    r"^\s*download[-_]?external[-_]?modules\s*[:=]\s*(?:true|yes|1)\s*$",
    re.IGNORECASE,
)
EMPTY_FRAMEWORK_PATTERN = re.compile(
    r"^\s*(?:framework|frameworks)\s*:\s*(?:\[\s*\]|none|null)\s*$",
    re.IGNORECASE,
)
EMPTY_SKIP_CHECKS_PATTERN = re.compile(
    r"^\s*(?:skip[-_]?checks?|skip_check)\s*:\s*(?:\[\s*\]|none|null)\s*$",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|endpoint|registry|api|server)\s*[:=]\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SECRETS_VAR_FILE_PATTERN = re.compile(
    r"(?:var[-_]?file|secrets?[-_]?file)\s*[:=]\s*"
    r"[\"']?[^\"'\n]*(?:secret|credential|password|\.env)[^\"'\n]*[\"']?",
    re.IGNORECASE,
)
SKIP_FRAMEWORK_PATTERN = re.compile(
    r"^\s*(?:-\s*)?(?:all|\*)\s*(?:#.*)?$",
    re.IGNORECASE,
)
DISABLED_OUTPUT_PATTERN = re.compile(
    r"^\s*(?:compact|quiet|no[-_]?guide)\s*[:=]\s*(?:true|yes|1)\s*$",
    re.IGNORECASE,
)
EVALUATE_VARIABLES_PATTERN = re.compile(
    r"^\s*evaluate[-_]?variables\s*[:=]\s*(?:true|yes|1)\s*$",
    re.IGNORECASE,
)
SKIP_SUPPRESSION_PATTERN = re.compile(
    r"^\s*skip[-_]?suppression\s*[:=]\s*(?:true|yes|1)\s*$",
    re.IGNORECASE,
)
CHECKOV_CLI_SKIP_PATTERN = re.compile(
    r"--skip-(?:check|framework)\s+(?:\*\*?|\*|CKV_\*|all)(?:\s|$|#)",
    re.IGNORECASE,
)


@dataclass
class CheckovFinding:
    """A security or best-practice issue in a Checkov config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CheckovInfo:
    """Parsed metadata about a Checkov config file."""

    path: str
    skip_check_count: int = 0
    skip_path_count: int = 0
    framework_count: int = 0
    has_baseline: bool = False
    lines: int = 0


@dataclass
class CheckovStats:
    """Aggregate Checkov analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_checkov_file(path: Path) -> bool:
    lower = path.name.lower()
    return lower in CHECKOV_CONFIG_NAMES or lower in CHECKOV_BASELINE_NAMES


class CheckovAnalyzer:
    """Audit Checkov configs for hardcoded tokens, soft-fail, and weakened IaC scanning.

    Scans `.checkov.yml`, `checkov.yaml`, and `.checkov.baseline` for embedded credentials,
    wildcard skip-check patterns, fail-open soft-fail settings, and broad path exclusions.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[CheckovFinding] | None = None
        self._stats: CheckovStats | None = None
        self._infos: list[CheckovInfo] | None = None

    def files(self) -> list[Path]:
        """Return Checkov config files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_checkov_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[CheckovFinding], CheckovInfo]:
        findings: list[CheckovFinding] = []
        rel = str(path.relative_to(self.root))
        is_baseline = path.name.lower() in CHECKOV_BASELINE_NAMES

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CheckovInfo(path=rel)

        info = CheckovInfo(path=rel, lines=len(raw_lines), has_baseline=is_baseline)
        in_skip_check_block = False
        in_skip_path_block = False
        in_framework_block = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"^\s*skip[-_]?checks?\s*:", line, re.IGNORECASE):
                in_skip_check_block = True
                in_skip_path_block = False
                in_framework_block = False
            elif re.search(r"^\s*skip[-_]?paths?\s*:", line, re.IGNORECASE):
                in_skip_path_block = True
                in_skip_check_block = False
                in_framework_block = False
            elif re.search(r"^\s*frameworks?\s*:", line, re.IGNORECASE):
                in_framework_block = True
                in_skip_check_block = False
                in_skip_path_block = False
            elif re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                if in_skip_check_block:
                    in_skip_check_block = False
                if in_skip_path_block:
                    in_skip_path_block = False
                if in_framework_block:
                    in_framework_block = False

            if in_skip_check_block and re.match(r"^\s*-\s*", line):
                info.skip_check_count += 1
                if SKIP_ALL_CHECKS_PATTERN.match(stripped):
                    findings.append(
                        CheckovFinding(
                            kind="wildcard_skip_check",
                            severity="high",
                            message="wildcard skip-check disables Checkov scanning — remove blanket suppressions",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif BROAD_SKIP_CHECK_PATTERN.match(stripped):
                    findings.append(
                        CheckovFinding(
                            kind="broad_skip_check",
                            severity="medium",
                            message="wildcard skip-check pattern suppresses entire check families — scope skips narrowly",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_skip_path_block and re.match(r"^\s*-\s*", line):
                info.skip_path_count += 1
                if BROAD_SKIP_PATH_PATTERN.match(stripped):
                    findings.append(
                        CheckovFinding(
                            kind="broad_skip_path",
                            severity="high",
                            message="broad skip-path excludes entire directories from IaC scanning",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_framework_block and re.match(r"^\s*-\s*", line):
                info.framework_count += 1
                if SKIP_FRAMEWORK_PATTERN.match(stripped):
                    findings.append(
                        CheckovFinding(
                            kind="skip_framework",
                            severity="high",
                            message="wildcard framework skip disables all IaC frameworks — specify explicit frameworks",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Checkov config — use environment variables or a secrets manager",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_API_KEY_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="api_key",
                        severity="high",
                        message="hardcoded Checkov/Bridgecrew API token — use BC_API_KEY env var",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SOFT_FAIL_PATTERN.search(line) or SOFT_FAIL_CLI_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="soft_fail",
                        severity="high",
                        message="soft-fail enabled — Checkov will not fail CI on policy violations",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOWNLOAD_EXTERNAL_MODULES_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="download_external_modules",
                        severity="medium",
                        message="download-external-modules enabled — pin module versions and verify sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EMPTY_FRAMEWORK_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="empty_framework",
                        severity="high",
                        message="empty framework list disables IaC scanning — specify terraform, kubernetes, etc.",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP endpoint in Checkov config — use HTTPS for registries and APIs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SECRETS_VAR_FILE_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="secrets_var_file",
                        severity="medium",
                        message="var-file references secrets path — avoid committing secret tfvars to version control",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if EVALUATE_VARIABLES_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="evaluate_variables",
                        severity="low",
                        message="evaluate-variables enabled — ensure tfvars do not contain committed secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_SUPPRESSION_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="skip_suppression",
                        severity="medium",
                        message="skip-suppression enabled — inline suppressions will not be validated",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CHECKOV_CLI_SKIP_PATTERN.search(line):
                findings.append(
                    CheckovFinding(
                        kind="cli_wildcard_skip",
                        severity="high",
                        message="CLI wildcard skip-check/framework flag disables policy enforcement",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if is_baseline and len(raw_lines) > 500:
                findings.append(
                    CheckovFinding(
                        kind="large_baseline",
                        severity="low",
                        message="large Checkov baseline file — review suppressed findings and reduce drift regularly",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
                break

        if is_baseline and info.lines > 0 and not findings:
            findings.append(
                CheckovFinding(
                    kind="baseline_present",
                    severity="low",
                    message="Checkov baseline suppresses known findings — re-baseline after fixing issues",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        return findings, info

    def analyze(self) -> list[CheckovFinding]:
        """Scan Checkov config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CheckovFinding] = []
        infos: list[CheckovInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = CheckovStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CheckovStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CheckovInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
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
        """Scaffold a hardened Checkov config template."""
        return """\
# Checkov config — https://www.checkov.io/
# Run: checkov -d . --config-file .checkov.yml
framework:
  - terraform
  - kubernetes
  - dockerfile
soft-fail: false
download-external-modules: false
skip-check: []
skip-path:
  - .terraform/
  - node_modules/
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Checkov: none found"
        return (
            f"Checkov: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Checkov config analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: skip_checks={info.skip_check_count}, "
                f"skip_paths={info.skip_path_count}, frameworks={info.framework_count}, "
                f"baseline={info.has_baseline}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
