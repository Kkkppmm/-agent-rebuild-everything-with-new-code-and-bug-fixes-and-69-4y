"""ActionlintAnalyzer — audit actionlint GitHub Actions lint configuration files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".actionlint.yaml",
    ".actionlint.yml",
    "actionlint.yaml",
    "actionlint.yml",
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
IGNORE_ALL_PATTERN = re.compile(
    r"^\s*-\s*(?:\*|['\"]?\*['\"]?|all)\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_SECURITY_RULE_PATTERN = re.compile(
    r"^\s*-\s*(?:self-hosted-runner|script-injection|untrusted-checkout|"
    r"pull-request-target|workflow-input|action-ref|shellcheck)\b",
    re.IGNORECASE,
)
SELF_HOSTED_ALLOW_ALL_PATTERN = re.compile(
    r"self-hosted-runner-allowed\s*:\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
PATH_IGNORE_SENSITIVE_PATTERN = re.compile(
    r"(?:^|[\s\"'])(?:\.github/workflows|workflows?|deploy(?:ment)?s?|"
    r"k8s|kubernetes|helm|charts?|manifests?|infra(?:structure)?)(?:/|[\s\"']|$)",
    re.IGNORECASE,
)
PATH_IGNORE_WILDCARD_PATTERN = re.compile(
    r"path-ignores?\s*:\s*[^\n]*\*",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CONFIG_SCHEMA_DISABLED_PATTERN = re.compile(
    r"config-schema\s*:\s*false\s*(?:#.*)?$",
    re.IGNORECASE,
)
ON_CREATED_DISABLED_PATTERN = re.compile(
    r"on-created\s*:\s*false\s*(?:#.*)?$",
    re.IGNORECASE,
)


@dataclass
class ActionlintFinding:
    """A security or best-practice issue in an actionlint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ActionlintInfo:
    """Parsed metadata about an actionlint configuration file."""

    path: str
    lines: int = 0
    ignored_rules: list[str] = field(default_factory=list)
    path_ignores: list[str] = field(default_factory=list)
    self_hosted_allowed: bool = False
    config_schema_enabled: bool = True


@dataclass
class ActionlintStats:
    """Aggregate actionlint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_actionlint_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


def _extract_list_item(line: str) -> str | None:
    match = re.match(r"^\s*-\s*(.+?)(?:\s*#.*)?$", line)
    if not match:
        return None
    return match.group(1).strip().strip("\"'")


class ActionlintAnalyzer:
    """Audit actionlint configuration for GitHub Actions lint hygiene and security risks.

    Scans `.actionlint.yaml` and related config files for blanket ignores,
    disabled security rules, unrestricted self-hosted runners, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[ActionlintFinding] | None = None
        self._stats: ActionlintStats | None = None
        self._infos: list[ActionlintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return actionlint configuration paths found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_actionlint_config(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[ActionlintFinding], ActionlintInfo]:
        findings: list[ActionlintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ActionlintInfo(path=rel)

        info = ActionlintInfo(path=rel, lines=len(raw_lines))
        in_ignore_block = False
        in_path_ignore_block = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^\s*ignore\s*:\s*$", line, re.IGNORECASE):
                in_ignore_block = True
                in_path_ignore_block = False
                continue
            if re.match(r"^\s*path-ignores?\s*:\s*$", line, re.IGNORECASE):
                in_path_ignore_block = True
                in_ignore_block = False
                continue
            if in_ignore_block and not line.startswith(" ") and not line.startswith("\t"):
                in_ignore_block = False
            if in_path_ignore_block and not line.startswith(" ") and not line.startswith("\t"):
                in_path_ignore_block = False

            if SELF_HOSTED_ALLOW_ALL_PATTERN.search(line):
                info.self_hosted_allowed = True
                findings.append(
                    ActionlintFinding(
                        kind="self_hosted_allowed",
                        severity="high",
                        message="self-hosted-runner-allowed:true permits any self-hosted runner — restrict labels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CONFIG_SCHEMA_DISABLED_PATTERN.search(line):
                info.config_schema_enabled = False
                findings.append(
                    ActionlintFinding(
                        kind="config_schema_disabled",
                        severity="medium",
                        message="config-schema:false disables workflow schema validation — keep enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ON_CREATED_DISABLED_PATTERN.search(line):
                findings.append(
                    ActionlintFinding(
                        kind="on_created_disabled",
                        severity="low",
                        message="on-created:false skips validation for newly created workflows",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_ignore_block:
                item = _extract_list_item(line)
                if item:
                    info.ignored_rules.append(item)
                if IGNORE_ALL_PATTERN.search(line):
                    findings.append(
                        ActionlintFinding(
                            kind="ignore_all",
                            severity="high",
                            message="ignore list contains wildcard — do not suppress all actionlint rules",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                if IGNORE_SECURITY_RULE_PATTERN.search(line):
                    findings.append(
                        ActionlintFinding(
                            kind="security_rule_ignored",
                            severity="high",
                            message="security-sensitive actionlint rule ignored — remove from ignore list",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_path_ignore_block:
                item = _extract_list_item(line)
                if item:
                    info.path_ignores.append(item)
                    if PATH_IGNORE_SENSITIVE_PATTERN.search(item):
                        findings.append(
                            ActionlintFinding(
                                kind="sensitive_path_ignored",
                                severity="high",
                                message="workflow or deployment path ignored — do not exclude security-sensitive paths",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )

            if PATH_IGNORE_WILDCARD_PATTERN.search(line):
                findings.append(
                    ActionlintFinding(
                        kind="path_ignore_wildcard",
                        severity="medium",
                        message="path-ignores uses wildcard — scope ignores to specific workflow files",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    ActionlintFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in actionlint config — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    ActionlintFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL in actionlint config — use HTTPS endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    ActionlintFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl|sh pattern in actionlint config — avoid piping remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if len(info.ignored_rules) >= 5:
            findings.append(
                ActionlintFinding(
                    kind="many_rules_ignored",
                    severity="medium",
                    message=f"{len(info.ignored_rules)} actionlint rules ignored — minimize suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[ActionlintFinding]:
        """Scan actionlint config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ActionlintFinding] = []
        infos: list[ActionlintInfo] = []
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
        self._stats = ActionlintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ActionlintStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ActionlintInfo]:
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
        """Scaffold a hardened actionlint configuration template."""
        return """\
# Generated by DevAI ActionlintAnalyzer
# actionlint config — https://github.com/rhysd/actionlint
# Run: actionlint

self-hosted-runner-allowed: false
config-schema: true
on-created: true

ignore: []
path-ignores: []
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "actionlint configs: none found"
        return (
            f"actionlint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "actionlint config analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: ignored={len(info.ignored_rules)}, "
                f"path_ignores={len(info.path_ignores)}, "
                f"self_hosted_allowed={info.self_hosted_allowed}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
