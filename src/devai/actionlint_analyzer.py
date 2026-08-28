"""ActionlintAnalyzer — audit actionlint configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
PATHS_SECTION_PATTERN = re.compile(r"^\s*paths\s*:\s*$", re.IGNORECASE)
IGNORE_SECTION_PATTERN = re.compile(r"^\s*ignore\s*:\s*$", re.IGNORECASE)
IGNORE_ENTRY_PATTERN = re.compile(r"^\s*-\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
PATH_GLOB_PATTERN = re.compile(
    r"^\s*['\"]?([^'\":\s]+)['\"]?\s*:\s*$",
    re.IGNORECASE,
)
CONFIG_VARIABLES_SECTION_PATTERN = re.compile(r"^\s*config-variables\s*:\s*$", re.IGNORECASE)
WORKFLOW_GLOB_PATTERN = re.compile(
    r"\.github/workflows/",
    re.IGNORECASE,
)
SELF_HOSTED_SECTION_PATTERN = re.compile(r"^\s*self-hosted-runner\s*:\s*$", re.IGNORECASE)
LABELS_SECTION_PATTERN = re.compile(r"^\s*labels\s*:\s*$", re.IGNORECASE)
LABEL_ENTRY_PATTERN = re.compile(r"^\s*-\s*['\"]?([^\"'\s#]+)['\"]?", re.IGNORECASE)
WILDCARD_LABEL_PATTERN = re.compile(r"^\s*-\s*['\"]?\*['\"]?\s*(?:#.*)?$")
EMPTY_LABELS_PATTERN = re.compile(r"^\s*labels\s*:\s*\[\s*\]\s*(?:#.*)?$", re.IGNORECASE)

# Security-sensitive actionlint ignore patterns grouped by concern.
SHELLCHECK_SECURITY_PATTERNS = (
    re.compile(r"SC2086", re.IGNORECASE),
    re.compile(r"SC2166", re.IGNORECASE),
    re.compile(r"SC2046", re.IGNORECASE),
    re.compile(r"SC2154", re.IGNORECASE),
)
RUNNER_IGNORE_PATTERNS = (
    re.compile(r"runner.*unknown", re.IGNORECASE),
    re.compile(r"runner of", re.IGNORECASE),
    re.compile(r"self-hosted", re.IGNORECASE),
)
ACTION_PIN_IGNORE_PATTERNS = (
    re.compile(r"action.*version", re.IGNORECASE),
    re.compile(r"could not resolve", re.IGNORECASE),
    re.compile(r"tag.*not found", re.IGNORECASE),
)
PERMISSION_IGNORE_PATTERNS = (
    re.compile(r"permission", re.IGNORECASE),
    re.compile(r"write-all", re.IGNORECASE),
    re.compile(r"pull_request_target", re.IGNORECASE),
)
BROAD_IGNORE_PATTERN = re.compile(r"\.[\*\+]|^\.\+$|^\.\*$", re.IGNORECASE)


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
    self_hosted_labels: list[str] = field(default_factory=list)
    config_variables: list[str] = field(default_factory=list)
    path_globs: list[str] = field(default_factory=list)
    ignore_patterns: list[str] = field(default_factory=list)


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


class ActionlintAnalyzer:
    """Audit actionlint configuration for GitHub Actions lint hygiene and security risks.

    Scans `.github/actionlint.yaml` and `.github/actionlint.yml` for broad workflow
    error suppressions, shellcheck security ignores, missing self-hosted runner labels,
    and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[ActionlintFinding] | None = None
        self._stats: ActionlintStats | None = None
        self._infos: list[ActionlintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return actionlint configuration paths found in the project."""
        paths: list[Path] = []
        github_dir = self.root / ".github"
        if github_dir.is_dir():
            for name in CONFIG_NAMES:
                candidate = github_dir / name
                if candidate.is_file():
                    paths.append(candidate)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_actionlint_config(path) and path not in paths:
                paths.append(path)
        return sorted(paths)

    def _record_ignore_pattern(
        self,
        pattern: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[ActionlintFinding],
        info: ActionlintInfo,
    ) -> None:
        info.ignore_patterns.append(pattern)

        if any(p.search(pattern) for p in SHELLCHECK_SECURITY_PATTERNS):
            findings.append(
                ActionlintFinding(
                    kind="ignore_shellcheck_security",
                    severity="high",
                    message="ignore suppresses shellcheck security rule — fix unquoted variables and unsafe shell",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif any(p.search(pattern) for p in RUNNER_IGNORE_PATTERNS):
            findings.append(
                ActionlintFinding(
                    kind="ignore_runner_check",
                    severity="medium",
                    message="ignore suppresses runner label checks — register self-hosted labels explicitly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif any(p.search(pattern) for p in ACTION_PIN_IGNORE_PATTERNS):
            findings.append(
                ActionlintFinding(
                    kind="ignore_action_pin",
                    severity="high",
                    message="ignore suppresses action version checks — pin actions to commit SHAs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif any(p.search(pattern) for p in PERMISSION_IGNORE_PATTERNS):
            findings.append(
                ActionlintFinding(
                    kind="ignore_permission_check",
                    severity="high",
                    message="ignore suppresses permission/workflow security checks — review CI permissions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif BROAD_IGNORE_PATTERN.search(pattern):
            findings.append(
                ActionlintFinding(
                    kind="ignore_broad_regex",
                    severity="medium",
                    message="broad ignore regex may hide actionlint errors — scope suppressions narrowly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ActionlintFinding],
        info: ActionlintInfo,
        *,
        in_paths: bool,
        in_ignore: bool,
        current_glob: str,
        in_self_hosted: bool,
        in_labels: bool,
        in_config_variables: bool,
    ) -> tuple[bool, bool, str, bool, bool, bool]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return in_paths, in_ignore, current_glob, in_self_hosted, in_labels, in_config_variables

        if SELF_HOSTED_SECTION_PATTERN.search(line):
            return in_paths, in_ignore, current_glob, True, False, False

        if CONFIG_VARIABLES_SECTION_PATTERN.search(line):
            return in_paths, in_ignore, current_glob, False, False, True

        if LABELS_SECTION_PATTERN.search(line) and in_self_hosted:
            return in_paths, in_ignore, current_glob, in_self_hosted, True, False

        if EMPTY_LABELS_PATTERN.search(line):
            findings.append(
                ActionlintFinding(
                    kind="empty_self_hosted_labels",
                    severity="low",
                    message="self-hosted-runner labels empty — add custom runner labels to avoid false positives",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if in_labels and LABEL_ENTRY_PATTERN.match(line):
            match = LABEL_ENTRY_PATTERN.match(line)
            if match:
                label = match.group(1)
                info.self_hosted_labels.append(label)
                if label == "*":
                    findings.append(
                        ActionlintFinding(
                            kind="wildcard_runner_label",
                            severity="medium",
                            message="wildcard runner label '*' accepts any label — enumerate known labels",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
            if WILDCARD_LABEL_PATTERN.search(line):
                findings.append(
                    ActionlintFinding(
                        kind="wildcard_runner_label",
                        severity="medium",
                        message="wildcard runner label accepts any label — enumerate known labels",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if PATHS_SECTION_PATTERN.search(line):
            return True, False, current_glob, in_self_hosted, in_labels, False

        if in_paths and PATH_GLOB_PATTERN.search(line):
            glob_match = PATH_GLOB_PATTERN.match(line)
            if glob_match:
                current_glob = glob_match.group(1)
                info.path_globs.append(current_glob)
                if WORKFLOW_GLOB_PATTERN.search(current_glob) and "**" in current_glob:
                    findings.append(
                        ActionlintFinding(
                            kind="ignore_broad_workflow",
                            severity="medium",
                            message="path glob matches all workflow files — avoid blanket error suppression",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        if in_paths and IGNORE_SECTION_PATTERN.search(line):
            return in_paths, True, current_glob, in_self_hosted, in_labels, in_config_variables

        if in_ignore:
            ignore_match = IGNORE_ENTRY_PATTERN.match(line)
            if ignore_match:
                self._record_ignore_pattern(
                    ignore_match.group(1),
                    lineno,
                    rel,
                    line,
                    findings,
                    info,
                )
            elif not line.startswith(" ") and not line.startswith("\t"):
                in_ignore = False

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ActionlintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in actionlint config — use GitHub secrets",
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
                    message="curl|wget piped to shell in actionlint config — avoid remote code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        config_var_match = re.match(r"^\s*-\s*['\"]?([A-Za-z_][\w-]*)['\"]?", line)
        if config_var_match and in_config_variables:
            var = config_var_match.group(1)
            if var not in info.config_variables:
                info.config_variables.append(var)

        if line and not line.startswith(" ") and not line.startswith("\t"):
            if not PATHS_SECTION_PATTERN.search(line) and not SELF_HOSTED_SECTION_PATTERN.search(line):
                in_config_variables = False
                if not LABELS_SECTION_PATTERN.search(line):
                    in_self_hosted = False
                    in_labels = False

        return in_paths, in_ignore, current_glob, in_self_hosted, in_labels, in_config_variables

    def _analyze_file(self, path: Path) -> tuple[list[ActionlintFinding], ActionlintInfo]:
        findings: list[ActionlintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, ActionlintInfo(path=rel)

        info = ActionlintInfo(path=rel, lines=len(raw_lines))
        in_paths = False
        in_ignore = False
        current_glob = ""
        in_self_hosted = False
        in_labels = False
        in_config_variables = False

        for lineno, line in enumerate(raw_lines, start=1):
            in_paths, in_ignore, current_glob, in_self_hosted, in_labels, in_config_variables = (
                self._scan_line(
                    line,
                    lineno,
                    rel,
                    findings,
                    info,
                    in_paths=in_paths,
                    in_ignore=in_ignore,
                    current_glob=current_glob,
                    in_self_hosted=in_self_hosted,
                    in_labels=in_labels,
                    in_config_variables=in_config_variables,
                )
            )

        return findings, info

    def analyze(self) -> list[ActionlintFinding]:
        """Scan actionlint configs and return findings."""
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ActionlintInfo]:
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
        """Scaffold a hardened actionlint configuration template."""
        return """\
# Generated by DevAI ActionlintAnalyzer
# actionlint — https://github.com/rhysd/actionlint
self-hosted-runner:
  labels:
    - self-hosted
    - linux
    - x64

config-variables: []

paths: {}
"""

    def summary(self) -> str:
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
        self.analyze()
        stats = self.stats
        lines = [
            "actionlint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            labels = len(info.self_hosted_labels)
            ignores = len(info.ignore_patterns)
            lines.append(
                f"  - {info.path}: labels={labels}, path_globs={len(info.path_globs)}, ignores={ignores}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
