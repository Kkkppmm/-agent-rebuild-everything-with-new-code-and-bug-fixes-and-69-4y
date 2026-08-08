"""PrecommitAnalyzer — audit pre-commit config for unpinned hooks and unsafe entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PRECOMMIT_NAMES = (
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "pre-commit-config.yaml",
    "pre-commit-config.yml",
)

UNPINNED_REV_PATTERN = re.compile(
    r"^\s*rev:\s*(main|master|dev|nightly|latest|HEAD)\s*$",
    re.IGNORECASE,
)
MUTABLE_TAG_PATTERN = re.compile(
    r"^\s*rev:\s*v\d+\s*$",
    re.IGNORECASE,
)
MISSING_REV_PATTERN = re.compile(r"^\s*rev:\s*$", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
UNSAFE_LOCAL_HOOK_PATTERN = re.compile(
    r"(rm\s+-rf\s+/|eval\s*\(|exec\s*\(|os\.system|subprocess\.call)",
    re.IGNORECASE,
)
HTTP_REPO_PATTERN = re.compile(
    r"^\s*-\s*repo:\s*http://",
    re.IGNORECASE,
)
SSH_REPO_PATTERN = re.compile(
    r"^\s*-\s*repo:\s*git@",
    re.IGNORECASE,
)
LOCAL_REPO_PATTERN = re.compile(
    r"^\s*-\s*repo:\s*local\s*$",
    re.IGNORECASE,
)
ENTRY_PATTERN = re.compile(r"^\s*-\s*id:\s*(\S+)")
REPO_PATTERN = re.compile(r"^\s*-\s*repo:\s*(.+)")
REV_PATTERN = re.compile(r"^\s*rev:\s*(.+)")
ENTRY_HOOK_PATTERN = re.compile(r"^\s*entry:\s*(.+)")
ARGS_PATTERN = re.compile(r"^\s*args:\s*(.+)")
LANGUAGE_VERSION_PATTERN = re.compile(r"^\s*language_version:\s*(system|default)\s*$", re.IGNORECASE)


@dataclass
class PrecommitFinding:
    """A security or best-practice issue in a pre-commit config."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    repo: str = ""
    hook_id: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        parts = []
        if self.repo:
            parts.append(self.repo)
        if self.hook_id:
            parts.append(self.hook_id)
        ctx = f" ({', '.join(parts)})" if parts else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{ctx} — {self.message}"


@dataclass
class PrecommitInfo:
    """Parsed metadata about a pre-commit config file."""

    path: str
    repos: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)
    has_local_repo: bool = False
    lines: int = 0


@dataclass
class PrecommitStats:
    """Aggregate pre-commit analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_precommit_file(path: Path) -> bool:
    name = path.name.lower()
    return name in PRECOMMIT_NAMES


class PrecommitAnalyzer:
    """Audit pre-commit config files for unpinned hooks and unsafe entries.

    Scans for unpinned ``rev`` values, mutable tags, secrets in hook args,
    curl-pipe-to-shell in local hooks, HTTP (non-HTTPS) repo URLs, and
    other common pre-commit misconfigurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PrecommitFinding] | None = None
        self._stats: PrecommitStats | None = None
        self._infos: list[PrecommitInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pre-commit config file paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_precommit_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PrecommitFinding], PrecommitInfo]:
        findings: list[PrecommitFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, PrecommitInfo(path=rel)

        info = PrecommitInfo(path=rel, lines=len(raw_lines))
        current_repo = ""
        current_hook = ""
        in_hooks_block = False
        hooks_indent = 0
        has_minimum_version = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("minimum_pre_commit_version:"):
                has_minimum_version = True
                continue

            repo_match = REPO_PATTERN.match(line)
            if repo_match:
                current_repo = repo_match.group(1).strip().strip("'\"")
                info.repos.append(current_repo)
                in_hooks_block = False
                if current_repo == "local":
                    info.has_local_repo = True
                if HTTP_REPO_PATTERN.match(line):
                    findings.append(
                        PrecommitFinding(
                            kind="http_repo",
                            severity="medium",
                            message="repo uses HTTP — prefer HTTPS for hook sources",
                            path=rel,
                            lineno=lineno,
                            repo=current_repo,
                            line=raw.strip(),
                        )
                    )
                if LOCAL_REPO_PATTERN.match(line):
                    findings.append(
                        PrecommitFinding(
                            kind="local_repo",
                            severity="low",
                            message="local repo hooks — review entry scripts carefully",
                            path=rel,
                            lineno=lineno,
                            repo="local",
                            line=raw.strip(),
                        )
                    )
                continue

            if REV_PATTERN.match(line):
                rev_value = REV_PATTERN.match(line).group(1).strip().strip("'\"")  # type: ignore[union-attr]
                if UNPINNED_REV_PATTERN.match(line):
                    findings.append(
                        PrecommitFinding(
                            kind="unpinned_rev",
                            severity="high",
                            message=f"rev: {rev_value} is unpinned — pin to a specific tag or SHA",
                            path=rel,
                            lineno=lineno,
                            repo=current_repo,
                            line=raw.strip(),
                        )
                    )
                elif MUTABLE_TAG_PATTERN.match(line):
                    findings.append(
                        PrecommitFinding(
                            kind="mutable_tag",
                            severity="medium",
                            message=f"rev: {rev_value} is a mutable tag — pin to full version (e.g. v4.5.0)",
                            path=rel,
                            lineno=lineno,
                            repo=current_repo,
                            line=raw.strip(),
                        )
                    )
                elif MISSING_REV_PATTERN.match(line) or not rev_value:
                    findings.append(
                        PrecommitFinding(
                            kind="missing_rev",
                            severity="high",
                            message="empty rev — pin hooks to a specific tag or SHA",
                            path=rel,
                            lineno=lineno,
                            repo=current_repo,
                            line=raw.strip(),
                        )
                    )
                continue

            if line == "hooks:" or line.startswith("hooks:"):
                in_hooks_block = True
                hooks_indent = len(raw) - len(raw.lstrip())
                continue

            entry_match = ENTRY_PATTERN.match(line)
            if entry_match:
                current_hook = entry_match.group(1)
                info.hooks.append(current_hook)
                continue

            if in_hooks_block:
                child_indent = len(raw) - len(raw.lstrip())
                if child_indent <= hooks_indent and line.endswith(":") and not line.startswith("-"):
                    in_hooks_block = False

            entry_hook_match = ENTRY_HOOK_PATTERN.match(line)
            if entry_hook_match:
                entry_value = entry_hook_match.group(1).strip().strip("'\"")
                if CURL_PIPE_SHELL_PATTERN.search(entry_value):
                    findings.append(
                        PrecommitFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="local hook entry uses curl/wget piped to shell",
                            path=rel,
                            lineno=lineno,
                            repo=current_repo,
                            hook_id=current_hook,
                            line=raw.strip(),
                        )
                    )
                if UNSAFE_LOCAL_HOOK_PATTERN.search(entry_value):
                    findings.append(
                        PrecommitFinding(
                            kind="unsafe_local_hook",
                            severity="high",
                            message="local hook entry contains potentially dangerous command",
                            path=rel,
                            lineno=lineno,
                            repo=current_repo,
                            hook_id=current_hook,
                            line=raw.strip(),
                        )
                    )
                continue

            args_match = ARGS_PATTERN.match(line)
            if args_match and SECRET_PATTERN.search(args_match.group(1)):
                findings.append(
                    PrecommitFinding(
                        kind="secret_in_args",
                        severity="high",
                        message="potential secret in hook args — use environment variables",
                        path=rel,
                        lineno=lineno,
                        repo=current_repo,
                        hook_id=current_hook,
                        line=raw.strip(),
                    )
                )

            if SECRET_PATTERN.search(line) and ("env:" in line or "additional_dependencies:" in line):
                findings.append(
                    PrecommitFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret in hook configuration",
                        path=rel,
                        lineno=lineno,
                        repo=current_repo,
                        hook_id=current_hook,
                        line=raw.strip(),
                    )
                )

            if LANGUAGE_VERSION_PATTERN.match(line):
                findings.append(
                    PrecommitFinding(
                        kind="language_version_system",
                        severity="low",
                        message="language_version: system — pin a specific version for reproducibility",
                        path=rel,
                        lineno=lineno,
                        repo=current_repo,
                        hook_id=current_hook,
                        line=raw.strip(),
                    )
                )

        if not has_minimum_version and info.repos:
            findings.append(
                PrecommitFinding(
                    kind="no_minimum_version",
                    severity="low",
                    message="missing minimum_pre_commit_version — add for reproducible installs",
                    path=rel,
                    lineno=1,
                )
            )

        return findings, info

    def analyze(self) -> list[PrecommitFinding]:
        """Scan pre-commit config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PrecommitFinding] = []
        infos: list[PrecommitInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = PrecommitStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PrecommitStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PrecommitInfo]:
        """Return parsed pre-commit config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config files)."""
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
        """Scaffold a hardened pre-commit config template."""
        return """\
# Generated by DevAI PrecommitAnalyzer
minimum_pre_commit_version: "3.6.0"

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ["--maxkb=500"]
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pre-commit configs: none found"
        lines = [
            (
                f"Pre-commit configs: {stats.config_files} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        lines = [
            "# Pre-commit Config Audit",
            "",
            self.summary(),
            "",
        ]
        if self.infos:
            lines.append("## Files")
            for info in self.infos:
                hooks = ", ".join(info.hooks[:10]) if info.hooks else "none"
                if len(info.hooks) > 10:
                    hooks += f", ... (+{len(info.hooks) - 10} more)"
                lines.append(
                    f"- {info.path}: {len(info.repos)} repo(s), {len(info.hooks)} hook(s) [{hooks}]"
                )
            lines.append("")
        findings = self._findings or []
        if findings:
            lines.append("## Findings")
            for finding in findings[:50]:
                lines.append(f"- {finding.format()}")
            if len(findings) > 50:
                lines.append(f"- ... and {len(findings) - 50} more")
        return "\n".join(lines)
