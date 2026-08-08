"""PrecommitAnalyzer — audit pre-commit config for unpinned hooks and unsafe entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PRECOMMIT_FILENAMES = (".pre-commit-config.yaml", ".pre-commit-config.yml")

UNPINNED_REV_PATTERN = re.compile(
    r"rev:\s*(main|master|develop|dev|latest|HEAD)\b",
    re.IGNORECASE,
)
LOCAL_HOOK_PATTERN = re.compile(r"^\s*-\s*id:\s*local\b", re.IGNORECASE)
REPO_HOOK_PATTERN = re.compile(r"^\s*-?\s*repo:\s*(https?://|git@)", re.IGNORECASE)
BASH_HOOK_PATTERN = re.compile(r"entry:\s*bash\b", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
SECRET_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
MISSING_REV_PATTERN = re.compile(r"^\s*repo:\s*", re.IGNORECASE)


@dataclass
class PrecommitFinding:
    """A security or best-practice issue in a pre-commit config."""

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
class PrecommitInfo:
    """Parsed metadata about a pre-commit config file."""

    path: str
    hooks: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    has_default_language_version: bool = False
    lines: int = 0


@dataclass
class PrecommitStats:
    """Aggregate pre-commit analysis statistics."""

    config_files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_precommit_config(path: Path) -> bool:
    return path.name in PRECOMMIT_FILENAMES


class PrecommitAnalyzer:
    """Audit pre-commit configuration for security risks and best practices.

    Scans for unpinned hook revisions, local hooks without rev, unsafe bash
  entries, curl-pipe-to-shell patterns, and secrets in hook args.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PrecommitFinding] | None = None
        self._stats: PrecommitStats | None = None
        self._infos: list[PrecommitInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pre-commit config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_precommit_config(path):
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
        in_repo_block = False
        has_rev_in_block = False
        repo_start = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("default_language_version:"):
                info.has_default_language_version = True

            if REPO_HOOK_PATTERN.match(line):
                in_repo_block = True
                has_rev_in_block = False
                repo_start = lineno
                repo = line.split(":", 1)[1].strip()
                info.repos.append(repo)
                continue

            if in_repo_block and line.startswith("- id:"):
                hook_id = line.split(":", 1)[1].strip()
                info.hooks.append(hook_id)
                if LOCAL_HOOK_PATTERN.match(line):
                    findings.append(
                        PrecommitFinding(
                            kind="local_hook",
                            severity="medium",
                            message="local hook — ensure entry script is reviewed and pinned",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if in_repo_block and line.startswith("rev:"):
                has_rev_in_block = True
                if UNPINNED_REV_PATTERN.search(line):
                    findings.append(
                        PrecommitFinding(
                            kind="unpinned_rev",
                            severity="high",
                            message="hook rev pinned to mutable branch — pin to a tag or commit SHA",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if BASH_HOOK_PATTERN.search(line):
                findings.append(
                    PrecommitFinding(
                        kind="bash_entry",
                        severity="medium",
                        message="bash entry hook — prefer language-specific hooks with pinned versions",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PrecommitFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="piping curl/wget to shell in hook entry is unsafe",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_PATTERN.search(line):
                findings.append(
                    PrecommitFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret in pre-commit config — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("hooks:") and in_repo_block and not has_rev_in_block and repo_start:
                findings.append(
                    PrecommitFinding(
                        kind="missing_rev",
                        severity="high",
                        message="repo block has hooks but no rev — pin hook versions",
                        path=rel,
                        lineno=repo_start,
                        line="",
                    )
                )

            if line and not line.startswith(" ") and not line.startswith("-"):
                if line.endswith(":") and line not in ("repos:", "hooks:"):
                    in_repo_block = False
                    has_rev_in_block = False

        if not info.has_default_language_version and info.hooks:
            findings.append(
                PrecommitFinding(
                    kind="missing_default_language_version",
                    severity="low",
                    message="no default_language_version — pin language versions for reproducibility",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[PrecommitFinding]:
        """Scan pre-commit configs and return findings."""
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
        """Return parsed config metadata."""
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
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.4
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

default_language_version:
  python: python3.12
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pre-commit: no config found"
        return (
            f"Pre-commit: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pre-commit config analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {len(info.hooks)} hook(s), {len(info.repos)} repo(s)"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
