"""PrecommitAnalyzer — audit pre-commit config for unpinned hooks and unsafe entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PRECOMMIT_FILENAMES = (".pre-commit-config.yaml", ".pre-commit-config.yml")

UNPINNED_REV_PATTERN = re.compile(r"rev:\s*(main|master|develop|latest)\s*$", re.IGNORECASE)
MISSING_REV_PATTERN = re.compile(r"^\s*-\s*repo:\s*", re.IGNORECASE)
LOCAL_REPO_PATTERN = re.compile(r"repo:\s*local\b", re.IGNORECASE)
DANGEROUS_HOOK_PATTERN = re.compile(
    r"(curl|wget|rm\s+-rf\s+/|sudo\s+|chmod\s+777|eval\s*\()",
    re.IGNORECASE,
)


@dataclass
class PrecommitFinding:
    """A security or best-practice issue in a pre-commit configuration."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    hook: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        hook = f" ({self.hook})" if self.hook else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{hook} — {self.message}"


@dataclass
class PrecommitHookInfo:
    """Parsed metadata about a pre-commit hook entry."""

    repo: str
    hook_id: str = ""
    rev: str = ""
    is_local: bool = False


@dataclass
class PrecommitStats:
    """Aggregate pre-commit analysis statistics."""

    config_files: int
    hooks: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


class PrecommitAnalyzer:
    """Audit pre-commit configuration for supply-chain and safety risks.

    Detects unpinned hook revisions, local hooks with dangerous commands,
    and missing version pins on remote repositories.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PrecommitFinding] | None = None
        self._stats: PrecommitStats | None = None
        self._hooks: list[PrecommitHookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pre-commit config file paths."""
        found: list[Path] = []
        for name in PRECOMMIT_FILENAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PrecommitFinding], list[PrecommitHookInfo]]:
        findings: list[PrecommitFinding] = []
        hooks: list[PrecommitHookInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, hooks

        current_repo = ""
        current_hook = ""
        current_rev = ""
        in_repo_block = False
        has_rev = False
        repo_start_line = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("- repo:"):
                if in_repo_block and not has_rev and current_repo and not LOCAL_REPO_PATTERN.search(
                    current_repo
                ):
                    findings.append(
                        PrecommitFinding(
                            kind="missing_rev",
                            severity="medium",
                            message="hook repo block missing rev — pin to a specific tag or SHA",
                            path=rel,
                            lineno=repo_start_line,
                            hook=current_hook,
                        )
                    )
                in_repo_block = True
                has_rev = False
                repo_start_line = lineno
                current_repo = stripped
                current_hook = ""
                current_rev = ""
                if LOCAL_REPO_PATTERN.search(stripped):
                    findings.append(
                        PrecommitFinding(
                            kind="local_repo",
                            severity="low",
                            message="local hook repo — review commands carefully",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if in_repo_block and stripped.startswith("repo:"):
                current_repo = stripped

            if stripped.startswith("rev:"):
                has_rev = True
                current_rev = stripped.split(":", 1)[1].strip()
                if UNPINNED_REV_PATTERN.search(stripped):
                    findings.append(
                        PrecommitFinding(
                            kind="unpinned_rev",
                            severity="medium",
                            message="hook rev points to a moving branch — pin a tag or commit SHA",
                            path=rel,
                            lineno=lineno,
                            hook=current_hook,
                            line=raw.strip(),
                        )
                    )

            if stripped.startswith("- id:"):
                current_hook = stripped.split(":", 1)[1].strip()
                info = PrecommitHookInfo(
                    repo=current_repo,
                    hook_id=current_hook,
                    rev=current_rev,
                    is_local=bool(LOCAL_REPO_PATTERN.search(current_repo)),
                )
                hooks.append(info)

            if stripped.startswith("entry:") and DANGEROUS_HOOK_PATTERN.search(stripped):
                findings.append(
                    PrecommitFinding(
                        kind="dangerous_entry",
                        severity="high",
                        message="hook entry contains a potentially dangerous shell command",
                        path=rel,
                        lineno=lineno,
                        hook=current_hook,
                        line=raw.strip(),
                    )
                )

            if stripped.startswith("- repo:") is False and stripped.startswith("- ") and not stripped.startswith(
                "- id:"
            ):
                if in_repo_block and not stripped.startswith(" ") and stripped.endswith(":"):
                    in_repo_block = False

        if in_repo_block and not has_rev and current_repo and not LOCAL_REPO_PATTERN.search(current_repo):
            findings.append(
                PrecommitFinding(
                    kind="missing_rev",
                    severity="medium",
                    message="hook repo block missing rev — pin to a specific tag or SHA",
                    path=rel,
                    lineno=repo_start_line,
                    hook=current_hook,
                )
            )

        return findings, hooks

    def analyze(self) -> list[PrecommitFinding]:
        """Scan pre-commit config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PrecommitFinding] = []
        hooks: list[PrecommitHookInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, file_hooks = self._analyze_file(path)
            findings.extend(file_findings)
            hooks.extend(file_hooks)

        self._findings = findings
        self._hooks = hooks
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = PrecommitStats(
            config_files=len(paths),
            hooks=len(hooks),
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
    def hooks(self) -> list[PrecommitHookInfo]:
        """Return parsed hook metadata."""
        if self._hooks is None:
            self.analyze()
        return self._hooks  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config)."""
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
        """Scaffold a hardened pre-commit configuration template."""
        return """\
# Generated by DevAI PrecommitAnalyzer
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
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
            return "Pre-commit config: none found"
        return (
            f"Pre-commit: {stats.config_files} config(s), "
            f"{stats.hooks} hook(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pre-commit analysis:",
            f"  config files: {stats.config_files}",
            f"  hooks: {stats.hooks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for hook in self.hooks[:20]:
            local = " (local)" if hook.is_local else ""
            lines.append(f"  - {hook.hook_id or 'hook'} @ {hook.rev or 'unpinned'}{local}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
