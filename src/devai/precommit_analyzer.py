"""PrecommitAnalyzer — audit pre-commit config for hook security and hygiene."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PRE_COMMIT_NAMES = (
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
)

FLOATING_REV_PATTERN = re.compile(r"rev:\s*(main|master|latest|HEAD)\s*$", re.IGNORECASE)
HTTP_REPO_PATTERN = re.compile(r"repo:\s*http://", re.IGNORECASE)
LOCAL_HOOK_PATTERN = re.compile(r"repo:\s*local\b", re.IGNORECASE)


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
class PrecommitHookInfo:
    """Parsed metadata about a pre-commit hook repo."""

    repo: str
    rev: str | None = None
    hooks: list[str] = field(default_factory=list)


@dataclass
class PrecommitStats:
    """Aggregate pre-commit analysis statistics."""

    config_files: int
    hook_repos: int
    hooks: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _strip_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


class PrecommitAnalyzer:
    """Audit pre-commit configuration for unpinned hooks and unsafe entries.

    Scans for floating revs (main/master), insecure HTTP repo URLs, and
    local hooks without language validation.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PrecommitFinding] | None = None
        self._stats: PrecommitStats | None = None
        self._hooks: list[PrecommitHookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pre-commit config paths found in the project."""
        found: list[Path] = []
        for name in PRE_COMMIT_NAMES:
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

        current: PrecommitHookInfo | None = None
        has_default_stages = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = _strip_comment(raw)
            if not line:
                continue

            stripped = line.strip()
            lower = stripped.lower()

            if lower.startswith("default_stages:"):
                has_default_stages = True

            if "repo:" in lower:
                repo_part = stripped
                if repo_part.startswith("- "):
                    repo_part = repo_part[2:].strip()
                if repo_part.lower().startswith("repo:"):
                    repo = repo_part.split(":", 1)[1].strip().strip("'\"")
                    current = PrecommitHookInfo(repo=repo)
                    hooks.append(current)

                    if HTTP_REPO_PATTERN.search(repo_part):
                        findings.append(
                            PrecommitFinding(
                                kind="insecure_repo_url",
                                severity="medium",
                                message="pre-commit repo uses HTTP instead of HTTPS",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

                    if LOCAL_HOOK_PATTERN.search(repo_part):
                        findings.append(
                            PrecommitFinding(
                                kind="local_hook",
                                severity="low",
                                message="local hook repo — ensure entry points are reviewed",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if current and "rev:" in lower:
                rev_part = stripped
                if rev_part.startswith("- "):
                    rev_part = rev_part[2:].strip()
                if rev_part.lower().startswith("rev:"):
                    rev = rev_part.split(":", 1)[1].strip().strip("'\"")
                    current.rev = rev
                    if FLOATING_REV_PATTERN.search(rev_part):
                        findings.append(
                            PrecommitFinding(
                                kind="floating_rev",
                                severity="high",
                                message=f"hook rev '{rev}' is not pinned to a tag or commit",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

            if current and "- id:" in lower:
                hook_id = stripped.split("id:", 1)[1].strip().strip("'\"")
                current.hooks.append(hook_id)

            if lower.startswith("language_version:") and "system" in lower:
                findings.append(
                    PrecommitFinding(
                        kind="system_python",
                        severity="low",
                        message="language_version: system may cause inconsistent hook behavior",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if hooks and not has_default_stages:
            findings.append(
                PrecommitFinding(
                    kind="no_default_stages",
                    severity="low",
                    message="no default_stages defined — hooks run on all stages by default",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, hooks

    def analyze(self) -> list[PrecommitFinding]:
        """Scan pre-commit configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PrecommitFinding] = []
        all_hooks: list[PrecommitHookInfo] = []
        paths = self.config_files()
        total_hooks = 0

        for path in paths:
            file_findings, hooks = self._analyze_file(path)
            findings.extend(file_findings)
            all_hooks.extend(hooks)
            total_hooks += sum(len(h.hooks) for h in hooks)

        self._findings = findings
        self._hooks = all_hooks
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = PrecommitStats(
            config_files=len(paths),
            hook_repos=len(all_hooks),
            hooks=total_hooks,
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
    def hook_repos(self) -> list[PrecommitHookInfo]:
        """Return parsed hook repo metadata."""
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

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Pre-commit config: none found"
        return (
            f"Pre-commit: {stats.config_files} config(s), "
            f"{stats.hook_repos} repo(s), {stats.hooks} hook(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pre-commit config analysis:",
            f"  config files: {stats.config_files}",
            f"  hook repos: {stats.hook_repos}",
            f"  hooks: {stats.hooks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
