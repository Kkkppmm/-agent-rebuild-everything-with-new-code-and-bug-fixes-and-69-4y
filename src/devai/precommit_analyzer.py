"""PrecommitAnalyzer — audit pre-commit config files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    ".pre-commit-hooks.yaml",
    ".pre-commit-hooks.yml",
)

UNPINNED_REV_PATTERN = re.compile(
    r"^\s*rev:\s*(main|master|HEAD|develop|dev|nightly|latest)\s*$",
    re.IGNORECASE,
)
MUTABLE_TAG_REV_PATTERN = re.compile(
    r"^\s*rev:\s*v\d+\s*$",
    re.IGNORECASE,
)
LOCAL_REPO_PATTERN = re.compile(r"^\s*repo:\s*local\s*$", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(curl|wget)\s+[^\n|]*\|\s*(sh|bash|zsh)\b",
    re.IGNORECASE,
)
DANGEROUS_ENTRY_PATTERN = re.compile(
    r"^\s*entry:\s*.*\b(curl|wget|eval|exec)\b",
    re.IGNORECASE,
)
SECRET_IN_CONFIG_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
UNPINNED_ADDITIONAL_DEP_PATTERN = re.compile(
    r"^\s*-\s*['\"]?[a-zA-Z0-9][a-zA-Z0-9._-]*(?![=<>!~])",
)


@dataclass
class PrecommitFinding:
    """A security or best-practice issue in a pre-commit config file."""

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
    """Parsed metadata about a pre-commit hook repository block."""

    repo: str
    rev: str | None = None
    hooks: list[str] = field(default_factory=list)
    is_local: bool = False


@dataclass
class PrecommitInfo:
    """Parsed metadata about a pre-commit config file."""

    path: str
    repos: list[PrecommitHookInfo] = field(default_factory=list)
    has_default_language_version: bool = False
    lines: int = 0


@dataclass
class PrecommitStats:
    """Aggregate pre-commit config analysis statistics."""

    config_files: int
    findings: int
    repos: int = 0
    hooks: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class PrecommitAnalyzer:
    """Audit pre-commit configuration files for security risks and best practices.

    Scans for unpinned hook revisions, local repo hooks with dangerous commands,
    secrets in config, curl-pipe-to-shell entry points, and missing
    ``default_language_version`` for Python projects.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PrecommitFinding] | None = None
        self._stats: PrecommitStats | None = None
        self._infos: list[PrecommitInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return pre-commit config file paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".pre-commit-config.*")):
            if path.is_file() and path not in found:
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
        current_repo: PrecommitHookInfo | None = None
        in_additional_deps = False
        additional_deps_indent = 0
        pending_repo = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("default_language_version:"):
                info.has_default_language_version = True

            if line == "repos:":
                pending_repo = True
                continue

            if pending_repo and line.startswith("- repo:"):
                pending_repo = False
                repo_value = line.split(":", 1)[1].strip()
                current_repo = PrecommitHookInfo(repo=repo_value, is_local=repo_value.lower() == "local")
                info.repos.append(current_repo)
                if current_repo.is_local:
                    findings.append(
                        PrecommitFinding(
                            kind="local_repo",
                            severity="medium",
                            message="local repo hook — review entry scripts for unsafe commands",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if LOCAL_REPO_PATTERN.match(line):
                current_repo = PrecommitHookInfo(repo="local", is_local=True)
                info.repos.append(current_repo)
                findings.append(
                    PrecommitFinding(
                        kind="local_repo",
                        severity="medium",
                        message="local repo hook — review entry scripts for unsafe commands",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
                continue

            if line.startswith("repo:") and not line.startswith("- repo:"):
                repo_value = line.split(":", 1)[1].strip()
                current_repo = PrecommitHookInfo(repo=repo_value, is_local=repo_value.lower() == "local")
                info.repos.append(current_repo)
                if current_repo.is_local:
                    findings.append(
                        PrecommitFinding(
                            kind="local_repo",
                            severity="medium",
                            message="local repo hook — review entry scripts for unsafe commands",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if UNPINNED_REV_PATTERN.match(line):
                findings.append(
                    PrecommitFinding(
                        kind="unpinned_rev",
                        severity="high",
                        message="hook revision pinned to mutable branch — pin to a tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
                if current_repo is not None:
                    current_repo.rev = line.split(":", 1)[1].strip()
                continue

            if MUTABLE_TAG_REV_PATTERN.match(line):
                findings.append(
                    PrecommitFinding(
                        kind="mutable_tag_rev",
                        severity="medium",
                        message="hook uses floating major tag (v1) — pin to full version or SHA",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
                if current_repo is not None:
                    current_repo.rev = line.split(":", 1)[1].strip()
                continue

            if line.startswith("rev:"):
                if current_repo is not None:
                    current_repo.rev = line.split(":", 1)[1].strip()
                if current_repo and not current_repo.is_local and current_repo.rev in ("", "null"):
                    findings.append(
                        PrecommitFinding(
                            kind="missing_rev",
                            severity="high",
                            message="remote repo hook missing revision pin",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if line.startswith("id:") or re.match(r"^-\s+id:", line):
                hook_id = line.split("id:", 1)[1].strip()
                if current_repo is not None:
                    current_repo.hooks.append(hook_id)
                continue

            if line.startswith("entry:"):
                if CURL_PIPE_SHELL_PATTERN.search(line):
                    findings.append(
                        PrecommitFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message="hook entry pipes curl/wget to shell — supply-chain risk",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                if DANGEROUS_ENTRY_PATTERN.search(line):
                    findings.append(
                        PrecommitFinding(
                            kind="dangerous_entry",
                            severity="high",
                            message="hook entry uses eval/exec or remote download — review carefully",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                continue

            if SECRET_IN_CONFIG_PATTERN.search(line):
                findings.append(
                    PrecommitFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret hardcoded in pre-commit config — use env vars",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("additional_dependencies:"):
                in_additional_deps = True
                additional_deps_indent = len(raw) - len(raw.lstrip())
                inline = line.split(":", 1)[1].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    for item in inline[1:-1].split(","):
                        dep = item.strip().strip("'\"")
                        if dep and "==" not in dep and ">=" not in dep and "<=" not in dep:
                            findings.append(
                                PrecommitFinding(
                                    kind="unpinned_additional_dep",
                                    severity="low",
                                    message=f"additional_dependencies entry '{dep}' is unpinned",
                                    path=rel,
                                    lineno=lineno,
                                    line=raw.strip(),
                                )
                            )
                    in_additional_deps = False
                continue

            if in_additional_deps:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= additional_deps_indent and not line.startswith("-"):
                    in_additional_deps = False
                elif line.startswith("-") and UNPINNED_ADDITIONAL_DEP_PATTERN.match(line):
                    dep = line.lstrip("- ").strip().strip("'\"")
                    if dep and "==" not in dep and ">=" not in dep and "<=" not in dep:
                        findings.append(
                            PrecommitFinding(
                                kind="unpinned_additional_dep",
                                severity="low",
                                message=f"additional_dependencies entry '{dep}' is unpinned",
                                path=rel,
                                lineno=lineno,
                                line=raw.strip(),
                            )
                        )

        for repo_info in info.repos:
            if not repo_info.is_local and repo_info.rev is None and repo_info.hooks:
                findings.append(
                    PrecommitFinding(
                        kind="missing_rev",
                        severity="high",
                        message=f"remote repo '{repo_info.repo}' has hooks but no rev pin",
                        path=rel,
                        lineno=0,
                        line="",
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

        total_repos = sum(len(i.repos) for i in infos)
        total_hooks = sum(len(h.hooks) for i in infos for h in i.repos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = PrecommitStats(
            config_files=len(paths),
            findings=len(findings),
            repos=total_repos,
            hooks=total_hooks,
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
        """Scaffold a hardened pre-commit configuration template."""
        return """\
# Generated by DevAI PrecommitAnalyzer
default_language_version:
  python: python3.12

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        args: ["--maxkb=500"]
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.9.6
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
            return "Pre-commit: no config files found"
        return (
            f"Pre-commit: {stats.config_files} config(s), {stats.repos} repo(s), "
            f"{stats.hooks} hook(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pre-commit configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  repos: {stats.repos}",
            f"  hooks: {stats.hooks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(f"  - {info.path}: {len(info.repos)} repo(s)")
            for repo in info.repos:
                hook_list = ", ".join(repo.hooks[:5]) or "none"
                rev = repo.rev or "unpinned"
                lines.append(f"      {repo.repo} @ {rev}: [{hook_list}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
