"""MixAnalyzer — audit mix.exs, mix.lock, and config/*.exs for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MIX_MANIFEST_NAMES = ("mix.exs",)
MIX_LOCK_NAMES = ("mix.lock",)
MIX_CONFIG_DIR = "config"
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|hex_api_key)\s*[:=]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?|"
    r"[\"'](?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|hex_api_key)[\"']\s*,\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
HEX_API_KEY_PATTERN = re.compile(
    r"[\"']?(?:hex:[A-Za-z0-9_-]{20,}|HEX_API_KEY[=:][A-Za-z0-9_-]{10,})[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git@|git\+https?://|https?://)[^:@\s]+:[^@\s]+@|"
    r"https?://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|github|gitlab|bitbucket)\s*:\s*[\"'][^\"']+[\"']|"
    r"branch\s*:\s*[\"']?(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
LOOSE_DEP_PATTERN = re.compile(
    r"\{:[a-z_][a-z0-9_]*\s*\}$|"
    r"\{:[a-z_][a-z0-9_]*\s*,\s*only\s*:",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
DANGEROUS_ALIAS_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|nc\s+-|/dev/tcp|System\.cmd|Port\.open)",
    re.IGNORECASE,
)
INSECURE_HEX_REPO_PATTERN = re.compile(
    r"url\s*:\s*[\"']http://",
    re.IGNORECASE,
)
DEP_PATTERN = re.compile(
    r"\{:(\w+)",
    re.IGNORECASE,
)
CONFIG_SECRET_PATTERN = re.compile(
    r"config\s+:[a-z_][a-z0-9_]*\s*,\s*[a-z_][a-z0-9_]*\s*:\s*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)


@dataclass
class MixFinding:
    """A security or best-practice issue in an Elixir Mix configuration file."""

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
class MixInfo:
    """Parsed metadata about a Mix configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    deps: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)


@dataclass
class MixStats:
    """Aggregate Mix analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_mix_file(path: Path) -> bool:
    """Return True if the path looks like a Mix configuration file."""
    name = path.name
    if name in MIX_MANIFEST_NAMES:
        return True
    if path.parent.name == MIX_CONFIG_DIR and name.endswith(".exs"):
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "mix.exs":
        return "manifest"
    if path.parent.name == MIX_CONFIG_DIR and name.endswith(".exs"):
        return "config"
    if name in MIX_LOCK_NAMES:
        return "lock"
    return "unknown"


def _has_lockfile(directory: Path) -> bool:
    return (directory / "mix.lock").exists()


class MixAnalyzer:
    """Audit Elixir Mix configuration for security issues.

    Scans mix.exs and config/*.exs for hardcoded tokens, insecure HTTP hex repos,
    credentials in git sources, unpinned git dependencies, loose version constraints,
    dangerous mix aliases, config secrets, and missing mix.lock lockfiles.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MixFinding] | None = None
        self._stats: MixStats | None = None
        self._infos: list[MixInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Mix configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_mix_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MixFinding],
        info: MixInfo,
        *,
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        dep_match = DEP_PATTERN.search(stripped)
        if dep_match:
            info.deps.append(dep_match.group(1))

        repo_match = re.search(r"url\s*:\s*[\"']([^\"']+)[\"']", stripped, re.IGNORECASE)
        if repo_match:
            info.repos.append(repo_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Mix config — use MIX_* env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HEX_API_KEY_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="hex_api_key",
                    severity="high",
                    message="Hex API key in config — use HEX_API_KEY env var or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Mix config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HEX_REPO_PATTERN.search(line) or INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP repo URL — use HTTPS for Hex and private package servers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in git source URL — use SSH keys or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency may be unpinned — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOOSE_DEP_PATTERN.search(stripped) and "defp deps" not in stripped:
            findings.append(
                MixFinding(
                    kind="loose_version",
                    severity="low",
                    message="dependency without version constraint — specify version and commit mix.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Mix config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid embedding credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_ALIAS_PATTERN.search(line) and (
            "alias" in stripped.lower() or "cmd" in stripped.lower() or is_config
        ):
            findings.append(
                MixFinding(
                    kind="dangerous_alias",
                    severity="high",
                    message="dangerous Mix alias or System.cmd — review shell commands in mix.exs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if is_config and CONFIG_SECRET_PATTERN.search(line):
            findings.append(
                MixFinding(
                    kind="config_secret",
                    severity="high",
                    message="secret in config/*.exs — use runtime.exs with env vars for production secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_manifest(self, path: Path, rel: str) -> tuple[list[MixFinding], MixInfo]:
        findings: list[MixFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MixInfo(path=rel, file_kind="manifest")

        raw_lines = text.splitlines()
        info = MixInfo(path=rel, lines=len(raw_lines), file_kind="manifest")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        if not _has_lockfile(path.parent):
            findings.append(
                MixFinding(
                    kind="missing_lock",
                    severity="low",
                    message="mix.lock missing — commit lockfile for reproducible installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_config(self, path: Path, rel: str) -> tuple[list[MixFinding], MixInfo]:
        findings: list[MixFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MixInfo(path=rel, file_kind="config")

        raw_lines = text.splitlines()
        info = MixInfo(path=rel, lines=len(raw_lines), file_kind="config")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info, is_config=True)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[MixFinding], MixInfo]:
        rel = str(path.relative_to(self.root))
        if path.parent.name == MIX_CONFIG_DIR and path.name.endswith(".exs"):
            return self._analyze_config(path, rel)
        return self._analyze_manifest(path, rel)

    def analyze(self) -> list[MixFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MixFinding] = []
        infos: list[MixInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        manifest_dirs = {
            p.parent for p in paths if p.name in MIX_MANIFEST_NAMES
        }
        self._findings = findings
        self._infos = infos
        self._stats = MixStats(
            configs=len(manifest_dirs),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MixStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MixInfo]:
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

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened mix.exs snippet with secure defaults."""
        return """\
defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [
      app: :my_app,
      version: "0.1.0",
      elixir: "~> 1.16",
      deps: deps()
    ]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.0"},
      # Pin git deps to tags or commits — never use branch: "master"
      # {:private_dep, git: "git@github.com:org/repo.git", tag: "v1.0.0"}
    ]
  end
end

# Store HEX_API_KEY via env vars — never hardcode in mix.exs
# export HEX_API_KEY=your_key_here
# Commit mix.lock for reproducible builds
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Mix configs: none found"
        return (
            f"Mix configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Mix analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.deps[:8]) if info.deps else "none"
            repos = ", ".join(info.repos[:4]) if info.repos else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.deps)} dep(s), {len(info.repos)} repo(s)"
            )
            lines.append(f"    deps: {deps}")
            lines.append(f"    repos: {repos}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
