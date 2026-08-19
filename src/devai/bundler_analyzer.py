"""BundlerAnalyzer — audit Gemfile, gems.rb, and .bundle/config for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUNDLER_MANIFEST_NAMES = ("Gemfile", "gems.rb")
BUNDLER_CONFIG_NAMES = (".bundle/config",)
BUNDLER_LOCK_NAMES = ("Gemfile.lock",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?|"
    r"[\"'](?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)[\"']\s*:\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
RUBYGEMS_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:rubygems_[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|"
    r"gho_[A-Za-z0-9]{20,}|gitlab[^\"'\s]{10,})[\"']?",
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
LOOSE_VERSION_PATTERN = re.compile(
    r"gem\s+[\"'][^\"']+[\"']\s*(?:,|\s)*$|"
    r"gem\s+[\"'][^\"']+[\"']\s*,\s*[\"'](?:\*|>=\s*0)[\"']",
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
DANGEROUS_HOOK_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|nc\s+-|/dev/tcp|Kernel\.system)",
    re.IGNORECASE,
)
BUNDLE_CONFIG_CREDENTIAL_PATTERN = re.compile(
    r"BUNDLE_[A-Z0-9_]*(?:TOKEN|PASSWORD|SECRET|KEY|CREDENTIAL)",
    re.IGNORECASE,
)
SOURCE_HTTP_PATTERN = re.compile(
    r"source\s+[\"']http://",
    re.IGNORECASE,
)
GEM_SOURCE_PATTERN = re.compile(
    r"gem\s+[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


@dataclass
class BundlerFinding:
    """A security or best-practice issue in a Bundler configuration file."""

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
class BundlerInfo:
    """Parsed metadata about a Bundler configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    gems: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class BundlerStats:
    """Aggregate Bundler analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bundler_file(path: Path) -> bool:
    """Return True if the path looks like a Bundler configuration file."""
    name = path.name
    if name in BUNDLER_MANIFEST_NAMES:
        return True
    if name == "config" and path.parent.name == ".bundle":
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in ("Gemfile", "gems.rb"):
        return "manifest"
    if name == "config" and path.parent.name == ".bundle":
        return "bundle_config"
    if name in BUNDLER_LOCK_NAMES:
        return "lock"
    return "unknown"


def _has_lockfile(directory: Path) -> bool:
    return (directory / "Gemfile.lock").exists()


class BundlerAnalyzer:
    """Audit Ruby Bundler configuration for security issues.

    Scans Gemfile, gems.rb, and .bundle/config for hardcoded tokens, insecure
    HTTP source URLs, credentials in git sources, unpinned git dependencies,
    loose version constraints, committed bundle credentials, dangerous install
    hooks, and missing Gemfile.lock lockfiles.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BundlerFinding] | None = None
        self._stats: BundlerStats | None = None
        self._infos: list[BundlerInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bundler configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_bundler_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BundlerFinding],
        info: BundlerInfo,
        *,
        is_bundle_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        source_match = re.search(r"source\s+[\"']([^\"']+)[\"']", stripped, re.IGNORECASE)
        if source_match:
            info.sources.append(source_match.group(1))

        gem_match = GEM_SOURCE_PATTERN.search(stripped)
        if gem_match:
            info.gems.append(gem_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Bundler config — use BUNDLE_* env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if RUBYGEMS_TOKEN_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="rubygems_token",
                    severity="high",
                    message="RubyGems/GitHub token in config — use bundle config with env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Bundler config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SOURCE_HTTP_PATTERN.search(line) or INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP source URL — use HTTPS for RubyGems and private gem servers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in git source URL — use bundle config credentials or SSH keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency may be unpinned — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOOSE_VERSION_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="loose_version",
                    severity="low",
                    message="gem without pinned version — specify version constraints and commit Gemfile.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Bundler config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_HOOK_PATTERN.search(line) and (
            "install" in stripped.lower() or "hook" in stripped.lower() or "plugin" in stripped.lower()
        ):
            findings.append(
                BundlerFinding(
                    kind="dangerous_hook",
                    severity="high",
                    message="dangerous Bundler hook or plugin command — review install-time scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if is_bundle_config and BUNDLE_CONFIG_CREDENTIAL_PATTERN.search(line):
            findings.append(
                BundlerFinding(
                    kind="bundle_credential",
                    severity="high",
                    message="credential stored in .bundle/config — add to .gitignore and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_manifest(self, path: Path, rel: str) -> tuple[list[BundlerFinding], BundlerInfo]:
        findings: list[BundlerFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BundlerInfo(path=rel, file_kind="manifest")

        raw_lines = text.splitlines()
        info = BundlerInfo(path=rel, lines=len(raw_lines), file_kind="manifest")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        if not _has_lockfile(path.parent):
            findings.append(
                BundlerFinding(
                    kind="missing_lock",
                    severity="low",
                    message="Gemfile.lock missing — commit lockfile for reproducible installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_bundle_config(self, path: Path, rel: str) -> tuple[list[BundlerFinding], BundlerInfo]:
        findings: list[BundlerFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BundlerInfo(path=rel, file_kind="bundle_config")

        raw_lines = text.splitlines()
        info = BundlerInfo(path=rel, lines=len(raw_lines), file_kind="bundle_config")

        findings.append(
            BundlerFinding(
                kind="committed_bundle_config",
                severity="high",
                message=".bundle/config committed to repository — add .bundle/ to .gitignore and use CI secrets",
                path=rel,
                lineno=1,
                line="",
            )
        )

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info, is_bundle_config=True)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[BundlerFinding], BundlerInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "config" and path.parent.name == ".bundle":
            return self._analyze_bundle_config(path, rel)
        return self._analyze_manifest(path, rel)

    def analyze(self) -> list[BundlerFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BundlerFinding] = []
        infos: list[BundlerInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        manifest_dirs = {
            p.parent for p in paths if p.name in BUNDLER_MANIFEST_NAMES
        }
        self._findings = findings
        self._infos = infos
        self._stats = BundlerStats(
            configs=len(manifest_dirs),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BundlerStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BundlerInfo]:
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
        """Scaffold a hardened Gemfile snippet with secure defaults."""
        return """\
source "https://rubygems.org"

# Pin Ruby version for reproducible builds
ruby "~> 3.3.0"

# Use version constraints and commit Gemfile.lock
gem "rails", "~> 7.2.0"

# For private gems, use bundle config credentials — never commit .bundle/config
# bundle config set --global rubygems.pkg.github.com USERNAME:$GITHUB_TOKEN
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bundler configs: none found"
        return (
            f"Bundler configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bundler analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            gems = ", ".join(info.gems[:8]) if info.gems else "none"
            sources = ", ".join(info.sources[:4]) if info.sources else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.gems)} gem(s), {len(info.sources)} source(s)"
            )
            lines.append(f"    gems: {gems}")
            lines.append(f"    sources: {sources}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
