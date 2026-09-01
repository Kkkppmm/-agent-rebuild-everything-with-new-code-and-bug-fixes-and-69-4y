"""ComposerAnalyzer — audit composer.json, auth.json, and composer.lock for security and build hardening."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

COMPOSER_MANIFEST_NAMES = ("composer.json",)
COMPOSER_AUTH_NAMES = ("auth.json",)
COMPOSER_LOCK_NAMES = ("composer.lock",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|github-oauth|http-basic|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?|"
    r"[\"'](?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)[\"']\s*:\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
COMPOSER_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
    r"gitlab[^\"'\s]{10,}|composer_[A-Za-z0-9_-]{20,})[\"']?",
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
DEV_VERSION_PATTERN = re.compile(
    r"[\"'](?:\*|dev-master|dev-main|dev-develop|@dev|dev-)[^\"']*[\"']|"
    r":\s*[\"'](?:\*|dev-master|dev-main|dev-develop|@dev)[\"']",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:vcs|git)\s*[\"'][^\"']+[\"']|"
    r"[\"']url[\"']\s*:\s*[\"']git[^\"']+#[\"']?(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SECURE_HTTP_DISABLED_PATTERN = re.compile(
    r"[\"']secure-http[\"']\s*:\s*false|"
    r"[\"']disable-tls[\"']\s*:\s*true|"
    r"[\"']cafile[\"']\s*:\s*[\"']?/dev/null[\"']?",
    re.IGNORECASE,
)
ALLOW_PLUGINS_WILDCARD_PATTERN = re.compile(
    r"[\"']allow-plugins[\"']\s*:\s*\{[^}]*[\"']\*[\"']\s*:\s*true|"
    r"[\"']allow-plugins[\"']\s*:\s*true",
    re.IGNORECASE,
)
MINIMUM_STABILITY_DEV_PATTERN = re.compile(
    r"[\"']minimum-stability[\"']\s*:\s*[\"']dev[\"']",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
SCRIPTS_PATTERN = re.compile(
    r"[\"']scripts[\"']\s*:\s*\{",
    re.IGNORECASE,
)


@dataclass
class ComposerFinding:
    """A security or best-practice issue in a Composer configuration file."""

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
class ComposerInfo:
    """Parsed metadata about a Composer configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass
class ComposerStats:
    """Aggregate Composer analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_composer_file(path: Path) -> bool:
    """Return True if the path looks like a Composer configuration file."""
    name = path.name
    return name in COMPOSER_MANIFEST_NAMES or name in COMPOSER_AUTH_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "composer.json":
        return "manifest"
    if name == "auth.json":
        return "auth"
    if name in COMPOSER_LOCK_NAMES:
        return "lock"
    return "unknown"


def _has_lockfile(directory: Path) -> bool:
    return (directory / "composer.lock").exists()


class ComposerAnalyzer:
    """Audit PHP Composer configuration for security issues.

    Scans composer.json and auth.json for hardcoded tokens, insecure HTTP
    repository URLs, credentials in VCS URLs, dev/unpinned dependencies,
    disabled TLS verification, wildcard allow-plugins, committed auth.json,
    dangerous scripts, and missing composer.lock lockfiles.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ComposerFinding] | None = None
        self._stats: ComposerStats | None = None
        self._infos: list[ComposerInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Composer configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_composer_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ComposerFinding],
        info: ComposerInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Composer config — use COMPOSER_AUTH env var or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COMPOSER_TOKEN_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="composer_token",
                    severity="high",
                    message="Composer/GitHub token in config — use auth.json locally (gitignored) or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Composer config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP repository URL — use HTTPS for Composer repositories",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use auth.json with env vars or SSH keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEV_VERSION_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="dev_version",
                    severity="medium",
                    message="dev or wildcard version constraint — pin dependencies and commit composer.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="VCS/git dependency may be unpinned — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SECURE_HTTP_DISABLED_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="tls_disabled",
                    severity="high",
                    message="TLS verification disabled — keep secure-http enabled and avoid disable-tls",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_PLUGINS_WILDCARD_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="allow_plugins_wildcard",
                    severity="medium",
                    message="wildcard allow-plugins — explicitly allow only required Composer plugins",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MINIMUM_STABILITY_DEV_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="minimum_stability_dev",
                    severity="low",
                    message="minimum-stability set to dev — prefer stable releases for production apps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Composer config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line) and SCRIPTS_PATTERN.search(line):
            findings.append(
                ComposerFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous Composer script — review post-install and auto-scripts for injection risks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _extract_json_metadata(self, data: dict, info: ComposerInfo) -> None:
        for section in ("require", "require-dev"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                info.dependencies.extend(f"{name}@{version}" for name, version in deps.items())

        repos = data.get("repositories", [])
        if isinstance(repos, list):
            for repo in repos:
                if isinstance(repo, dict):
                    url = repo.get("url") or repo.get("package", "")
                    if url:
                        info.repositories.append(str(url))

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            info.scripts.extend(scripts.keys())

    def _analyze_composer_json(self, path: Path, rel: str) -> tuple[list[ComposerFinding], ComposerInfo]:
        findings: list[ComposerFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ComposerInfo(path=rel, file_kind="manifest")

        raw_lines = text.splitlines()
        info = ComposerInfo(path=rel, lines=len(raw_lines), file_kind="manifest")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads(text)
            if isinstance(data, dict):
                self._extract_json_metadata(data, info)
        except json.JSONDecodeError:
            findings.append(
                ComposerFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="invalid composer.json — fix JSON syntax for reproducible dependency resolution",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if not _has_lockfile(path.parent):
            findings.append(
                ComposerFinding(
                    kind="missing_lock",
                    severity="low",
                    message="composer.lock missing — commit lockfile for reproducible installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_auth_json(self, path: Path, rel: str) -> tuple[list[ComposerFinding], ComposerInfo]:
        findings: list[ComposerFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ComposerInfo(path=rel, file_kind="auth")

        raw_lines = text.splitlines()
        info = ComposerInfo(path=rel, lines=len(raw_lines), file_kind="auth")

        findings.append(
            ComposerFinding(
                kind="committed_auth",
                severity="high",
                message="auth.json committed to repository — add to .gitignore and use CI secrets",
                path=rel,
                lineno=1,
                line="",
            )
        )

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[ComposerFinding], ComposerInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "auth.json":
            return self._analyze_auth_json(path, rel)
        return self._analyze_composer_json(path, rel)

    def analyze(self) -> list[ComposerFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ComposerFinding] = []
        infos: list[ComposerInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = ComposerStats(
            configs=len({p.parent for p in paths if p.name == "composer.json"} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ComposerStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ComposerInfo]:
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
        """Scaffold a hardened composer.json snippet with secure defaults."""
        return """\
{
    "config": {
        "secure-http": true,
        "sort-packages": true,
        "allow-plugins": {
            "composer/installers": true
        }
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Composer configs: none found"
        return (
            f"Composer configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Composer analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            repos = ", ".join(info.repositories[:4]) if info.repositories else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.repositories)} repo(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    repositories: {repos}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
