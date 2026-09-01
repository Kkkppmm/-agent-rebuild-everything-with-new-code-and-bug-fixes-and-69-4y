"""NpmAnalyzer — audit package.json, .npmrc, and lockfiles for security and build hardening."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

NPM_PACKAGE_NAMES = ("package.json",)
NPM_CONFIG_NAMES = (".npmrc",)
NPM_LOCK_NAMES = ("package-lock.json", "npm-shrinkwrap.json")
YARN_LOCK_NAMES = ("yarn.lock",)
PNPM_LOCK_NAMES = ("pnpm-lock.yaml",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|_authToken|_auth)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
NPM_TOKEN_PATTERN = re.compile(r"[\"']?npm_[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"[\"'](?:\*|latest|LATEST)[\"']|"
    r":\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"[\"']git\+[^\"']+#[\"']?(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git\+|github:|gitlab:|bitbucket:)[^\s\"']+#(?:main|master|HEAD|develop)\b|"
    r"[\"']git\+[^\"']+#[\"']?(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:strict-ssl\s*=\s*false|strictSsl\s*:\s*false|"
    r"cafile\s*=\s*/dev/null|ca\s*=\s*null)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
REGISTRY_URL_PATTERN = re.compile(
    r"(?:registry|@scope:registry)\s*[=:]\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
LIFECYCLE_SCRIPT_PATTERN = re.compile(
    r"\"(?:preinstall|install|postinstall|prepare)\"\s*:\s*\"([^\"]+)\"",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)


@dataclass
class NpmFinding:
    """A security or best-practice issue in an npm configuration file."""

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
class NpmInfo:
    """Parsed metadata about an npm configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass
class NpmStats:
    """Aggregate npm analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_npm_file(path: Path) -> bool:
    """Return True if the path looks like an npm configuration file."""
    name = path.name
    if name in NPM_PACKAGE_NAMES or name in NPM_CONFIG_NAMES:
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "package.json":
        return "package"
    if name == ".npmrc":
        return "npmrc"
    if name in NPM_LOCK_NAMES:
        return "lock"
    if name in YARN_LOCK_NAMES:
        return "yarn_lock"
    if name in PNPM_LOCK_NAMES:
        return "pnpm_lock"
    return "unknown"


def _has_lockfile(directory: Path) -> bool:
    for name in (*NPM_LOCK_NAMES, *YARN_LOCK_NAMES, *PNPM_LOCK_NAMES):
        if (directory / name).exists():
            return True
    return False


class NpmAnalyzer:
    """Audit npm configuration for security issues.

    Scans package.json, .npmrc, and related files for hardcoded npm tokens,
    insecure HTTP registry URLs, credentials in git/source URLs, unpinned git
    dependencies, loose version constraints, lifecycle script risks, strict-ssl
    bypasses, and missing lockfiles.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[NpmFinding] | None = None
        self._stats: NpmStats | None = None
        self._infos: list[NpmInfo] | None = None

    def configs(self) -> list[Path]:
        """Return npm configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_npm_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[NpmFinding],
        info: NpmInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        registry_match = REGISTRY_URL_PATTERN.search(stripped)
        if registry_match:
            info.registries.append(registry_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in npm config — use NPM_TOKEN env var or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in config — use NPM_TOKEN or .npmrc with env var interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in npm config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP registry URL — use HTTPS for npm registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use token env vars or SSH keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DYNAMIC_VERSION_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="dynamic_version",
                    severity="medium",
                    message="loose version constraint — pin dependencies and commit lockfile",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency pinned to moving branch — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_SSL_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="insecure_ssl",
                    severity="high",
                    message="SSL/TLS verification disabled — keep strict-ssl enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in npm config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                NpmFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        for script_match in LIFECYCLE_SCRIPT_PATTERN.finditer(line):
            script_body = script_match.group(1)
            info.scripts.append(script_match.group(0))
            if CURL_PIPE_SHELL_PATTERN.search(script_body):
                findings.append(
                    NpmFinding(
                        kind="lifecycle_curl_pipe",
                        severity="high",
                        message="lifecycle script pipes remote content to shell — review install hooks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if DANGEROUS_SCRIPT_PATTERN.search(script_body):
                findings.append(
                    NpmFinding(
                        kind="dangerous_script",
                        severity="high",
                        message="lifecycle script contains dangerous commands — audit install hooks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_package_json(
        self, path: Path, rel: str
    ) -> tuple[list[NpmFinding], NpmInfo]:
        findings: list[NpmFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, NpmInfo(path=rel, file_kind="package")

        raw_lines = text.splitlines()
        info = NpmInfo(path=rel, lines=len(raw_lines), file_kind="package")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                NpmFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="package.json is not valid JSON — fix syntax before publishing",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return findings, info

        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                for name, version in deps.items():
                    info.dependencies.append(name)
                    version_str = str(version)
                    if version_str in ("*", "latest", "LATEST"):
                        findings.append(
                            NpmFinding(
                                kind="dynamic_version",
                                severity="medium",
                                message=f"unpinned dependency {name} — pin to exact version",
                                path=rel,
                                lineno=1,
                                line=f"{name}: {version_str}",
                            )
                        )
                    if GIT_DEP_UNPINNED_PATTERN.search(version_str):
                        findings.append(
                            NpmFinding(
                                kind="unpinned_git_dep",
                                severity="medium",
                                message=f"git dependency {name} uses moving ref — pin to commit SHA",
                                path=rel,
                                lineno=1,
                                line=version_str,
                            )
                        )

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for name, body in scripts.items():
                if name in ("preinstall", "install", "postinstall", "prepare"):
                    body_str = str(body)
                    info.scripts.append(name)
                    if CURL_PIPE_SHELL_PATTERN.search(body_str):
                        findings.append(
                            NpmFinding(
                                kind="lifecycle_curl_pipe",
                                severity="high",
                                message=f"{name} script pipes remote content to shell",
                                path=rel,
                                lineno=1,
                                line=body_str,
                            )
                        )
                    if DANGEROUS_SCRIPT_PATTERN.search(body_str):
                        findings.append(
                            NpmFinding(
                                kind="dangerous_script",
                                severity="high",
                                message=f"{name} script contains dangerous commands",
                                path=rel,
                                lineno=1,
                                line=body_str,
                            )
                        )

        if not _has_lockfile(path.parent):
            findings.append(
                NpmFinding(
                    kind="missing_lockfile",
                    severity="low",
                    message="lockfile missing — commit package-lock.json, yarn.lock, or pnpm-lock.yaml",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[NpmFinding], NpmInfo]:
        findings: list[NpmFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, NpmInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = NpmInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[NpmFinding], NpmInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "package.json":
            return self._analyze_package_json(path, rel)
        return self._analyze_text_file(path, rel)

    def analyze(self) -> list[NpmFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[NpmFinding] = []
        infos: list[NpmInfo] = []
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
        self._stats = NpmStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> NpmStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[NpmInfo]:
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
        """Scaffold a hardened .npmrc snippet with secure defaults."""
        return """\
# .npmrc — hardened defaults for npm projects
# Store credentials via environment variables:
#   export NPM_TOKEN=your-token
#   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
registry=https://registry.npmjs.org/
strict-ssl=true
# always-auth=true  # only when using private registries
# engine-strict=true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Npm configs: none found"
        return (
            f"Npm configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Npm analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            registries = ", ".join(info.registries[:8]) if info.registries else "none"
            scripts = ", ".join(info.scripts[:8]) if info.scripts else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.registries)} registry URL(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    registries: {registries}")
            lines.append(f"    lifecycle scripts: {scripts}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
