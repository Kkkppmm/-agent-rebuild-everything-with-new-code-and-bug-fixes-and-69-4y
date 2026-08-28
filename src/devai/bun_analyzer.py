"""BunAnalyzer — audit bunfig.toml, bun.lock, and Bun package.json settings for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

BUN_CONFIG_NAMES = ("bunfig.toml",)
BUN_LOCK_NAMES = ("bun.lock", "bun.lockb")
BUN_NPMRC_NAME = ".npmrc"
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:strict-ssl\s*=\s*false|strictSsl\s*:\s*false|"
    r"cafile\s*=\s*/dev/null|ca\s*=\s*null|tls\s*=\s*false)",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git\+|github:|gitlab:|bitbucket:)[^\s\"']+#(?:main|master|HEAD|develop)\b|"
    r"[\"']git\+[^\"']+#[\"']?(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"[\"'](?:\*|latest|LATEST)[\"']|"
    r":\s*[\"'](?:\*|latest|LATEST)[\"']",
    re.IGNORECASE,
)
INSTALL_AUTO_FORCE_PATTERN = re.compile(
    r"(?:auto|install\.auto)\s*=\s*[\"']?force[\"']?",
    re.IGNORECASE,
)
FROZEN_LOCKFILE_DISABLED_PATTERN = re.compile(
    r"(?:frozenLockfile|frozen-lockfile|install\.frozenLockfile)\s*=\s*false\b",
    re.IGNORECASE,
)
TRUST_ALL_PATTERN = re.compile(
    r"(?:trustedDependencies|install\.trusted)\s*=\s*\[\s*[\"']\*[\"']\s*\]|"
    r"trust\s*=\s*true\b",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
LIFECYCLE_SCRIPT_PATTERN = re.compile(
    r"\"(?:preinstall|install|postinstall|prepare)\"\s*:\s*\"([^\"]+)\"",
    re.IGNORECASE,
)


@dataclass
class BunFinding:
    """A security or best-practice issue in a Bun configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BunInfo:
    """Parsed metadata about a Bun configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    workspaces: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass
class BunStats:
    """Aggregate Bun analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bun_file(path: Path) -> bool:
    name = path.name
    if name in BUN_CONFIG_NAMES or name in BUN_LOCK_NAMES:
        return True
    if name == BUN_NPMRC_NAME:
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "bunfig.toml":
        return "bunfig"
    if name in BUN_LOCK_NAMES:
        return "lock"
    if name == BUN_NPMRC_NAME:
        return "npmrc"
    if name == "package.json":
        return "package"
    return "unknown"


def _has_bun_lock(directory: Path) -> bool:
    return any((directory / name).exists() for name in BUN_LOCK_NAMES)


def _looks_like_bun_project(root: Path) -> bool:
    if _has_bun_lock(root):
        return True
    if any((root / name).exists() for name in BUN_CONFIG_NAMES):
        return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            package_manager = str(data.get("packageManager", ""))
            if package_manager.startswith("bun@"):
                return True
            if isinstance(data.get("workspaces"), (list, dict)):
                if _has_bun_lock(root) or (root / "bunfig.toml").exists():
                    return True
        except (OSError, json.JSONDecodeError):
            pass
    npmrc = root / BUN_NPMRC_NAME
    if npmrc.is_file() and _has_bun_lock(root):
        return True
    return False


class BunAnalyzer:
    """Audit Bun configuration for security and supply-chain risks.

    Scans bunfig.toml, bun.lock/bun.lockb, .npmrc, and package.json for hardcoded
    tokens, insecure registry URLs, disabled lockfile enforcement, trusted-all
    dependency settings, unpinned git dependencies, and dangerous lifecycle scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BunFinding] | None = None
        self._stats: BunStats | None = None
        self._infos: list[BunInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bun configuration paths found in the project."""
        if not _looks_like_bun_project(self.root):
            return []

        found: list[Path] = []
        for name in (*BUN_CONFIG_NAMES, *BUN_LOCK_NAMES, BUN_NPMRC_NAME):
            path = self.root / name
            if path.is_file():
                found.append(path)

        for pattern in ("bunfig.toml", "bun.lock", "bun.lockb"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found:
                    found.append(path)

        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                package_manager = str(data.get("packageManager", ""))
                if package_manager.startswith("bun@"):
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BunFinding],
        info: BunInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        registry_match = re.search(
            r"(?:registry|@scope:registry|url)\s*[=:]\s*[\"']?(\S+)[\"']?",
            stripped,
            re.IGNORECASE,
        )
        if registry_match:
            info.registries.append(registry_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Bun config — use env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in Bun config — use NPM_TOKEN env var interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Bun config — rotate and use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP registry URL — use HTTPS for Bun registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use token env vars or SSH keys",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_SSL_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="insecure_ssl",
                    severity="high",
                    message="TLS verification disabled — keep strict-ssl enabled for Bun registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Bun config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous command in Bun config — review install hooks and lifecycle scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency pinned to moving branch — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DYNAMIC_VERSION_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="dynamic_version",
                    severity="medium",
                    message="loose version constraint — pin dependencies and commit bun.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSTALL_AUTO_FORCE_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="install_auto_force",
                    severity="medium",
                    message="install.auto=force runs lifecycle scripts unconditionally — prefer frozen lockfile with explicit trust",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FROZEN_LOCKFILE_DISABLED_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="frozen_lockfile_disabled",
                    severity="medium",
                    message="frozen lockfile disabled — enable install.frozenLockfile in CI for reproducible installs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRUST_ALL_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="trust_all_deps",
                    severity="high",
                    message="trusted all dependencies — only trust specific packages that require lifecycle scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if info.file_kind == "bunfig" and EVAL_PATTERN.search(line):
            findings.append(
                BunFinding(
                    kind="bunfig_eval",
                    severity="high",
                    message="eval in bunfig.toml — avoid dynamic code execution in install configuration",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_package_json(
        self, path: Path, rel: str
    ) -> tuple[list[BunFinding], BunInfo]:
        findings: list[BunFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BunInfo(path=rel, file_kind="package")

        raw_lines = text.splitlines()
        info = BunInfo(path=rel, lines=len(raw_lines), file_kind="package")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                BunFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="package.json is not valid JSON — fix syntax before publishing",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return findings, info

        workspaces = data.get("workspaces")
        if isinstance(workspaces, list):
            info.workspaces.extend(str(w) for w in workspaces)
        elif isinstance(workspaces, dict) and isinstance(workspaces.get("packages"), list):
            info.workspaces.extend(str(w) for w in workspaces["packages"])

        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for name, script in scripts.items():
                if name in ("preinstall", "install", "postinstall", "prepare"):
                    info.scripts.append(name)
                    script_str = str(script)
                    if DANGEROUS_SCRIPT_PATTERN.search(script_str):
                        findings.append(
                            BunFinding(
                                kind="dangerous_lifecycle_script",
                                severity="high",
                                message=f"dangerous {name} script — review lifecycle hooks before publishing",
                                path=rel,
                                lineno=1,
                                line=script_str,
                            )
                        )
                    if CURL_PIPE_SHELL_PATTERN.search(script_str):
                        findings.append(
                            BunFinding(
                                kind="curl_pipe_shell",
                                severity="high",
                                message=f"curl/wget piped to shell in {name} script — vendor scripts locally",
                                path=rel,
                                lineno=1,
                                line=script_str,
                            )
                        )

        deps_blocks = []
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            block = data.get(key)
            if isinstance(block, dict):
                deps_blocks.append(block)

        for block in deps_blocks:
            for name, version in block.items():
                version_str = str(version)
                if version_str in ("*", "latest", "LATEST"):
                    findings.append(
                        BunFinding(
                            kind="dynamic_version",
                            severity="medium",
                            message=f"dependency {name} uses wildcard — pin exact versions in bun.lock",
                            path=rel,
                            lineno=1,
                            line=f"{name}: {version_str}",
                        )
                    )
                if GIT_DEP_UNPINNED_PATTERN.search(version_str):
                    findings.append(
                        BunFinding(
                            kind="unpinned_git_dep",
                            severity="medium",
                            message=f"dependency {name} uses moving git ref — pin to commit SHA",
                            path=rel,
                            lineno=1,
                            line=version_str,
                        )
                    )

        if not _has_bun_lock(path.parent):
            findings.append(
                BunFinding(
                    kind="missing_lockfile",
                    severity="low",
                    message="bun.lock missing — commit lockfile for reproducible installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[BunFinding], BunInfo]:
        findings: list[BunFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BunInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = BunInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[BunFinding], BunInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "package.json":
            return self._analyze_package_json(path, rel)
        return self._analyze_text_file(path, rel)

    def analyze(self) -> list[BunFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BunFinding] = []
        infos: list[BunInfo] = []
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
        self._stats = BunStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BunStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BunInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold hardened bunfig.toml defaults."""
        return """\
# bunfig.toml — hardened defaults for Bun projects
[install]
registry = "https://registry.npmjs.org/"
frozenLockfile = true
exact = true
# auto = "disable"  # disable lifecycle scripts by default; trust specific packages
# trustedDependencies = ["esbuild", "sharp"]  # only trust packages that need postinstall

# .npmrc — optional registry overrides
# strict-ssl=true
# Store credentials via environment variables:
#   export NPM_TOKEN=your-token
#   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bun configs: none found"
        return (
            f"Bun configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Bun analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            workspaces = ", ".join(info.workspaces[:8]) if info.workspaces else "none"
            registries = ", ".join(info.registries[:8]) if info.registries else "none"
            scripts = ", ".join(info.scripts[:8]) if info.scripts else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.workspaces)} workspace(s), {len(info.scripts)} lifecycle script(s)"
            )
            lines.append(f"    workspaces: {workspaces}")
            lines.append(f"    registries: {registries}")
            lines.append(f"    scripts: {scripts}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
