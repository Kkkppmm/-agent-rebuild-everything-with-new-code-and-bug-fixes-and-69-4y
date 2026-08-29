"""PnpmAnalyzer — audit pnpm workspace and config files for security and supply-chain risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

PNPM_WORKSPACE_NAMES = ("pnpm-workspace.yaml", "pnpm-workspace.yml")
PNPM_LOCK_NAMES = ("pnpm-lock.yaml",)
PNPM_HOOK_NAMES = (".pnpmfile.cjs", ".pnpmfile.js")
PNPM_NPMRC_NAME = ".npmrc"
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
    r"verify-store-integrity\s*=\s*false|cafile\s*=\s*/dev/null|ca\s*=\s*null)",
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
SHAMEFULLY_HOIST_PATTERN = re.compile(r"shamefully-hoist\s*=\s*true\b", re.IGNORECASE)
STRICT_PEER_DISABLED_PATTERN = re.compile(
    r"strict-peer-dependencies\s*=\s*false\b", re.IGNORECASE
)
AUTO_INSTALL_PEERS_PATTERN = re.compile(r"auto-install-peers\s*=\s*true\b", re.IGNORECASE)
PNPM_OVERRIDE_PATTERN = re.compile(r"^\s*\"?pnpm\"?\s*:\s*\{", re.IGNORECASE)
RESOLUTION_PATTERN = re.compile(r"^\s*\"?(?:overrides|resolutions|pnpm\.overrides)\"?\s*:", re.IGNORECASE)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)
REMOTE_REQUIRE_PATTERN = re.compile(
    r"require\s*\(\s*['\"]https?://", re.IGNORECASE
)


@dataclass
class PnpmFinding:
    """A security or best-practice issue in a pnpm configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PnpmInfo:
    """Parsed metadata about a pnpm configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    packages: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)
    overrides: list[str] = field(default_factory=list)


@dataclass
class PnpmStats:
    """Aggregate pnpm analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pnpm_file(path: Path) -> bool:
    name = path.name
    if name in PNPM_WORKSPACE_NAMES or name in PNPM_LOCK_NAMES or name in PNPM_HOOK_NAMES:
        return True
    if name == PNPM_NPMRC_NAME:
        return True
    if name == "package.json":
        return False
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in PNPM_WORKSPACE_NAMES:
        return "workspace"
    if name in PNPM_LOCK_NAMES:
        return "lock"
    if name in PNPM_HOOK_NAMES:
        return "hook"
    if name == PNPM_NPMRC_NAME:
        return "npmrc"
    if name == "package.json":
        return "package"
    return "unknown"


def _has_pnpm_lock(directory: Path) -> bool:
    return any((directory / name).exists() for name in PNPM_LOCK_NAMES)


def _looks_like_pnpm_project(root: Path) -> bool:
    if _has_pnpm_lock(root):
        return True
    if any((root / name).exists() for name in PNPM_WORKSPACE_NAMES):
        return True
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            package_manager = str(data.get("packageManager", ""))
            if package_manager.startswith("pnpm@"):
                return True
            if isinstance(data.get("pnpm"), dict):
                return True
        except (OSError, json.JSONDecodeError):
            pass
    npmrc = root / PNPM_NPMRC_NAME
    if npmrc.is_file():
        try:
            text = npmrc.read_text(encoding="utf-8", errors="replace")
            if re.search(
                r"(?:shamefully-hoist|auto-install-peers|verify-store-integrity|"
                r"node-linker|pnpm-version)\s*=",
                text,
                re.IGNORECASE,
            ):
                return True
        except OSError:
            pass
    return False


class PnpmAnalyzer:
    """Audit pnpm workspace configuration for security and supply-chain risks.

    Scans pnpm-workspace.yaml, pnpm-lock.yaml, .pnpmfile hooks, and pnpm-specific
    .npmrc settings for hardcoded tokens, disabled integrity checks, shamefully-hoist,
    unpinned git dependencies, dangerous hook scripts, and override/resolution risks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PnpmFinding] | None = None
        self._stats: PnpmStats | None = None
        self._infos: list[PnpmInfo] | None = None

    def configs(self) -> list[Path]:
        """Return pnpm configuration paths found in the project."""
        if not _looks_like_pnpm_project(self.root):
            return []

        found: list[Path] = []
        for name in (*PNPM_WORKSPACE_NAMES, *PNPM_LOCK_NAMES, *PNPM_HOOK_NAMES, PNPM_NPMRC_NAME):
            path = self.root / name
            if path.is_file():
                found.append(path)

        for pattern in ("pnpm-workspace.y*ml", "pnpm-lock.yaml", ".pnpmfile.*"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found:
                    if _is_pnpm_file(path) or path.name.startswith(".pnpmfile"):
                        found.append(path)

        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data.get("pnpm"), dict) or "pnpm.overrides" in json.dumps(data):
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PnpmFinding],
        info: PnpmInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if info.file_kind == "workspace" and stripped.startswith("- "):
            package = stripped[2:].strip().strip("'\"")
            if package:
                info.packages.append(package)

        registry_match = re.search(
            r"(?:registry|@scope:registry)\s*[=:]\s*[\"']?(\S+)[\"']?",
            stripped,
            re.IGNORECASE,
        )
        if registry_match:
            info.registries.append(registry_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in pnpm config — use env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in pnpm config — use NPM_TOKEN env var interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in pnpm config — rotate and use secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP registry URL — use HTTPS for pnpm registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                PnpmFinding(
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
                PnpmFinding(
                    kind="insecure_ssl",
                    severity="high",
                    message="store or TLS verification disabled — keep verify-store-integrity and strict-ssl enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in pnpm config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SCRIPT_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="dangerous_script",
                    severity="high",
                    message="dangerous command in pnpm config — review hooks and lifecycle scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                PnpmFinding(
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
                PnpmFinding(
                    kind="dynamic_version",
                    severity="medium",
                    message="loose version constraint — pin dependencies and commit pnpm-lock.yaml",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SHAMEFULLY_HOIST_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="shamefully_hoist",
                    severity="medium",
                    message="shamefully-hoist enabled — increases dependency confusion and phantom dependency risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_PEER_DISABLED_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="strict_peer_disabled",
                    severity="low",
                    message="strict-peer-dependencies disabled — peer dependency mismatches may go unnoticed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AUTO_INSTALL_PEERS_PATTERN.search(line):
            findings.append(
                PnpmFinding(
                    kind="auto_install_peers",
                    severity="low",
                    message="auto-install-peers enabled — review peer dependency auto-install behavior",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if info.file_kind == "hook":
            if EVAL_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="pnpmfile_eval",
                        severity="high",
                        message="eval in .pnpmfile hook — avoid dynamic code execution in install hooks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if REMOTE_REQUIRE_PATTERN.search(line):
                findings.append(
                    PnpmFinding(
                        kind="pnpmfile_remote_require",
                        severity="high",
                        message="remote require in .pnpmfile — vendor hook dependencies locally",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        override_match = re.search(r'"([^"]+)"\s*:\s*"([^"]+)"', line)
        if override_match and (
            RESOLUTION_PATTERN.search(line) or info.file_kind in ("package", "npmrc")
        ):
            info.overrides.append(override_match.group(1))
            override_value = override_match.group(2)
            if override_value in ("*", "latest", "LATEST"):
                findings.append(
                    PnpmFinding(
                        kind="wildcard_override",
                        severity="high",
                        message=f"pnpm override {override_match.group(1)} uses wildcard — pin exact versions",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_package_json(
        self, path: Path, rel: str
    ) -> tuple[list[PnpmFinding], PnpmInfo]:
        findings: list[PnpmFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PnpmInfo(path=rel, file_kind="package")

        raw_lines = text.splitlines()
        info = PnpmInfo(path=rel, lines=len(raw_lines), file_kind="package")

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                PnpmFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="package.json is not valid JSON — fix syntax before publishing",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return findings, info

        pnpm_block = data.get("pnpm", {})
        if isinstance(pnpm_block, dict):
            overrides = pnpm_block.get("overrides", {})
            if isinstance(overrides, dict):
                for name, version in overrides.items():
                    info.overrides.append(str(name))
                    version_str = str(version)
                    if version_str in ("*", "latest", "LATEST"):
                        findings.append(
                            PnpmFinding(
                                kind="wildcard_override",
                                severity="high",
                                message=f"pnpm.overrides.{name} uses wildcard — pin exact versions",
                                path=rel,
                                lineno=1,
                                line=f"{name}: {version_str}",
                            )
                        )
                    if GIT_DEP_UNPINNED_PATTERN.search(version_str):
                        findings.append(
                            PnpmFinding(
                                kind="unpinned_git_dep",
                                severity="medium",
                                message=f"pnpm override {name} uses moving git ref — pin to commit SHA",
                                path=rel,
                                lineno=1,
                                line=version_str,
                            )
                        )

        if not _has_pnpm_lock(path.parent):
            findings.append(
                PnpmFinding(
                    kind="missing_lockfile",
                    severity="low",
                    message="pnpm-lock.yaml missing — commit lockfile for reproducible installs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[PnpmFinding], PnpmInfo]:
        findings: list[PnpmFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PnpmInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = PnpmInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        if info.file_kind == "workspace" and not info.packages:
            findings.append(
                PnpmFinding(
                    kind="empty_workspace",
                    severity="low",
                    message="pnpm-workspace.yaml has no packages — verify workspace globs",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[PnpmFinding], PnpmInfo]:
        rel = str(path.relative_to(self.root))
        if path.name == "package.json":
            return self._analyze_package_json(path, rel)
        return self._analyze_text_file(path, rel)

    def analyze(self) -> list[PnpmFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PnpmFinding] = []
        infos: list[PnpmInfo] = []
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
        self._stats = PnpmStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PnpmStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PnpmInfo]:
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
        """Scaffold hardened pnpm workspace and .npmrc defaults."""
        return """\
# pnpm-workspace.yaml
packages:
  - "packages/*"
  - "apps/*"

# .npmrc — hardened defaults for pnpm projects
registry=https://registry.npmjs.org/
strict-ssl=true
verify-store-integrity=true
strict-peer-dependencies=true
auto-install-peers=false
# shamefully-hoist=false
# engine-strict=true
# Store credentials via environment variables:
#   export NPM_TOKEN=your-token
#   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pnpm configs: none found"
        return (
            f"Pnpm configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Pnpm analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            packages = ", ".join(info.packages[:8]) if info.packages else "none"
            registries = ", ".join(info.registries[:8]) if info.registries else "none"
            overrides = ", ".join(info.overrides[:8]) if info.overrides else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.packages)} package(s), {len(info.overrides)} override(s)"
            )
            lines.append(f"    packages: {packages}")
            lines.append(f"    registries: {registries}")
            lines.append(f"    overrides: {overrides}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
