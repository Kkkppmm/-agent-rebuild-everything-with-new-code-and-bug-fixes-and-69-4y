"""HomebrewAnalyzer — audit Brewfile, Formula, and Cask files for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BREWFILE_NAMES = ("Brewfile", "Brewfile.lock.json", ".homebrew-bundle.yml")
BREW_CONFIG_NAMES = (".brewconfig",)
BREW_DIRS = ("Formula", "Casks", "HomebrewFormula", "homebrew-core", "homebrew-cask")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
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
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:branch|revision|ref|tag|head)\s*[=:]\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"(?:\?|&)ref=(?:main|master|HEAD|develop|trunk)\b|"
    r"git:\s*[\"'][^\"']*(?:main|master|HEAD|develop|trunk)[\"']",
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
TLS_VERIFY_OFF_PATTERN = re.compile(
    r"(?:HOMEBREW_NO_VERIFY_ATTESTATIONS|HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK|"
    r"ssl_verify|verify_ssl)[\"']?\s*[=:]\s*(?:true|1|on|True|ON)\b|"
    r"curl\s+[^\n]*--insecure\b|"
    r"curl\s+[^\n]*-k\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
BREW_TAP_PATTERN = re.compile(
    r'\b(?:tap|cask_tap)\s+["\']([^"\']+)["\']',
    re.IGNORECASE,
)
BREW_INSTALL_PATTERN = re.compile(
    r'\b(?:brew|cask)\s+["\']([^"\']+)["\']',
    re.IGNORECASE,
)
FORMULA_URL_PATTERN = re.compile(
    r'\burl\s+["\']([^"\']+)["\']',
    re.IGNORECASE,
)
FORMULA_GIT_PATTERN = re.compile(
    r'\b(?:url|head)\s+["\']git\+?https?://[^"\']+["\']',
    re.IGNORECASE,
)
HASH_PATTERN = re.compile(
    r"(?:sha256|sha1|sha512|checksum)\s+[\"'][a-fA-F0-9]{8,}[\"']",
    re.IGNORECASE,
)
SYSTEM_COMMAND_PATTERN = re.compile(r"\bsystem\s+[\"']", re.IGNORECASE)
BREW_ENV_SECRET_PATTERN = re.compile(
    r"(?:ENV|ENV\.fetch)\s*\[[\"'](?:HOMEBREW_.*(?:PASSWORD|SECRET|TOKEN|API)|"
    r"PASSWORD|SECRET|TOKEN|API[_-]?KEY)[\"']\]\s*=\s*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
BREW_API_TOKEN_PATTERN = re.compile(
    r"HOMEBREW_GITHUB_API_TOKEN\s*=\s*[\"']?[^\"'\s${}][^\"']*[\"']?",
    re.IGNORECASE,
)
BREW_INSECURE_DOWNLOAD_PATTERN = re.compile(
    r"(?:resource|livecheck)\s+.*http://",
    re.IGNORECASE,
)


@dataclass
class HomebrewFinding:
    """A security or best-practice issue in a Homebrew configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class HomebrewInfo:
    """Parsed metadata from a Homebrew configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    taps: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)


@dataclass
class HomebrewStats:
    """Aggregate statistics from Homebrew analysis."""

    configs: int
    files: int
    findings: int
    high_severity: int
    medium_severity: int
    low_severity: int


def _is_homebrew_file(path: Path) -> bool:
    name = path.name
    if name in BREWFILE_NAMES or name in BREW_CONFIG_NAMES:
        return True
    if path.suffix == ".rb":
        if path.parent.name in BREW_DIRS:
            return True
        if name.endswith("Formula.rb") or name.endswith("Cask.rb"):
            return True
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        if "class" in text and ("< Formula" in text or "< Cask" in text):
            return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "Brewfile":
        return "brewfile"
    if name == "Brewfile.lock.json":
        return "brewfile.lock"
    if name == ".homebrew-bundle.yml":
        return "bundle"
    if name == ".brewconfig":
        return "brewconfig"
    if path.parent.name == "Formula" or name.endswith("Formula.rb"):
        return "formula"
    if path.parent.name == "Casks" or name.endswith("Cask.rb"):
        return "cask"
    if path.suffix == ".rb":
        return "ruby"
    return "unknown"


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith("#")


class HomebrewAnalyzer:
    """Audit Homebrew configuration for security issues.

    Scans Brewfile, Formula/Cask Ruby files, and brew config for hardcoded
    secrets, insecure HTTP URLs, credentials in git URLs, unpinned git refs,
    disabled TLS verification, unverified downloads, and dangerous system calls.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HomebrewFinding] | None = None
        self._stats: HomebrewStats | None = None
        self._infos: list[HomebrewInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Homebrew configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_homebrew_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        file_kind: str,
        findings: list[HomebrewFinding],
        info: HomebrewInfo,
    ) -> None:
        if _is_comment_line(line):
            return

        tap_match = BREW_TAP_PATTERN.search(line)
        if tap_match:
            info.taps.append(tap_match.group(1))

        pkg_match = BREW_INSTALL_PATTERN.search(line)
        if pkg_match:
            info.packages.append(pkg_match.group(1))

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or BREW_ENV_SECRET_PATTERN.search(line)
            or BREW_API_TOKEN_PATTERN.search(line)
        ):
            findings.append(
                HomebrewFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Homebrew config — use env vars or macOS Keychain",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Homebrew config — use credential helpers",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line) or BREW_INSECURE_DOWNLOAD_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for taps, downloads, and bottle mirrors",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="git ref pinned to moving branch — pin to commit SHA or version tag",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in formulas",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep SSL verification enabled for downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SYSTEM_COMMAND_PATTERN.search(line) and DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                HomebrewFinding(
                    kind="dangerous_system_call",
                    severity="high",
                    message="dangerous command in system() call — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FORMULA_URL_PATTERN.search(line) and not HASH_PATTERN.search(line):
            if "http://" in line.lower() or FORMULA_GIT_PATTERN.search(line):
                findings.append(
                    HomebrewFinding(
                        kind="unverified_download",
                        severity="medium",
                        message="formula download without sha256 — pin checksum for reproducibility",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[HomebrewFinding], HomebrewInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[HomebrewFinding] = []
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, HomebrewInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = HomebrewInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, file_kind, findings, info)

        return findings, info

    def analyze(self) -> list[HomebrewFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HomebrewFinding] = []
        infos: list[HomebrewInfo] = []
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
        self._stats = HomebrewStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HomebrewStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HomebrewInfo]:
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
        """Scaffold a hardened Brewfile snippet with secure defaults."""
        return """\
# Secure Brewfile — load secrets from the environment, never hardcode tokens
tap "homebrew/core"
tap "homebrew/cask"

brew "git"
brew "node"

# Use HOMEBREW_GITHUB_API_TOKEN from the environment for private taps
# export HOMEBREW_GITHUB_API_TOKEN="$(security find-generic-password -s github -w)"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Homebrew configs: none found"
        return (
            f"Homebrew configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Homebrew analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            taps = ", ".join(info.taps[:8]) if info.taps else "none"
            packages = ", ".join(info.packages[:8]) if info.packages else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.taps)} tap(s), {len(info.packages)} package(s)"
            )
            lines.append(f"      taps: {taps}")
            lines.append(f"      packages: {packages}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
