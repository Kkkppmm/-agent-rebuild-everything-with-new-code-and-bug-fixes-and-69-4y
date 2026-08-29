"""ConanAnalyzer — audit Conan conanfiles, profiles, and remotes for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONANFILE_NAMES = ("conanfile.py", "conanfile.txt")
CONANDATA_NAME = "conandata.yml"
CONAN_LOCK_NAME = "conan.lock"
CONAN_GLOBAL_CONF = "global.conf"
CONAN_REMOTES_NAME = "remotes.json"
CONAN_PROFILE_DIRS = ("profiles", "conan/profiles", ".conan/profiles")
CONAN_PROFILE_SUFFIXES = (".profile",)
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
    r"(?:branch|revision|user|channel)\s*=\s*(?:head|HEAD|main|master|develop|trunk)\b|"
    r"(?:version|ref)\s*=\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"version\s*=\s*[\"']?\[[^\]]*\][\"']?|"
    r"checkout\s*\(\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?\s*\)|"
    r"requires\s*\(\s*[\"'][^\"']*/\[[^\]]*\][\"']|"
    r"/\[[^\]]*\]",
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
    r"(?:verify_ssl|ssl_verify|CONAN_REVISIONS_ENABLED)[\"']?\s*[=:]\s*(?:false|0|off|False)\b|"
    r"core\.(?:download|upload):insecure\s*=\s*True\b|"
    r"core\.(?:download|upload)\.insecure\s*=\s*True\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
CONAN_REQUIRE_PATTERN = re.compile(
    r"\bself\.requires\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
CONAN_TOOL_GET_PATTERN = re.compile(r"(?:tools\.)?get\s*\(", re.IGNORECASE)
CONAN_DOWNLOAD_PATTERN = re.compile(r"(?:tools\.)?download\s*\(", re.IGNORECASE)
CONAN_GIT_PATTERN = re.compile(r"\btools\.Git\s*\(", re.IGNORECASE)
CONAN_RUN_PATTERN = re.compile(r"\bself\.run\s*\(", re.IGNORECASE)
CONAN_REMOTE_CREDENTIAL_PATTERN = re.compile(
    r"[\"'](?:password|token|api[_-]?key|secret)[\"']\s*:\s*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
CONAN_SET_SECRET_PATTERN = re.compile(
    r"(?:self\.output\.|os\.environ|tools\.set_env)\s*\([^)]*"
    r"(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL)[^)]*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
CONAN_SHA_PATTERN = re.compile(
    r"(?:sha256|md5|sha1|checksum)\s*[=:]\s*[\"']?[a-fA-F0-9]{8,}",
    re.IGNORECASE,
)


@dataclass
class ConanFinding:
    """A security or best-practice issue in a Conan configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ConanInfo:
    """Parsed metadata from a Conan configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    requirements: list[str] = field(default_factory=list)


@dataclass
class ConanStats:
    """Aggregate statistics from Conan analysis."""

    configs: int
    files: int
    findings: int
    high_severity: int
    medium_severity: int
    low_severity: int


def _is_conan_file(path: Path) -> bool:
    name = path.name
    if name in CONANFILE_NAMES or name == CONANDATA_NAME or name == CONAN_LOCK_NAME:
        return True
    if name == CONAN_GLOBAL_CONF or name == CONAN_REMOTES_NAME:
        return True
    if path.suffix in CONAN_PROFILE_SUFFIXES:
        if any(part in CONAN_PROFILE_DIRS for part in path.parts):
            return True
        if path.parent.name == "profiles":
            return True
    if path.parent.name == "profiles" and path.is_file():
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "conanfile.py":
        return "conanfile.py"
    if name == "conanfile.txt":
        return "conanfile.txt"
    if name == CONANDATA_NAME:
        return "conandata"
    if name == CONAN_REMOTES_NAME:
        return "remotes"
    if name == CONAN_GLOBAL_CONF:
        return "global.conf"
    if path.suffix in CONAN_PROFILE_SUFFIXES:
        return "profile"
    if name == CONAN_LOCK_NAME:
        return "lockfile"
    return "unknown"


def _is_comment_line(line: str, file_kind: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if file_kind == "conanfile.txt":
        return stripped.startswith("#") or stripped.startswith(";")
    return stripped.startswith("#")


class ConanAnalyzer:
    """Audit Conan configuration for security issues.

    Scans conanfile.py, conanfile.txt, conandata.yml, profiles, remotes.json,
    and global.conf for hardcoded secrets, insecure HTTP remotes, credentials
    in git URLs, unpinned git refs, disabled TLS verification, unverified
    downloads, and dangerous self.run commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ConanFinding] | None = None
        self._stats: ConanStats | None = None
        self._infos: list[ConanInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Conan configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_conan_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        file_kind: str,
        findings: list[ConanFinding],
        info: ConanInfo,
    ) -> None:
        if _is_comment_line(line, file_kind):
            return

        req_match = CONAN_REQUIRE_PATTERN.search(line)
        if req_match:
            info.requirements.append(req_match.group(1))

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or CONAN_SET_SECRET_PATTERN.search(line)
            or CONAN_REMOTE_CREDENTIAL_PATTERN.search(line)
        ):
            findings.append(
                ConanFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Conan config — use Conan secrets or environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Conan config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for remotes and download URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in repository URL — use SSH keys or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="dependency pinned to moving ref — pin to tag, commit SHA, or exact version",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Conan recipe — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid bundling credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TLS_VERIFY_OFF_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep verify_ssl enabled for remotes and downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and CONAN_RUN_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="dangerous_run_command",
                    severity="high",
                    message="dangerous command in self.run — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if (
            CONAN_TOOL_GET_PATTERN.search(line) or CONAN_DOWNLOAD_PATTERN.search(line)
        ) and not CONAN_SHA_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="unverified_download",
                    severity="medium",
                    message="tools.get/download without checksum — verify download integrity with sha256",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CONAN_GIT_PATTERN.search(line) and UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                ConanFinding(
                    kind="unpinned_git_clone",
                    severity="medium",
                    message="tools.Git with moving ref — pin commit or tag in Conan recipe",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[ConanFinding], ConanInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[ConanFinding] = []
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ConanInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = ConanInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, file_kind, findings, info)

        return findings, info

    def analyze(self) -> list[ConanFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ConanFinding] = []
        infos: list[ConanInfo] = []
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
        self._stats = ConanStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ConanStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ConanInfo]:
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
        """Scaffold a hardened Conan recipe snippet with secure defaults."""
        return """\
# conanfile.py — hardened defaults for Conan projects
from conan import ConanFile
from conan.tools.files import get
from conan.tools.scm import Git


class SecureDemoConan(ConanFile):
    name = "secure-demo"
    version = "1.0.0"

    def source(self):
        # Pin git dependencies to tags or commit SHAs
        git = Git(self, folder="src")
        git.clone(url="https://github.com/org/mylib.git", target=".")
        git.checkout("v1.2.3")

        # Verify downloads with sha256
        get(
            self,
            "https://example.com/archive.tar.gz",
            sha256="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )

    # Store credentials via Conan secrets or environment variables — never hardcode
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Conan configs: none found"
        return (
            f"Conan configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Conan analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            reqs = ", ".join(info.requirements[:8]) if info.requirements else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.requirements)} requirement(s)"
            )
            lines.append(f"      requirements: {reqs}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
