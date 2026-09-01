"""VcpkgAnalyzer — audit vcpkg.json manifests, portfiles, and registry config for security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

VCPKG_JSON_NAME = "vcpkg.json"
VCPKG_CONFIGURATION_NAME = "vcpkg-configuration.json"
VCPKG_PORTFILE_NAME = "portfile.cmake"
VCPKG_PORTS_DIR = "ports"
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
    r"(?:REF|HEAD_REF|GIT_REF|BASELINE)\s+[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"(?:ref|head|baseline)\s*[=:]\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"vcpkg_from_github\s*\([^)]*REF\s+[\"']?(?:main|master|HEAD|develop|trunk)[\"']?|"
    r"[\"'](?:builtin-)?baseline[\"']\s*:\s*[\"']?(?:main|master|HEAD|develop|trunk)[\"']?",
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
    r"(?:verify_ssl|ssl_verify|TLS_VERIFY|CURL_SSL_NO_VERIFY)[\"']?\s*[=:]\s*(?:false|0|off|False|OFF)\b|"
    r"set\s*\(\s*ENV\{CURL_SSL_NO_VERIFY\}\s+1\s*\)",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
VCPKG_DOWNLOAD_PATTERN = re.compile(
    r"vcpkg_download_distfile\s*\(",
    re.IGNORECASE,
)
VCPKG_FROM_GITHUB_PATTERN = re.compile(
    r"vcpkg_from_github\s*\(",
    re.IGNORECASE,
)
VCPKG_FROM_GIT_PATTERN = re.compile(
    r"vcpkg_from_git\s*\(",
    re.IGNORECASE,
)
VCPKG_EXECUTE_PATTERN = re.compile(
    r"vcpkg_execute_required_process\s*\(",
    re.IGNORECASE,
)
COMMAND_SHELL_PATTERN = re.compile(
    r"COMMAND\s+(?:sh\s+-c|bash\s+-c|/bin/sh\s+-c)",
    re.IGNORECASE,
)
SHA512_PATTERN = re.compile(
    r"(?:SHA512|sha512)\s+[\"']?[a-fA-F0-9]{32,}",
    re.IGNORECASE,
)
VCPKG_DEPENDENCY_PATTERN = re.compile(
    r"[\"']dependencies[\"']\s*:\s*\[([^\]]*)\]",
    re.IGNORECASE,
)
VCPKG_BASELINE_PATTERN = re.compile(
    r"[\"']builtin-baseline[\"']\s*:\s*[\"']([a-fA-F0-9]{8,})[\"']",
    re.IGNORECASE,
)
VCPKG_REGISTRY_PATTERN = re.compile(
    r"[\"']repository[\"']\s*:\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
VCPKG_SECRET_JSON_PATTERN = re.compile(
    r"[\"'](?:password|token|api[_-]?key|secret|credential)[\"']\s*:\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)


@dataclass
class VcpkgFinding:
    """A security or best-practice issue in a vcpkg configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class VcpkgInfo:
    """Parsed metadata from a vcpkg configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    dependencies: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)


@dataclass
class VcpkgStats:
    """Aggregate statistics from vcpkg analysis."""

    configs: int
    files: int
    findings: int
    high_severity: int
    medium_severity: int
    low_severity: int


def _is_vcpkg_file(path: Path) -> bool:
    name = path.name
    if name == VCPKG_JSON_NAME or name == VCPKG_CONFIGURATION_NAME:
        return True
    if name == VCPKG_PORTFILE_NAME:
        return True
    if name == VCPKG_JSON_NAME and VCPKG_PORTS_DIR in path.parts:
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == VCPKG_JSON_NAME and VCPKG_PORTS_DIR in path.parts:
        return "port-json"
    if name == VCPKG_JSON_NAME:
        return "manifest"
    if name == VCPKG_CONFIGURATION_NAME:
        return "configuration"
    if name == VCPKG_PORTFILE_NAME:
        return "portfile"
    return "unknown"


def _is_comment_line(line: str, file_kind: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if file_kind in ("manifest", "configuration", "port-json"):
        return False
    return stripped.startswith("#")


class VcpkgAnalyzer:
    """Audit vcpkg configuration for security issues.

    Scans vcpkg.json, vcpkg-configuration.json, and portfile.cmake for
    hardcoded secrets, insecure HTTP URLs, credentials in git URLs, unpinned
    git refs, disabled TLS verification, unverified downloads, and dangerous
    vcpkg_execute_required_process calls.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[VcpkgFinding] | None = None
        self._stats: VcpkgStats | None = None
        self._infos: list[VcpkgInfo] | None = None

    def configs(self) -> list[Path]:
        """Return vcpkg configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_vcpkg_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        file_kind: str,
        findings: list[VcpkgFinding],
        info: VcpkgInfo,
    ) -> None:
        if _is_comment_line(line, file_kind):
            return

        dep_match = VCPKG_DEPENDENCY_PATTERN.search(line)
        if dep_match:
            deps = re.findall(r"[\"']([^\"']+)[\"']", dep_match.group(1))
            info.dependencies.extend(deps)

        registry_match = VCPKG_REGISTRY_PATTERN.search(line)
        if registry_match:
            info.registries.append(registry_match.group(1))

        baseline_match = VCPKG_BASELINE_PATTERN.search(line)
        if baseline_match:
            info.registries.append(f"baseline:{baseline_match.group(1)}")

        if (
            HARDCODED_SECRET_PATTERN.search(line)
            or VCPKG_SECRET_JSON_PATTERN.search(line)
        ):
            findings.append(
                VcpkgFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in vcpkg config — use environment variables or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in vcpkg config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL — use HTTPS for downloads and registry URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
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
                VcpkgFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="dependency pinned to moving ref — pin to tag, commit SHA, or builtin-baseline",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in portfile — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
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
                VcpkgFinding(
                    kind="tls_verify_disabled",
                    severity="high",
                    message="TLS verification disabled — keep SSL verification enabled for downloads",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and (
            VCPKG_EXECUTE_PATTERN.search(line) or COMMAND_SHELL_PATTERN.search(line)
        ):
            findings.append(
                VcpkgFinding(
                    kind="dangerous_execute_command",
                    severity="high",
                    message="dangerous command in vcpkg_execute_required_process — review shell invocation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if COMMAND_SHELL_PATTERN.search(line) and file_kind == "portfile":
            findings.append(
                VcpkgFinding(
                    kind="dangerous_execute_command",
                    severity="high",
                    message="dangerous COMMAND sh -c in portfile — avoid piping remote scripts to shell",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VCPKG_DOWNLOAD_PATTERN.search(line) and not SHA512_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
                    kind="unverified_download",
                    severity="medium",
                    message="vcpkg_download_distfile without SHA512 — verify download integrity",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if (
            VCPKG_FROM_GITHUB_PATTERN.search(line) or VCPKG_FROM_GIT_PATTERN.search(line)
        ) and UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                VcpkgFinding(
                    kind="unpinned_git_clone",
                    severity="medium",
                    message="vcpkg_from_github/git with moving ref — pin REF to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[VcpkgFinding], VcpkgInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[VcpkgFinding] = []
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, VcpkgInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = VcpkgInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, file_kind, findings, info)

        return findings, info

    def analyze(self) -> list[VcpkgFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[VcpkgFinding] = []
        infos: list[VcpkgInfo] = []
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
        self._stats = VcpkgStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> VcpkgStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[VcpkgInfo]:
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
        """Scaffold a hardened vcpkg.json manifest with secure defaults."""
        return """\
{
  "name": "secure-demo",
  "version-string": "1.0.0",
  "dependencies": [
    "openssl"
  ],
  "builtin-baseline": "abcdef0123456789abcdef0123456789abcdef01",
  "vcpkg-configuration": {
    "default-registry": {
      "kind": "git",
      "repository": "https://github.com/microsoft/vcpkg",
      "baseline": "abcdef0123456789abcdef0123456789abcdef01"
    }
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Vcpkg configs: none found"
        return (
            f"Vcpkg configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Vcpkg analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(s)"
            )
            lines.append(f"      dependencies: {deps}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
