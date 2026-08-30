"""BuckAnalyzer — audit Buck BUCK files and .buckconfig for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUCK_FILE_NAMES = ("BUCK",)
BUCK_CONFIG_NAMES = (".buckconfig", ".buckconfig.local")
BUCK_VERSION_NAMES = (".buckversion",)
BUCK_MARKER_PATTERN = re.compile(
    r"(?:^\s*(?:load|python_library|cxx_binary|java_library|go_binary|genrule|"
    r"remote_file|prebuilt_jar|maven_jar|android_binary|sh_binary|http_archive)\b|"
    r"^\s*\[(?:download|maven|http|cache|build)\])",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*=\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
REMOTE_FILE_PATTERN = re.compile(r"remote_file\s*\(", re.IGNORECASE)
SHA_PATTERN = re.compile(r"(?:sha1|sha256|sha512)\s*=", re.IGNORECASE)
HTTP_ARCHIVE_PATTERN = re.compile(r"http_archive\s*\(", re.IGNORECASE)
MAVEN_JAR_PATTERN = re.compile(r"maven_jar\s*\(", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
GENRULE_PATTERN = re.compile(r"genrule\s*\(", re.IGNORECASE)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged\s*=\s*True|run_as_root\s*=\s*True|"
    r"\"--privileged\"|'--privileged')",
    re.IGNORECASE,
)
INSECURE_DOWNLOAD_PATTERN = re.compile(
    r"(?:download\.insecure|ssl\.verify\s*=\s*false|trust_all_certs\s*=\s*true)",
    re.IGNORECASE,
)
LOOSE_BUCK_VERSION_PATTERN = re.compile(
    r"^\s*(?:latest|\*|>=|~=)",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git\+https?://|git@)[^\s\"']+(?![^\n]*(?:commit|rev|tag)\s*=)",
    re.IGNORECASE,
)
CACHE_DISABLE_PATTERN = re.compile(
    r"(?:cache\.mode\s*=\s*none|buck\.cache\.mode\s*=\s*none|disable_cache\s*=\s*True)",
    re.IGNORECASE,
)


@dataclass
class BuckFinding:
    """A security or best-practice issue in a Buck configuration file."""

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
class BuckInfo:
    """Parsed metadata about a Buck configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    rules: list[str] = field(default_factory=list)
    loads: list[str] = field(default_factory=list)


@dataclass
class BuckStats:
    """Aggregate Buck analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_buck_file(path: Path) -> bool:
    """Return True if the path looks like a Buck configuration file."""
    name = path.name
    if name in BUCK_FILE_NAMES or name in BUCK_CONFIG_NAMES or name in BUCK_VERSION_NAMES:
        return True
    if name.endswith(".buck") or name == "DEFS":
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if BUCK_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in BUCK_FILE_NAMES:
        return "buck"
    if name in BUCK_CONFIG_NAMES:
        return "buckconfig"
    if name in BUCK_VERSION_NAMES:
        return "buckversion"
    if name == "DEFS":
        return "defs"
    if name.endswith(".buck"):
        return "buck"
    return "unknown"


class BuckAnalyzer:
    """Audit Buck BUCK files and .buckconfig for security issues.

    Scans for hardcoded secrets, unpinned remote_file/http_archive rules, insecure
    Maven/download settings, curl-pipe-to-shell in genrules, privileged container
    settings, sensitive path references, and disabled build caches.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BuckFinding] | None = None
        self._stats: BuckStats | None = None
        self._infos: list[BuckInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Buck configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_buck_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[BuckFinding], BuckInfo]:
        findings: list[BuckFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BuckInfo(path=rel)

        raw_lines = text.splitlines()
        info = BuckInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            load_match = re.match(r"load\s*\(\s*[\"']([^\"']+)[\"']", stripped)
            if load_match:
                info.loads.append(load_match.group(1))

            rule_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", stripped)
            if rule_match and rule_match.group(1) not in ("load", "if", "for", "def"):
                info.rules.append(rule_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Buck config — use buckconfig user overrides or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Buck config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for external dependencies",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if REMOTE_FILE_PATTERN.search(line):
                block = self._extract_rule_block(raw_lines, lineno - 1)
                if not SHA_PATTERN.search(block):
                    findings.append(
                        BuckFinding(
                            kind="remote_file_no_checksum",
                            severity="high",
                            message="remote_file without sha1/sha256 — pin with checksum verification",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if HTTP_ARCHIVE_PATTERN.search(line):
                block = self._extract_rule_block(raw_lines, lineno - 1)
                if not SHA_PATTERN.search(block):
                    findings.append(
                        BuckFinding(
                            kind="http_archive_no_checksum",
                            severity="high",
                            message="http_archive without checksum — pin with sha1/sha256 verification",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if MAVEN_JAR_PATTERN.search(line) and INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="insecure_maven_repo",
                        severity="medium",
                        message="maven_jar with insecure HTTP repository — use HTTPS Maven mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in genrule — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GENRULE_PATTERN.search(line):
                block = self._extract_rule_block(raw_lines, lineno - 1)
                if SENSITIVE_PATH_PATTERN.search(block):
                    findings.append(
                        BuckFinding(
                            kind="sensitive_path_in_genrule",
                            severity="high",
                            message="genrule references sensitive host path — avoid bundling credentials",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if INSECURE_DOWNLOAD_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="insecure_download",
                        severity="high",
                        message="download SSL verification disabled — keep TLS verification enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CACHE_DISABLE_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="cache_disabled",
                        severity="low",
                        message="build cache disabled globally — caching improves reproducibility and auditability",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged or root container settings — disable privileged builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    BuckFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock reference — avoid host Docker socket in Buck rules",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git+" in line.lower() or "git@" in line.lower()
            ):
                findings.append(
                    BuckFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="git URL without commit pin — pin to immutable revision",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if info.file_kind == "buckversion" and LOOSE_BUCK_VERSION_PATTERN.match(stripped):
                findings.append(
                    BuckFinding(
                        kind="unpinned_buck_version",
                        severity="medium",
                        message="loose Buck version constraint — pin to an exact release in .buckversion",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def _extract_rule_block(self, lines: list[str], start: int) -> str:
        """Return text from a rule opening line through its closing parenthesis."""
        depth = 0
        parts: list[str] = []
        for line in lines[start:]:
            parts.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0 and "(" in line:
                break
        return "\n".join(parts)

    def analyze(self) -> list[BuckFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BuckFinding] = []
        infos: list[BuckInfo] = []
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
        self._stats = BuckStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BuckStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BuckInfo]:
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
        """Scaffold a hardened .buckconfig with HTTPS Maven and pinned downloads."""
        return """\
[download]
# Keep TLS verification enabled (default). Never set download.insecure = true.

[maven]
# Use HTTPS Maven mirrors only
repositories = central=https://repo1.maven.org/maven2

[cache]
mode = dir
dir_max_size = 5G

[build]
# Pin toolchains and keep reproducible builds enabled
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Buck configs: none found"
        return (
            f"Buck configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Buck analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            rules = ", ".join(info.rules[:8]) if info.rules else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): {len(info.rules)} rule(s), "
                f"{len(info.loads)} load(s)"
            )
            lines.append(f"    rules: {rules}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
