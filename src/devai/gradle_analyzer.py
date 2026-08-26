"""GradleAnalyzer — audit Gradle build files for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GRADLE_BUILD_NAMES = ("build.gradle", "build.gradle.kts")
GRADLE_SETTINGS_NAMES = ("settings.gradle", "settings.gradle.kts")
GRADLE_PROPERTIES_NAMES = ("gradle.properties",)
GRADLE_VERSION_CATALOG_NAMES = ("libs.versions.toml")
GRADLE_MARKER_PATTERN = re.compile(
    r"(?:^\s*(?:plugins|dependencies|repositories|android|java|kotlin|"
    r"implementation|api|compile|testImplementation|maven|gradle)\b|"
    r"^\s*\[versions\]|\[libraries\]|\[plugins\])",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|storePassword|keyPassword|signingKey)\s*[=:]\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
ALLOW_INSECURE_PROTOCOL_PATTERN = re.compile(
    r"allowInsecureProtocol\s*=\s*true",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"(?:version|classpath)\s*[=:]\s*[\"'](?:\+|latest|LATEST|RELEASE|\d+\.\+)[\"']|"
    r"[\"'][\w.-]+:[\w.-]+:(?:\+|latest|LATEST|RELEASE)[\"']",
    re.IGNORECASE,
)
LOOSE_VERSION_PATTERN = re.compile(
    r"[\"'](?:\+|latest|LATEST|RELEASE)[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged\s*=\s*true|runAsRoot\s*=\s*true|"
    r"\"--privileged\"|'--privileged')",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:trustAllCertificates|disableHostnameVerification|"
    r"insecureSkipTlsVerify|ssl\.verify\s*=\s*false|"
    r"checkServerIdentity\s*=\s*false)",
    re.IGNORECASE,
)
MAVEN_REPO_HTTP_PATTERN = re.compile(
    r"(?:maven\s*\{|url\s*[=:]\s*[\"']http://)",
    re.IGNORECASE,
)
SIGNING_KEY_INLINE_PATTERN = re.compile(
    r"(?:signingKey|storeFile)\s*[=:]\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git\+https?://|git@)[^\s\"']+(?![^\n]*(?:commit|rev|tag)\s*[=:])",
    re.IGNORECASE,
)


@dataclass
class GradleFinding:
    """A security or best-practice issue in a Gradle configuration file."""

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
class GradleInfo:
    """Parsed metadata about a Gradle configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    plugins: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)


@dataclass
class GradleStats:
    """Aggregate Gradle analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_gradle_file(path: Path) -> bool:
    """Return True if the path looks like a Gradle configuration file."""
    name = path.name
    if (
        name in GRADLE_BUILD_NAMES
        or name in GRADLE_SETTINGS_NAMES
        or name in GRADLE_PROPERTIES_NAMES
        or name in GRADLE_VERSION_CATALOG_NAMES
    ):
        return True
    if name.endswith(".gradle") or name.endswith(".gradle.kts"):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if GRADLE_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in GRADLE_BUILD_NAMES:
        return "build"
    if name in GRADLE_SETTINGS_NAMES:
        return "settings"
    if name in GRADLE_PROPERTIES_NAMES:
        return "properties"
    if name in GRADLE_VERSION_CATALOG_NAMES:
        return "version_catalog"
    if name.endswith(".gradle.kts"):
        return "build_kts"
    if name.endswith(".gradle"):
        return "gradle"
    return "unknown"


class GradleAnalyzer:
    """Audit Gradle build files for security issues.

    Scans build.gradle(.kts), settings.gradle(.kts), gradle.properties, and
  libs.versions.toml for hardcoded secrets, insecure Maven repositories,
    allowInsecureProtocol, dynamic dependency versions, signing keys in plain
    text, curl-pipe-to-shell in exec tasks, and privileged container settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GradleFinding] | None = None
        self._stats: GradleStats | None = None
        self._infos: list[GradleInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Gradle configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_gradle_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[GradleFinding], GradleInfo]:
        findings: list[GradleFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GradleInfo(path=rel)

        raw_lines = text.splitlines()
        info = GradleInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            plugin_match = re.search(
                r"(?:id\s*[=:]\s*[\"']([^\"']+)[\"']|plugin\s*\(\s*[\"']([^\"']+)[\"'])",
                stripped,
            )
            if plugin_match:
                plugin = plugin_match.group(1) or plugin_match.group(2)
                if plugin:
                    info.plugins.append(plugin)

            dep_match = re.search(
                r"(?:implementation|api|compile|testImplementation|runtimeOnly|"
                r"classpath)\s*[\(:]\s*[\"']([^\"']+)[\"']",
                stripped,
            )
            if dep_match:
                info.dependencies.append(dep_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Gradle config — use gradle.properties or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Gradle config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for repositories and dependencies",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALLOW_INSECURE_PROTOCOL_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="allow_insecure_protocol",
                        severity="high",
                        message="allowInsecureProtocol enabled — require HTTPS for Maven repositories",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(line) or (
                LOOSE_VERSION_PATTERN.search(line) and "version" in line.lower()
            ):
                findings.append(
                    GradleFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="dynamic or unpinned dependency version — pin to exact release",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if MAVEN_REPO_HTTP_PATTERN.search(line) and INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="insecure_maven_repo",
                        severity="medium",
                        message="Maven repository over HTTP — use HTTPS mirrors",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in Gradle task — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SIGNING_KEY_INLINE_PATTERN.search(line) and HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    GradleFinding(
                        kind="inline_signing_key",
                        severity="high",
                        message="signing key or store path with inline secret — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    GradleFinding(
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
                    GradleFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock reference — avoid host Docker socket in Gradle tasks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git+" in line.lower() or "git@" in line.lower()
            ):
                findings.append(
                    GradleFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="git URL without commit pin — pin to immutable revision",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[GradleFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GradleFinding] = []
        infos: list[GradleInfo] = []
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
        self._stats = GradleStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GradleStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GradleInfo]:
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
        """Scaffold a hardened gradle.properties with HTTPS repos and pinned versions."""
        return """\
# Use HTTPS Maven repositories only
systemProp.org.gradle.internal.http.connectionTimeout=120000
systemProp.org.gradle.internal.http.socketTimeout=120000

# Enable dependency verification and build cache
org.gradle.caching=true
org.gradle.parallel=true

# Never store signing secrets here — use environment variables or CI secret stores
# signing.keyId=
# signing.password=
# signing.secretKeyRingFile=
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Gradle configs: none found"
        return (
            f"Gradle configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Gradle analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            plugins = ", ".join(info.plugins[:8]) if info.plugins else "none"
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.plugins)} plugin(s), {len(info.dependencies)} dep(s)"
            )
            lines.append(f"    plugins: {plugins}")
            lines.append(f"    dependencies: {deps}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
