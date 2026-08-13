"""MavenAnalyzer — audit Maven pom.xml and settings.xml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

POM_NAMES = ("pom.xml",)
SETTINGS_NAMES = ("settings.xml",)
MVN_CONFIG_NAMES = ("maven.config", "jvm.config", "extensions.xml")
MAVEN_MARKER_PATTERN = re.compile(
    r"(?:<\s*(?:project|modelVersion|groupId|artifactId|version|dependency|"
    r"plugin|repository|distributionManagement|server|settings|profile|"
    r"properties|parent|build|modules)\b|"
    r"^\s*(?:-D|--add-opens))",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|passphrase|gpg\.passphrase)\s*[=:>]\s*"
    r"[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
XML_SECRET_PATTERN = re.compile(
    r"<(?:password|passphrase|secret|token|privateKey|clientSecret)>"
    r"[^<\s${}][^<]*</(?:password|passphrase|secret|token|privateKey|clientSecret)>",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"(?:<version>|version\s*[=:]\s*)[\"']?(?:LATEST|RELEASE|\+|\$\{revision\}|\$\{changelist\})[\"']?|"
    r"[\"'][\w.-]+:[\w.-]+:(?:LATEST|RELEASE|\+)[\"']",
    re.IGNORECASE,
)
SNAPSHOT_VERSION_PATTERN = re.compile(
    r"<version>\s*[^<]*-SNAPSHOT\s*</version>",
    re.IGNORECASE,
)
LOOSE_VERSION_PATTERN = re.compile(
    r"(?:<version>|version\s*[=:]\s*)[\"']?(?:LATEST|RELEASE|\+)[\"']?",
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
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|\.m2/settings-security\.xml)",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:trustAllCertificates|disableHostnameVerification|"
    r"maven\.wagon\.http\.ssl\.insecure|maven\.wagon\.http\.ssl\.allowall|"
    r"ssl\.verify\s*=\s*false|checkServerIdentity\s*=\s*false)",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"<plugin>\s*<groupId>[^<]+</groupId>\s*<artifactId>[^<]+</artifactId>\s*</plugin>",
    re.IGNORECASE | re.DOTALL,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:scm\.connection|scm\.developerConnection|connection)\s*>?\s*"
    r"scm:(?:git|svn):[^\s<]+(?![^\n]*(?:commit|revision|tag))",
    re.IGNORECASE,
)
SIGNING_KEY_INLINE_PATTERN = re.compile(
    r"(?:gpg\.keyname|gpg\.passphrase|signing\.key|signing\.password)\s*[=:>]\s*"
    r"[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
SERVER_CREDENTIAL_PATTERN = re.compile(
    r"<server>\s*<id>[^<]+</id>\s*<(?:username|password)>",
    re.IGNORECASE | re.DOTALL,
)
EXEC_PLUGIN_PATTERN = re.compile(r"maven-exec-plugin|exec-maven-plugin", re.IGNORECASE)


@dataclass
class MavenFinding:
    """A security or best-practice issue in a Maven configuration file."""

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
class MavenInfo:
    """Parsed metadata about a Maven configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    plugins: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)


@dataclass
class MavenStats:
    """Aggregate Maven analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_maven_file(path: Path) -> bool:
    """Return True if the path looks like a Maven configuration file."""
    name = path.name
    if name in POM_NAMES or name in SETTINGS_NAMES or name in MVN_CONFIG_NAMES:
        return True
    if path.parent.name == ".mvn" and name.endswith((".config", ".xml")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if MAVEN_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in POM_NAMES:
        return "pom"
    if name in SETTINGS_NAMES:
        return "settings"
    if name == "maven.config":
        return "maven_config"
    if name == "jvm.config":
        return "jvm_config"
    if name == "extensions.xml":
        return "extensions"
    if path.parent.name == ".mvn":
        return "mvn"
    return "unknown"


class MavenAnalyzer:
    """Audit Maven pom.xml and settings.xml for security issues.

    Scans pom.xml, settings.xml, and .mvn/* configs for hardcoded secrets,
    insecure HTTP repositories, dynamic dependency versions, SNAPSHOT releases,
    server credentials in settings.xml, GPG signing keys in plain text,
    curl-pipe-to-shell in exec plugins, and insecure SSL wagon settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MavenFinding] | None = None
        self._stats: MavenStats | None = None
        self._infos: list[MavenInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Maven configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_maven_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[MavenFinding], MavenInfo]:
        findings: list[MavenFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, MavenInfo(path=rel)

        raw_lines = text.splitlines()
        info = MavenInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("<!--") or stripped.startswith("//"):
                continue

            plugin_match = re.search(
                r"<artifactId>\s*([^<]+)\s*</artifactId>",
                stripped,
            )
            if plugin_match and (
                "plugin" in stripped.lower()
                or (lineno > 1 and "plugin" in raw_lines[lineno - 2].lower())
            ):
                plugin = plugin_match.group(1).strip()
                if plugin and plugin not in info.plugins:
                    info.plugins.append(plugin)

            dep_match = re.search(
                r"<dependency>.*?<artifactId>\s*([^<]+)\s*</artifactId>",
                stripped,
            )
            if dep_match:
                dep = dep_match.group(1).strip()
                if dep:
                    info.dependencies.append(dep)

            if HARDCODED_SECRET_PATTERN.search(line) or XML_SECRET_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Maven config — use settings-security.xml or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Maven config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for repositories and distribution",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOOSE_VERSION_PATTERN.search(line) or DYNAMIC_VERSION_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="dynamic or unpinned dependency version — pin to exact release",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SNAPSHOT_VERSION_PATTERN.search(line) and "distributionManagement" not in line:
                findings.append(
                    MavenFinding(
                        kind="snapshot_version",
                        severity="low",
                        message="SNAPSHOT version in dependency — prefer pinned release artifacts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in Maven exec — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    MavenFinding(
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
                    MavenFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SIGNING_KEY_INLINE_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="inline_signing_key",
                        severity="high",
                        message="GPG signing key or passphrase inline — use environment variables or CI secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SERVER_CREDENTIAL_PATTERN.search(line) and XML_SECRET_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="server_credential",
                        severity="high",
                        message="server credentials in settings.xml — use settings-security.xml encryption",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    MavenFinding(
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
                    MavenFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock reference — avoid host Docker socket in Maven plugins",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="SCM connection without pinned revision — pin to immutable tag or commit",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if UNPINNED_PLUGIN_PATTERN.search(text):
            findings.append(
                MavenFinding(
                    kind="unpinned_plugin",
                    severity="medium",
                    message="plugin without version — pin plugin versions in pluginManagement",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[MavenFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MavenFinding] = []
        infos: list[MavenInfo] = []
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
        self._stats = MavenStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MavenStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MavenInfo]:
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
        """Scaffold a hardened settings.xml snippet with HTTPS repos and pinned versions."""
        return """\
<!-- Use HTTPS Maven repositories only -->
<settings>
  <mirrors>
    <mirror>
      <id>central-https</id>
      <mirrorOf>central</mirrorOf>
      <url>https://repo.maven.apache.org/maven2</url>
    </mirror>
  </mirrors>
  <!-- Never store passwords here — use settings-security.xml encryption -->
  <!-- <servers><server><id>deploy</id><username>...</username><password>...</password></server></servers> -->
</settings>
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Maven configs: none found"
        return (
            f"Maven configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Maven analysis:",
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
