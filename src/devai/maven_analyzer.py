"""MavenAnalyzer — audit Maven pom.xml and settings.xml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAVEN_POM_NAMES = ("pom.xml",)
MAVEN_SETTINGS_NAMES = ("settings.xml",)
MAVEN_CONFIG_NAMES = (".mvn/maven.config", "maven.config")
MAVEN_MARKER_PATTERN = re.compile(
    r"(?:<project\b|<modelVersion>|<groupId>|<artifactId>|<dependencies>|"
    r"<repositories>|<distributionManagement>|<build>|<plugins>)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|passphrase)\s*>[^<\s][^<]*<",
    re.IGNORECASE,
)
HARDCODED_SECRET_ATTR_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*=\s*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"<version>\s*(?:LATEST|RELEASE|\+|\[|\()\s*[^<]*</version>|"
    r"<version>\s*\$\{[^}]+\.version\}\s*</version>",
    re.IGNORECASE,
)
LOOSE_VERSION_PATTERN = re.compile(
    r"<version>\s*(?:LATEST|RELEASE)\s*</version>",
    re.IGNORECASE,
)
SNAPSHOT_VERSION_PATTERN = re.compile(
    r"<version>\s*[^<]*-SNAPSHOT\s*</version>",
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
INSECURE_SSL_PATTERN = re.compile(
    r"(?:trustAllCertificates|disableHostnameVerification|"
    r"insecureSkipTlsVerify|maven\.wagon\.http\.ssl\.insecure|"
    r"ssl\.verify\s*=\s*false)",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:scm\.git|git@|git\+https?://)[^\s\"'<>]+",
    re.IGNORECASE,
)
EXEC_PLUGIN_PATTERN = re.compile(
    r"<artifactId>\s*exec-maven-plugin\s*</artifactId>",
    re.IGNORECASE,
)
DISTRIBUTION_HTTP_PATTERN = re.compile(
    r"<distributionManagement>[\s\S]*?<url>\s*http://",
    re.IGNORECASE,
)


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
    group_id: str = ""
    artifact_id: str = ""
    dependencies: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)


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
    rel_parts = path.parts
    if name in MAVEN_POM_NAMES or name in MAVEN_SETTINGS_NAMES:
        return True
    if name == "maven.config" and (".mvn" in rel_parts or name == "maven.config"):
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
    if name == "pom.xml":
        return "pom"
    if name == "settings.xml":
        return "settings"
    if name == "maven.config":
        return "config"
    return "unknown"


class MavenAnalyzer:
    """Audit Maven pom.xml and settings.xml for security issues.

    Scans pom.xml, settings.xml, and maven.config for hardcoded secrets,
    insecure HTTP repositories, dynamic dependency versions, snapshot
    dependencies in release builds, distributionManagement over HTTP,
    curl-pipe-to-shell in exec-maven-plugin, and SSL verification bypass.
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

        group_match = re.search(r"<groupId>\s*([^<]+)\s*</groupId>", text)
        if group_match:
            info.group_id = group_match.group(1).strip()
        artifact_match = re.search(r"<artifactId>\s*([^<]+)\s*</artifactId>", text)
        if artifact_match:
            info.artifact_id = artifact_match.group(1).strip()

        for dep_match in re.finditer(
            r"<dependency>[\s\S]*?<artifactId>\s*([^<]+)\s*</artifactId>",
            text,
        ):
            info.dependencies.append(dep_match.group(1).strip())

        for plugin_match in re.finditer(
            r"<plugin>[\s\S]*?<artifactId>\s*([^<]+)\s*</artifactId>",
            text,
        ):
            info.plugins.append(plugin_match.group(1).strip())

        if DISTRIBUTION_HTTP_PATTERN.search(text):
            findings.append(
                MavenFinding(
                    kind="insecure_distribution",
                    severity="high",
                    message="distributionManagement over HTTP — use HTTPS artifact repositories",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("<!--"):
                continue

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_SECRET_ATTR_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Maven config — use settings.xml server credentials or CI secrets",
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

            if LOOSE_VERSION_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="LATEST or RELEASE dependency version — pin to exact release",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif DYNAMIC_VERSION_PATTERN.search(line) and "SNAPSHOT" not in line.upper():
                findings.append(
                    MavenFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="dynamic or range dependency version — pin to exact release",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SNAPSHOT_VERSION_PATTERN.search(line) and info.file_kind == "pom":
                findings.append(
                    MavenFinding(
                        kind="snapshot_dependency",
                        severity="low",
                        message="SNAPSHOT dependency — prefer pinned release versions for reproducible builds",
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
                        message="curl/wget piped to shell in Maven config — vendor scripts with checksum verification",
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

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git+" in line.lower() or "git@" in line.lower() or "scm.git" in line.lower()
            ):
                if not re.search(r"(?:tag|commit|revision)\s*>", text, re.IGNORECASE):
                    findings.append(
                        MavenFinding(
                            kind="unpinned_git_source",
                            severity="medium",
                            message="git SCM URL without tag/commit pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if EXEC_PLUGIN_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="exec_plugin",
                        severity="low",
                        message="exec-maven-plugin detected — review shell commands for injection and secret exposure",
                        path=rel,
                        lineno=lineno,
                        line=line,
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
        """Scaffold a hardened settings.xml snippet with HTTPS repos."""
        return """\
<!-- Use HTTPS repositories only; store credentials in ~/.m2/settings.xml server entries -->
<settings>
  <mirrors>
    <mirror>
      <id>central-https</id>
      <mirrorOf>*</mirrorOf>
      <url>https://repo.maven.apache.org/maven2</url>
    </mirror>
  </mirrors>
  <profiles>
    <profile>
      <id>hardened</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo.maven.apache.org/maven2</url>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>hardened</activeProfile>
  </activeProfiles>
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
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            plugins = ", ".join(info.plugins[:8]) if info.plugins else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{info.group_id or '?'}:{info.artifact_id or '?'}, "
                f"{len(info.dependencies)} dep(s), {len(info.plugins)} plugin(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    plugins: {plugins}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
