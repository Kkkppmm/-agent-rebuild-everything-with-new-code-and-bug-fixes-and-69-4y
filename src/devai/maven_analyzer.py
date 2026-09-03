"""MavenAnalyzer — audit Maven pom.xml and settings.xml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAVEN_POM_NAMES = ("pom.xml",)
MAVEN_SETTINGS_NAMES = ("settings.xml",)
MAVEN_CONFIG_NAMES = ("maven.config", "jvm.config", "extensions.xml")
MAVEN_WRAPPER_NAMES = ("maven-wrapper.properties",)
MAVEN_MARKER_PATTERN = re.compile(
    r"(?:<project\b|<settings\b|<mirrors>|<repositories>|<pluginRepositories>|"
    r"<distributionManagement>|<dependencyManagement>|<build>|<profiles>)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|passphrase)\s*[=:>]\s*"
    r"[\"']?[^\"'\s<${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
XML_PASSWORD_TAG_PATTERN = re.compile(
    r"<(?:password|passphrase|secret)>\s*[^<\s][^<]*</(?:password|passphrase|secret)>",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"<version>\s*(?:LATEST|RELEASE|\+|\d+\.\+)\s*</version>|"
    r"<version>\s*\[[^\]]*,\)\s*</version>|"
    r"<version>\s*\(\s*,[^\]]*\]\s*</version>",
    re.IGNORECASE,
)
LOOSE_VERSION_PROPERTY_PATTERN = re.compile(
    r"<(?:[^>]+Version)>\s*(?:LATEST|RELEASE|\+)\s*</",
    re.IGNORECASE,
)
ALLOW_INSECURE_PROTOCOL_PATTERN = re.compile(
    r"<allowInsecureProtocol>\s*true\s*</allowInsecureProtocol>",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:maven\.wagon\.http\.ssl\.(?:insecure|allowall)\s*=\s*true|"
    r"<maven\.wagon\.http\.ssl\.(?:insecure|allowall)>\s*true\s*</maven\.wagon\.http\.ssl\.(?:insecure|allowall)>|"
    r"trustAllCertificates|disableHostnameVerification|"
    r"insecureSkipTlsVerify|ssl\.verify\s*=\s*false)",
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
SCM_CREDENTIALS_PATTERN = re.compile(
    r"scm:[^\s]*://[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
SNAPSHOT_ENABLED_PATTERN = re.compile(
    r"<snapshots>\s*<enabled>\s*true\s*</enabled>",
    re.IGNORECASE,
)
EXEC_PLUGIN_PATTERN = re.compile(r"<artifactId>\s*exec-maven-plugin\s*</artifactId>", re.IGNORECASE)
WILDCARD_MIRROR_PATTERN = re.compile(
    r"<mirrorOf>\s*\*\s*</mirrorOf>",
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
    artifacts: list[str] = field(default_factory=list)
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
    if name in MAVEN_POM_NAMES or name in MAVEN_SETTINGS_NAMES:
        return True
    if name in MAVEN_CONFIG_NAMES or name in MAVEN_WRAPPER_NAMES:
        return True
    if ".mvn" in path.parts and name.endswith((".xml", ".config", ".properties")):
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
        return "maven_config"
    if name == "jvm.config":
        return "jvm_config"
    if name == "extensions.xml":
        return "extensions"
    if name == "maven-wrapper.properties":
        return "wrapper"
    return "unknown"


class MavenAnalyzer:
    """Audit Maven pom.xml and settings.xml for security issues.

    Scans pom.xml, settings.xml, .mvn/maven.config, and wrapper properties for
    hardcoded secrets, insecure HTTP repositories, unpinned dependency versions,
    allowInsecureProtocol, SCM credentials in URLs, wildcard mirrors, and
    curl-pipe-to-shell in exec-maven-plugin configurations.
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
        has_exec_plugin = EXEC_PLUGIN_PATTERN.search(text) is not None

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("<!--") or stripped.startswith("#"):
                continue

            artifact_match = re.search(
                r"<artifactId>\s*([^<]+)\s*</artifactId>",
                stripped,
            )
            if artifact_match:
                artifact = artifact_match.group(1).strip()
                if artifact.endswith("-plugin"):
                    info.plugins.append(artifact)
                else:
                    info.artifacts.append(artifact)

            if HARDCODED_SECRET_PATTERN.search(line) or XML_PASSWORD_TAG_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Maven config — use settings.xml server credentials or CI secret stores",
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

            if INSECURE_HTTP_PATTERN.search(line) and not re.search(
                r"(?:xmlns|schemaLocation|xsi)=", line, re.IGNORECASE
            ):
                findings.append(
                    MavenFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for repositories and distribution endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALLOW_INSECURE_PROTOCOL_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="allow_insecure_protocol",
                        severity="high",
                        message="allowInsecureProtocol enabled — require HTTPS for Maven repositories",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DYNAMIC_VERSION_PATTERN.search(line) or LOOSE_VERSION_PROPERTY_PATTERN.search(line):
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

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in SCM URL — use SSH keys or CI credential helpers",
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

            if has_exec_plugin and CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="exec_plugin_shell",
                        severity="high",
                        message="exec-maven-plugin runs curl-pipe-to-shell — avoid remote script execution in builds",
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

            if WILDCARD_MIRROR_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="wildcard_mirror",
                        severity="medium",
                        message="wildcard mirrorOf (*) — scope mirrors narrowly to avoid dependency hijacking",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SNAPSHOT_ENABLED_PATTERN.search(line) and INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    MavenFinding(
                        kind="insecure_snapshot_repo",
                        severity="medium",
                        message="snapshot repository over HTTP — use HTTPS for snapshot deployments",
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
        """Scaffold a hardened settings.xml snippet with HTTPS repos and pinned versions."""
        return """\
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <!-- Use HTTPS mirrors only; scope mirrorOf narrowly -->
  <mirrors>
    <mirror>
      <id>central-https</id>
      <mirrorOf>central</mirrorOf>
      <url>https://repo.maven.apache.org/maven2</url>
    </mirror>
  </mirrors>

  <!-- Store server credentials in ~/.m2/settings-security.xml or CI secret stores -->
  <!-- Never commit plaintext passwords in settings.xml -->
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
            artifacts = ", ".join(info.artifacts[:8]) if info.artifacts else "none"
            plugins = ", ".join(info.plugins[:8]) if info.plugins else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.artifacts)} artifact(s), {len(info.plugins)} plugin(s)"
            )
            lines.append(f"    artifacts: {artifacts}")
            lines.append(f"    plugins: {plugins}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
