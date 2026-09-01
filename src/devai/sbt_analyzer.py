"""SbtAnalyzer — audit build.sbt, project/*.sbt, and .sbtopts for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SBT_MANIFEST_NAMES = ("build.sbt", "build.scala")
SBT_PROJECT_DIR = "project"
SBT_PROJECT_FILES = ("build.properties", "plugins.sbt")
SBT_OPTS_NAMES = (".sbtopts",)
SBT_CREDENTIALS_NAMES = ("credentials.sbt", ".credentials")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?|"
    r"Credentials\s*\(\s*[\"'][^\"']+[\"']\s*,\s*[\"'][^\"']+[\"']\s*,\s*"
    r"[\"'][^\"']+[\"']\s*,\s*[\"'][^\"'\s${}][^\"']*[\"']",
    re.IGNORECASE,
)
PUBLISH_CREDENTIALS_PATTERN = re.compile(
    r"publishCredentials\s*:=\s*Credentials\s*\(",
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
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:branch|rev|tag)\s*[=:]\s*[\"']?(?:main|master|HEAD|develop)[\"']?|"
    r"\.git#(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
LOOSE_VERSION_PATTERN = re.compile(
    r"%\s*[\"'](?:latest|LATEST|\*)[\"']|"
    r"version\s*:=\s*[\"'](?:latest|LATEST|\*)[\"']",
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
INSECURE_RESOLVER_PATTERN = re.compile(
    r"(?:resolvers\s*\+?=|Resolver\.url|mavenResolver|at\s+[\"']http://)",
    re.IGNORECASE,
)
INSECURE_PUBLISH_PATTERN = re.compile(
    r"publishTo\s*:=\s*.*http://(?!localhost|127\.0\.0\.1)",
    re.IGNORECASE,
)
DANGEROUS_TASK_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|Runtime\.getRuntime\(\)\.exec|"
    r"sys\.process\.|Process\s*\()",
    re.IGNORECASE,
)
DEP_PATTERN = re.compile(
    r'["\']([a-zA-Z0-9_.-]+)["\']\s*%\s*["\']([a-zA-Z0-9_.-]+)["\']',
)


@dataclass
class SbtFinding:
    """A security or best-practice issue in an sbt configuration file."""

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
class SbtInfo:
    """Parsed metadata about an sbt configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    resolvers: list[str] = field(default_factory=list)


@dataclass
class SbtStats:
    """Aggregate sbt analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_sbt_file(path: Path) -> bool:
    """Return True if the path looks like an sbt configuration file."""
    name = path.name
    if name in SBT_MANIFEST_NAMES or name in SBT_OPTS_NAMES:
        return True
    if name in SBT_CREDENTIALS_NAMES:
        return True
    if path.parent.name == SBT_PROJECT_DIR:
        if name in SBT_PROJECT_FILES or name.endswith(".sbt"):
            return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in SBT_MANIFEST_NAMES:
        return "manifest"
    if name == "build.properties":
        return "build_properties"
    if name == "plugins.sbt":
        return "plugins"
    if name in SBT_OPTS_NAMES:
        return "sbtopts"
    if name in SBT_CREDENTIALS_NAMES:
        return "credentials"
    if path.parent.name == SBT_PROJECT_DIR and name.endswith(".sbt"):
        return "project_sbt"
    return "unknown"


class SbtAnalyzer:
    """Audit sbt configuration for security issues.

    Scans build.sbt, project/*.sbt, .sbtopts, and credentials files for
    hardcoded publish credentials, insecure HTTP resolvers, credentials in git
    sources, unpinned git dependencies, loose version constraints, dangerous
    shell tasks, and sensitive path references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SbtFinding] | None = None
        self._stats: SbtStats | None = None
        self._infos: list[SbtInfo] | None = None

    def configs(self) -> list[Path]:
        """Return sbt configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_sbt_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[SbtFinding],
        info: SbtInfo,
        *,
        is_credentials: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

        dep_match = DEP_PATTERN.search(stripped)
        if dep_match:
            info.dependencies.append(f"{dep_match.group(1)}:{dep_match.group(2)}")

        resolver_match = re.search(
            r'(?:at|from)\s+["\']([^"\']+)["\']',
            stripped,
            re.IGNORECASE,
        )
        if resolver_match:
            info.resolvers.append(resolver_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line) or (
            is_credentials and re.search(r"pass(word|wd)\s*=", line, re.IGNORECASE)
        ):
            findings.append(
                SbtFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in sbt config — use env vars or ~/.sbt/.credentials",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PUBLISH_CREDENTIALS_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="publish_credentials",
                    severity="high",
                    message="publishCredentials in build file — use credentials.sbt in .gitignore or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in sbt config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line) or INSECURE_RESOLVER_PATTERN.search(line):
            if "http://" in line.lower():
                findings.append(
                    SbtFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP resolver or URL — use HTTPS for Maven/Ivy repositories",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if INSECURE_PUBLISH_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="insecure_publish",
                    severity="high",
                    message="publishTo uses HTTP — use HTTPS artifact repositories",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in git source URL — use SSH keys or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_DEP_UNPINNED_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="unpinned_git_dep",
                    severity="medium",
                    message="git dependency may be unpinned — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOOSE_VERSION_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="loose_version",
                    severity="low",
                    message="dependency without pinned version — specify explicit version",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in sbt config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                SbtFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid embedding credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_TASK_PATTERN.search(line) and (
            "task" in stripped.lower() or "command" in stripped.lower() or is_credentials
        ):
            findings.append(
                SbtFinding(
                    kind="dangerous_task",
                    severity="high",
                    message="dangerous shell command in sbt task — review sys.process and exec usage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[SbtFinding], SbtInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[SbtFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, SbtInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = SbtInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        is_credentials = path.name in SBT_CREDENTIALS_NAMES

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                is_credentials=is_credentials,
            )

        return findings, info

    def analyze(self) -> list[SbtFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SbtFinding] = []
        infos: list[SbtInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        manifest_dirs = {
            p.parent for p in paths if p.name in SBT_MANIFEST_NAMES
        }
        self._findings = findings
        self._infos = infos
        self._stats = SbtStats(
            configs=len(manifest_dirs),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SbtStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SbtInfo]:
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
        """Scaffold a hardened build.sbt snippet with secure defaults."""
        return """\
ThisBuild / scalaVersion := "2.13.14"
ThisBuild / version := "0.1.0-SNAPSHOT"

lazy val root = (project in file("."))
  .settings(
    name := "my-app",
  )

// Use HTTPS resolvers only
// resolvers += "Secure Repo" at "https://repo.example.com/maven"

// Store publish credentials in ~/.sbt/.credentials (gitignored) — never hardcode
// publishTo := Some("releases" at "https://repo.example.com/releases")

// Pin git deps to tags or commits — never use branch = "master"
// libraryDependencies += "com.example" % "lib" % "1.0.0"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "sbt configs: none found"
        return (
            f"sbt configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "sbt analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            resolvers = ", ".join(info.resolvers[:4]) if info.resolvers else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dep(s), {len(info.resolvers)} resolver(s)"
            )
            lines.append(f"    deps: {deps}")
            lines.append(f"    resolvers: {resolvers}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
