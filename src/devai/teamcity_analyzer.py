"""TeamCityAnalyzer — audit TeamCity pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TEAMCITY_FILENAMES = (
    "settings.kts",
    "teamcity-settings.xml",
    "pom.xml",
)
TEAMCITY_DIRS = (".teamcity", "teamcity", "ci/teamcity")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*[=:]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_KOTLIN_SECRET_PATTERN = re.compile(
    r"(?:password|token|privateKey|accessToken|clientSecret)\s*=\s*"
    r"[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|docker|imageName)\s*[=:]\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged|privilegedMode)\s*[=:]\s*true\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"%(?:teamcity\.build\.(?:branch|vcs\.branch|number|id)|env\.[A-Z0-9_]+|"
    r"build\.vcs\.number|vcsroot\.[A-Za-z0-9_.]+)%",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"(?:/etc/passwd|/etc/shadow|/root|/home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:user|runAsUser)\s*[=:]\s*[\"']?root[\"']?\b",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
BROAD_VCS_TRIGGER_PATTERN = re.compile(
    r"(?:branchFilter|branch_filter)\s*[=:]\s*[\"']?\*[\"']?",
    re.IGNORECASE,
)
INSECURE_VCS_PASSWORD_PATTERN = re.compile(
    r"(?:password|authPassword)\s*[=:]\s*[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
SKIP_SECURITY_PATTERN = re.compile(
    r"(?:enabled|executionPolicy)\s*[=:]\s*false\b",
    re.IGNORECASE,
)
UNPINNED_DOCKER_IMAGE_PATTERN = re.compile(
    r"(?:dockerImage|imageName)\s*[=:]\s*[\"'](?:ubuntu|node|python|golang)[\"']",
    re.IGNORECASE,
)
EXPOSED_PARAM_PATTERN = re.compile(
    r"(?:password|secret|token)\s*\{\s*param\s*\(\s*[\"'][^\"']+[\"']\s*,\s*display\s*=\s*ParameterDisplay\.(?:NORMAL|PROMPT)\s*\)",
    re.IGNORECASE,
)


@dataclass
class TeamCityFinding:
    """A security or best-practice issue in a TeamCity pipeline."""

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
class TeamCityInfo:
    """Parsed metadata about a TeamCity config file."""

    path: str
    build_configs: list[str] = field(default_factory=list)
    vcs_roots: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TeamCityStats:
    """Aggregate TeamCity analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_teamcity_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in TEAMCITY_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(TEAMCITY_DIRS):
        if lower.endswith((".kts", ".xml", ".kt")):
            return True
        if lower == "pom.xml":
            return True
    if lower.endswith(".teamcity.kts"):
        return True
    return False


class TeamCityAnalyzer:
    """Audit TeamCity pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.teamcity/settings.kts` and related Kotlin DSL / XML configs for
    curl-pipe-to-shell, %teamcity.build.branch% injection, and secrets in VCS roots.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TeamCityFinding] | None = None
        self._stats: TeamCityStats | None = None
        self._infos: list[TeamCityInfo] | None = None

    def files(self) -> list[Path]:
        """Return TeamCity config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_teamcity_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TeamCityFinding], TeamCityInfo]:
        findings: list[TeamCityFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, TeamCityInfo(path=rel)

        info = TeamCityInfo(path=rel, lines=len(raw_lines))
        in_security_step = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue

            build_match = re.search(
                r"(?:buildType|BuildType)\s*\(\s*[\"']([^\"']+)[\"']",
                raw,
            )
            if build_match:
                name = build_match.group(1)
                info.build_configs.append(name)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(name))

            vcs_match = re.search(
                r"(?:vcsRoot|VcsRoot)\s*\(\s*[\"']([^\"']+)[\"']",
                raw,
            )
            if vcs_match:
                info.vcs_roots.append(vcs_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_KOTLIN_SECRET_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use TeamCity parameters or password-type params",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PLAIN_SECRET_VALUE_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="plain_secret_value",
                        severity="high",
                        message="sensitive-looking value in config — store in TeamCity credentials",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="script_injection",
                        severity="medium",
                        message="TeamCity parameter interpolated in script — validate untrusted VCS inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path referenced — avoid mounting credentials or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="root_user",
                        severity="medium",
                        message="step runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if BROAD_VCS_TRIGGER_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="broad_vcs_trigger",
                        severity="high",
                        message="VCS trigger matches all branches — restrict to protected branches",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_VCS_PASSWORD_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="vcs_password",
                        severity="high",
                        message="hardcoded VCS password — use TeamCity credentials or OAuth",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_DOCKER_IMAGE_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="unpinned_docker_image",
                        severity="low",
                        message="docker image not version-pinned — pin to a specific tag or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EXPOSED_PARAM_PATTERN.search(line):
                findings.append(
                    TeamCityFinding(
                        kind="exposed_secret_param",
                        severity="medium",
                        message="secret parameter displayed in UI — use ParameterDisplay.HIDDEN",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_SECURITY_PATTERN.search(line) and in_security_step:
                findings.append(
                    TeamCityFinding(
                        kind="security_step_disabled",
                        severity="medium",
                        message="security build step disabled — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[TeamCityFinding]:
        """Scan TeamCity configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TeamCityFinding] = []
        infos: list[TeamCityInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = TeamCityStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TeamCityStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TeamCityInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no pipelines)."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened TeamCity Kotlin DSL settings template."""
        return """\
// Generated by DevAI TeamCityAnalyzer
import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script
import jetbrains.buildServer.configs.kotlin.triggers.vcs

version = "2024.03"

project {
    vcsRoot(HttpsGitVcsRoot {
        id("AppRepo")
        name = "App Repository"
        url = "https://github.com/example/app.git"
        branch = "refs/heads/main"
        authMethod = password {
            userName = "ci-bot"
            password = "credentialsJSON:git-token"
        }
    })

    buildType(BuildType {
        id("Tests")
        name = "Tests"
        vcs {
            root(HttpsGitVcsRoot { id("AppRepo") })
            branchFilter = "+:main"
        }
        steps {
            script {
                name = "Run tests"
                scriptContent = "pip install -e .[dev] && python -m pytest"
            }
        }
        triggers {
            vcs {
                branchFilter = "+:main"
            }
        }
    })

    buildType(BuildType {
        id("SecurityScan")
        name = "Security Scan"
        vcs {
            root(HttpsGitVcsRoot { id("AppRepo") })
            branchFilter = "+:main"
        }
        steps {
            script {
                name = "Static analysis"
                scriptContent = "devai security-scan ."
            }
        }
    })
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "TeamCity: none found"
        return (
            f"TeamCity: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "TeamCity pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            configs = ", ".join(info.build_configs[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.build_configs)} build config(s), configs=[{configs}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
