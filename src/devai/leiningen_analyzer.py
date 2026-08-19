"""LeiningenAnalyzer — audit project.clj and profiles.clj for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

LEININGEN_MANIFEST_NAMES = ("project.clj", "profiles.clj")
LEININGEN_DIR = ".lein"
LEININGEN_PLUGIN_FILES = ("plugins.clj",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?::password|:pass|:token|:secret|:api-key|:api_key|:auth-token|:client-secret)\s+"
    r"[\"'][^\"'\s${}][^\"']*[\"']|"
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
DEPLOY_CREDENTIALS_PATTERN = re.compile(
    r":deploy-credentials\s*\{",
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
    r":(?:branch|tag|rev)\s+[\"']?(?:main|master|HEAD|develop)[\"']?|"
    r":git\s+[\"'][^\"']+\.git[\"']\s*$|"
    r"\.git#(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
LOOSE_VERSION_PATTERN = re.compile(
    r"[\"'](?:latest|LATEST|RELEASE|\+|\*)[\"']|"
    r":version\s+[\"'](?:latest|LATEST|RELEASE)[\"']",
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
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|Runtime\.getRuntime\(\)\.exec|"
    r"\bsh\s+-c\b|\bshell\b|\bdo\b)",
    re.IGNORECASE,
)
DEP_PATTERN = re.compile(
    r'\[\s*([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)\s+["\']([^"\']+)["\']\s*\]',
)


@dataclass
class LeiningenFinding:
    """A security or best-practice issue in a Leiningen configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class LeiningenInfo:
    """Parsed metadata from a Leiningen configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "project"
    dependencies: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)


@dataclass
class LeiningenStats:
    """Aggregate statistics from Leiningen analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_leiningen_file(path: Path) -> bool:
    if path.name in LEININGEN_MANIFEST_NAMES:
        return True
    if path.parent.name == LEININGEN_DIR and path.name in LEININGEN_PLUGIN_FILES:
        return True
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "project.clj":
        return "project"
    if name == "profiles.clj":
        return "profiles"
    if path.parent.name == LEININGEN_DIR and name in LEININGEN_PLUGIN_FILES:
        return "plugins"
    return "unknown"


class LeiningenAnalyzer:
    """Audit Leiningen configuration for security issues.

    Scans project.clj, profiles.clj, and .lein/plugins.clj for hardcoded deploy
    credentials, insecure HTTP repositories, credentials in git sources, unpinned
    git dependencies, loose version constraints, dangerous shell aliases, and
    sensitive path references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LeiningenFinding] | None = None
        self._stats: LeiningenStats | None = None
        self._infos: list[LeiningenInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Leiningen configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_leiningen_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LeiningenFinding],
        info: LeiningenInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            return

        dep_match = DEP_PATTERN.search(stripped)
        if dep_match:
            info.dependencies.append(f"{dep_match.group(1)}:{dep_match.group(2)}")

        repo_match = re.search(
            r':url\s+["\']([^"\']+)["\']',
            stripped,
            re.IGNORECASE,
        )
        if repo_match:
            info.repositories.append(repo_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                LeiningenFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Leiningen config — use env vars or ~/.lein/credentials.clj",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DEPLOY_CREDENTIALS_PATTERN.search(line):
            findings.append(
                LeiningenFinding(
                    kind="deploy_credentials",
                    severity="high",
                    message="deploy-credentials in project file — use ~/.lein/credentials.clj (gitignored) or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                LeiningenFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Leiningen config — use credential helpers or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                LeiningenFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP repository URL — use HTTPS for Maven/Clojars repositories",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                LeiningenFinding(
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
                LeiningenFinding(
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
                LeiningenFinding(
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
                LeiningenFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Leiningen config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                LeiningenFinding(
                    kind="sensitive_path",
                    severity="high",
                    message="sensitive host path reference — avoid embedding credentials in builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line) and (
            ":aliases" in stripped.lower()
            or ":prep-tasks" in stripped.lower()
            or "shell" in stripped.lower()
            or "sh " in stripped.lower()
        ):
            findings.append(
                LeiningenFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Leiningen alias or task — review shell/do usage",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[LeiningenFinding], LeiningenInfo]:
        rel = str(path.relative_to(self.root))
        findings: list[LeiningenFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, LeiningenInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = LeiningenInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[LeiningenFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LeiningenFinding] = []
        infos: list[LeiningenInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        manifest_dirs = {
            p.parent for p in paths if p.name in LEININGEN_MANIFEST_NAMES
        }
        self._findings = findings
        self._infos = infos
        self._stats = LeiningenStats(
            configs=len(manifest_dirs),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> LeiningenStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[LeiningenInfo]:
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
        """Scaffold a hardened project.clj snippet with secure defaults."""
        return """\
(defproject my-app "0.1.0-SNAPSHOT"
  :description "A secure Leiningen project"
  :dependencies [[org.clojure/clojure "1.11.4"]]

  ;; Use HTTPS repositories only
  ;; :repositories [["central" {:url "https://repo1.maven.org/maven2/" :snapshots false}]]

  ;; Store deploy credentials in ~/.lein/credentials.clj (gitignored) — never hardcode
  ;; :deploy-repositories [["releases" {:url "https://repo.clojars.org" :sign-releases false}]]

  ;; Pin git deps to tags or commits — never use :branch "master"
  ;; :dependencies [[com.example/lib "1.0.0"]]
)
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Leiningen configs: none found"
        return (
            f"Leiningen configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Leiningen analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            repos = ", ".join(info.repositories[:4]) if info.repositories else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dep(s), {len(info.repositories)} repo(s)"
            )
            lines.append(f"    deps: {deps}")
            lines.append(f"    repos: {repos}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
