"""SemanticReleaseAnalyzer — audit python-semantic-release configs for release security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("semantic_release.toml",)
PYPROJECT_NAME = "pyproject.toml"

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|hvcs[_-]?token)\s*[=:]\s*"
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|os\.system\s*\(|"
    r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True)",
    re.IGNORECASE,
)
GIT_HTTP_DEPS_PATTERN = re.compile(
    r"(?:git\+http://|http://[^\s\"']+#egg=)",
    re.IGNORECASE,
)
SEMANTIC_RELEASE_SECTION_PATTERN = re.compile(r"^\[tool\.semantic_release\]", re.IGNORECASE)
COMMAND_KEY_PATTERN = re.compile(
    r"^\s*(?:build_command|post_version_command|pre_version_command|"
    r"changelog_command|commit_parser|version_source)\s*=",
    re.IGNORECASE,
)
PATH_KEY_PATTERN = re.compile(
    r"^\s*(?:version_toml|version_variable|dist_path|changelog_file|"
    r"template_dir|upload_to_repository)\s*=",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"[\"'](?:\.\./|\.\.\\|/etc/|/tmp/|\.ssh/|~/)",
    re.IGNORECASE,
)
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?:version_toml|version_variable|dist_path|changelog_file)\s*=\s*[\"']/[^\"']*[\"']",
    re.IGNORECASE,
)
TAG_FORMAT_SHELL_PATTERN = re.compile(
    r"tag_format\s*=\s*[\"'][^\"']*(?:\$\(|`|\|\||&&|;)[^\"']*[\"']",
    re.IGNORECASE,
)
NO_GIT_VERIFY_PATTERN = re.compile(r"no_git_verify\s*=\s*true\b", re.IGNORECASE)
ALLOW_ZERO_VERSION_PATTERN = re.compile(r"allow_zero_version\s*=\s*true\b", re.IGNORECASE)
UPLOAD_PYPI_TRUE_PATTERN = re.compile(r"upload_to_pypi\s*=\s*true\b", re.IGNORECASE)


@dataclass
class SemanticReleaseFinding:
    """A security or best-practice issue in a semantic-release configuration."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class SemanticReleaseInfo:
    """Parsed metadata about a python-semantic-release configuration file."""

    path: str
    lines: int = 0
    build_command: str = ""
    upload_to_pypi: bool | None = None
    no_git_verify: bool = False
    allow_zero_version: bool = False


@dataclass
class SemanticReleaseStats:
    """Aggregate semantic-release analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


class SemanticReleaseAnalyzer:
    """Audit python-semantic-release configs for release automation security risks.

    Scans pyproject.toml [tool.semantic_release] and semantic_release.toml for
    hardcoded tokens, dangerous build commands, path traversal in version paths,
    insecure HTTP URLs, SCM credentials, disabled git verification, and unsafe
    tag formats.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SemanticReleaseFinding] | None = None
        self._stats: SemanticReleaseStats | None = None
        self._infos: list[SemanticReleaseInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return semantic-release configuration paths found in the project."""
        found: list[Path] = []
        pyproject = self.root / PYPROJECT_NAME
        if pyproject.is_file() and self._has_semantic_release_section(pyproject):
            found.append(pyproject)
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        return found

    def _has_semantic_release_section(self, path: Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "[tool.semantic_release" in text.lower()

    def _record_command_value(self, line: str, info: SemanticReleaseInfo) -> None:
        match = re.search(
            r"build_command\s*=\s*[\"']([^\"']+)[\"']",
            line,
            re.IGNORECASE,
        )
        if match:
            info.build_command = match.group(1)

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[SemanticReleaseFinding],
        info: SemanticReleaseInfo,
        in_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if in_section:
            self._record_command_value(line, info)

            if UPLOAD_PYPI_TRUE_PATTERN.search(line):
                info.upload_to_pypi = True

            if NO_GIT_VERIFY_PATTERN.search(line):
                info.no_git_verify = True
                findings.append(
                    SemanticReleaseFinding(
                        kind="no_git_verify",
                        severity="medium",
                        message="no_git_verify=true — bypasses git hooks during release commits",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALLOW_ZERO_VERSION_PATTERN.search(line):
                info.allow_zero_version = True
                findings.append(
                    SemanticReleaseFinding(
                        kind="allow_zero_version",
                        severity="low",
                        message="allow_zero_version=true — can publish 0.0.0 releases unintentionally",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if TAG_FORMAT_SHELL_PATTERN.search(line):
                findings.append(
                    SemanticReleaseFinding(
                        kind="tag_format_shell",
                        severity="medium",
                        message="tag_format contains shell metacharacters — keep formats static",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PATH_KEY_PATTERN.match(stripped):
                if PATH_TRAVERSAL_PATTERN.search(line):
                    findings.append(
                        SemanticReleaseFinding(
                            kind="path_traversal",
                            severity="high",
                            message="path traversal in semantic-release path setting — use repo-relative paths",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                if ABSOLUTE_PATH_PATTERN.search(line):
                    findings.append(
                        SemanticReleaseFinding(
                            kind="absolute_path",
                            severity="medium",
                            message="absolute path in semantic-release config — prefer repo-relative paths",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        if not in_section:
            return

        if COMMAND_KEY_PATTERN.match(stripped):
            if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
                findings.append(
                    SemanticReleaseFinding(
                        kind="dangerous_command",
                        severity="high",
                        message="dangerous shell command in release config — review build/version hooks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if HARDCODED_SECRET_PATTERN.search(line):
            if not re.search(r"os\.environ|getenv|environ\.get|\{[A-Z_]+\}", line, re.IGNORECASE):
                findings.append(
                    SemanticReleaseFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in semantic-release config — use env vars or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                SemanticReleaseFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in semantic-release config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                SemanticReleaseFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in semantic-release config — use HTTPS for remotes and deps",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                SemanticReleaseFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GIT_HTTP_DEPS_PATTERN.search(line):
            findings.append(
                SemanticReleaseFinding(
                    kind="insecure_git_deps",
                    severity="high",
                    message="HTTP git dependency in semantic-release config — use HTTPS or pinned wheels",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[SemanticReleaseFinding], SemanticReleaseInfo]:
        findings: list[SemanticReleaseFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, SemanticReleaseInfo(path=rel)

        info = SemanticReleaseInfo(path=rel, lines=len(raw_lines))
        in_section = path.name == "semantic_release.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if SEMANTIC_RELEASE_SECTION_PATTERN.match(stripped):
                in_section = True
            elif stripped.startswith("[") and not SEMANTIC_RELEASE_SECTION_PATTERN.match(stripped):
                in_section = False

            self._scan_line(line, lineno, rel, findings, info, in_section)

        return findings, info

    def analyze(self) -> list[SemanticReleaseFinding]:
        """Scan semantic-release config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SemanticReleaseFinding] = []
        infos: list[SemanticReleaseInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = SemanticReleaseStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SemanticReleaseStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SemanticReleaseInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
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
        """Scaffold a hardened pyproject.toml [tool.semantic_release] template."""
        return """\
# Generated by DevAI SemanticReleaseAnalyzer
# Add this section to pyproject.toml

[tool.semantic_release]
version_toml = ["pyproject.toml:project.version"]
build_command = "python -m build"
upload_to_pypi = false
upload_to_vcs_release = true
no_git_verify = false
allow_zero_version = false
tag_format = "v{version}"
# Use GH_TOKEN / GITLAB_TOKEN env vars — never hardcode tokens here
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Semantic-release configs: none found"
        return (
            f"Semantic-release configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Semantic-release analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            build = info.build_command or "unspecified"
            pypi = "enabled" if info.upload_to_pypi else "disabled/unspecified"
            git_verify = "disabled" if info.no_git_verify else "enabled/unspecified"
            lines.append(
                f"  - {info.path}: build_command={build}, upload_to_pypi={pypi}, "
                f"no_git_verify={git_verify}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
