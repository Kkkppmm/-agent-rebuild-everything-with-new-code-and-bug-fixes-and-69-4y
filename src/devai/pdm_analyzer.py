"""PdmAnalyzer — audit PDM pyproject.toml, .pdm.toml, and pdm.lock for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PDM_PYPROJECT_NAMES = ("pyproject.toml",)
PDM_CONFIG_NAMES = (".pdm.toml", "pdm.toml")
PDM_LOCK_NAMES = ("pdm.lock",)
PDM_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.pdm\]|^\[tool\.pdm\.|^\[\[tool\.pdm\.source\]\]|"
    r"^\[tool\.pdm\.scripts\]|^\[tool\.pdm\.dev-dependencies\]|"
    r"pdm-backend|pdm\s*=\s*\{)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token|http-basic)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
DYNAMIC_VERSION_PATTERN = re.compile(
    r"=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"=\s*\{[^}]*version\s*=\s*[\"'](?:\*|latest|LATEST)[\"']|"
    r"(?:>=|<=|>|<)\s*[\"']?\d|"
    r"[a-zA-Z0-9_.-]+\s*=\s*\*",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:git|rev|branch|tag|ref)\s*=\s*[\"'](?:main|master|HEAD|develop)[\"']|"
    r"@(?:main|master|HEAD|develop)\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
INSECURE_SSL_PATTERN = re.compile(
    r"(?:cert\s*=\s*false|disable[_-]?ssl|ssl[_-]?verify\s*=\s*false|"
    r"trusted-host\s*=|allow-insecure-host|verify_ssl\s*=\s*false)",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
INDEX_URL_PATTERN = re.compile(
    r"(?:index-url|extra-index-url|url|repo)\s*=\s*[\"']?(\S+)[\"']?",
    re.IGNORECASE,
)
TRUSTED_HOST_PATTERN = re.compile(
    r"(?:--trusted-host|trusted-host)\s*[= ]?\s*([^\s#]+)",
    re.IGNORECASE,
)
INSECURE_ENV_VAR_PATTERN = re.compile(
    r"(?:PDM_REPO_PASSWORD|PDM_PUBLISH_PASSWORD|PDM_PEP517_SCM_PWD|"
    r"PDM_PYPI_PASSWORD|TWINE_PASSWORD|TWINE_USERNAME)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:pre_install|post_install|pre_build|post_build)\s*=\s*",
    re.IGNORECASE,
)


@dataclass
class PdmFinding:
    """A security or best-practice issue in a PDM configuration file."""

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
class PdmInfo:
    """Parsed metadata about a PDM configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    dependencies: list[str] = field(default_factory=list)
    index_urls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class PdmStats:
    """Aggregate PDM analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pdm_file(path: Path) -> bool:
    """Return True if the path looks like a PDM configuration file."""
    name = path.name
    if name in PDM_LOCK_NAMES or name in PDM_CONFIG_NAMES:
        return True
    if name in PDM_PYPROJECT_NAMES:
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            if PDM_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name == "pyproject.toml":
        return "pyproject"
    if name in ("pdm.toml", ".pdm.toml"):
        return "pdm_config"
    if name == "pdm.lock":
        return "lock"
    return "unknown"


class PdmAnalyzer:
    """Audit PDM configuration for security issues.

    Scans pyproject.toml (with [tool.pdm]), .pdm.toml, and pdm.lock for
    hardcoded PyPI tokens, insecure HTTP repository URLs, credentials in
    git/source URLs, unpinned git dependencies, dynamic version constraints,
    curl-pipe-to-shell in scripts, disabled SSL verification, missing lockfile,
    and publish credentials in plain text.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PdmFinding] | None = None
        self._stats: PdmStats | None = None
        self._infos: list[PdmInfo] | None = None

    def configs(self) -> list[Path]:
        """Return PDM configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pdm_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[PdmFinding], PdmInfo]:
        findings: list[PdmFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PdmInfo(path=rel)

        raw_lines = text.splitlines()
        info = PdmInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            source_match = re.match(r"^\[\[tool\.pdm\.source\]\]", stripped, re.IGNORECASE)
            if source_match:
                info.sources.append("source")

            index_match = INDEX_URL_PATTERN.search(stripped)
            if index_match:
                info.index_urls.append(index_match.group(1))

            dep_match = re.search(
                r"^([a-zA-Z0-9_.-]+)\s*=\s*(?:\{|[\"'])",
                stripped,
            )
            if dep_match and not stripped.startswith("["):
                dep_name = dep_match.group(1)
                if dep_name not in ("name", "version", "description", "authors", "license"):
                    info.dependencies.append(dep_name)

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in PDM config — use PDM_REPO_PASSWORD or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_TOKEN_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in PDM config — use keyring or PDM_PUBLISH_* env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in PDM config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_ENV_VAR_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="publish_credential",
                        severity="high",
                        message="publish credentials in PDM config — use env vars or keyring",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for PyPI indexes and custom sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in repository URL — use token env vars or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if (
                DYNAMIC_VERSION_PATTERN.search(stripped)
                and not re.match(r"python\s*=", stripped, re.IGNORECASE)
                and (
                    re.search(
                        r"(?:dependencies|dev-dependencies|override-dependencies|sources)",
                        stripped,
                        re.IGNORECASE,
                    )
                    or ("=" in stripped and not stripped.startswith("["))
                )
            ):
                findings.append(
                    PdmFinding(
                        kind="dynamic_version",
                        severity="medium",
                        message="loose version constraint — pin dependencies for reproducible builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GIT_DEP_UNPINNED_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_SSL_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="insecure_ssl",
                        severity="high",
                        message="SSL/TLS verification disabled — keep certificate validation enabled",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if TRUSTED_HOST_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="trusted_host",
                        severity="medium",
                        message="trusted-host bypass — avoid disabling TLS hostname verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in PDM config — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="sensitive_path",
                        severity="high",
                        message="sensitive host path reference — avoid bundling credentials in builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DANGEROUS_SCRIPT_PATTERN.search(line):
                findings.append(
                    PdmFinding(
                        kind="dangerous_script",
                        severity="medium",
                        message="install/build script hook in PDM config — review for supply-chain risks",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def _check_missing_lock(self, paths: list[Path], findings: list[PdmFinding]) -> None:
        """Flag projects with PDM pyproject but no pdm.lock."""
        has_pdm_pyproject = any(
            p.name == "pyproject.toml" and _file_kind(p) == "pyproject" for p in paths
        )
        has_lock = any(p.name == "pdm.lock" for p in paths)
        if has_pdm_pyproject and not has_lock:
            findings.append(
                PdmFinding(
                    kind="missing_lock",
                    severity="low",
                    message="PDM project without pdm.lock — commit lockfile for reproducible installs",
                    path="pdm.lock",
                    lineno=0,
                )
            )

    def analyze(self) -> list[PdmFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PdmFinding] = []
        infos: list[PdmInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._check_missing_lock(paths, findings)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = PdmStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PdmStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PdmInfo]:
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
        """Scaffold a hardened PDM pyproject.toml snippet with secure defaults."""
        return """\
# pyproject.toml — hardened PDM defaults
[tool.pdm]
# Commit pdm.lock for reproducible installs

[[tool.pdm.source]]
# Use HTTPS PyPI only; store credentials via:
#   export PDM_REPO_USERNAME=__token__
#   export PDM_REPO_PASSWORD=pypi-<token>
# Never commit tokens in pyproject.toml or .pdm.toml

[tool.pdm.scripts]
# Avoid curl-pipe-to-shell in pre/post install hooks
# Pin dependencies with == or compatible release (~=) constraints
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "PDM configs: none found"
        return (
            f"PDM configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "PDM analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:8]) if info.dependencies else "none"
            indexes = ", ".join(info.index_urls[:8]) if info.index_urls else "none"
            sources = ", ".join(info.sources[:8]) if info.sources else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.dependencies)} dependency(ies), {len(info.sources)} source(s)"
            )
            lines.append(f"    dependencies: {deps}")
            lines.append(f"    index URLs: {indexes}")
            lines.append(f"    sources: {sources}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
