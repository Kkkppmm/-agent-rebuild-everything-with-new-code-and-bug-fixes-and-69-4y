"""PantsAnalyzer — audit Pants BUILD files and pants.toml for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PANTS_CONFIG_NAMES = ("pants.toml", "pants.ci.toml", "pants.local.toml")
PANTS_BUILD_NAMES = ("BUILD",)
PANTS_MARKER_PATTERN = re.compile(
    r"(?:^\s*(?:python_sources|python_requirements|docker_image|shell_command|pex_binary|"
    r"go_binary|jvm_artifact|python_distribution|resources)\s*\(|^\s*\[GLOBAL\]|"
    r"^\s*pants_version\s*=)",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged\s*=\s*True|run_as_root\s*=\s*True|"
    r"\"--privileged\"|'--privileged')",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
SHELL_COMMAND_PATTERN = re.compile(r"shell_command\s*\(", re.IGNORECASE)
DOCKER_IMAGE_PATTERN = re.compile(r"docker_image\s*\(", re.IGNORECASE)
PYTHON_REQUIREMENTS_PATTERN = re.compile(r"python_requirements\s*\(", re.IGNORECASE)
PYPI_REPO_PATTERN = re.compile(r"\[pypi\]", re.IGNORECASE)
DOCKER_REGISTRY_PATTERN = re.compile(r"\[docker\.registries\.", re.IGNORECASE)
LOOSE_PANTS_VERSION_PATTERN = re.compile(
    r"pants_version\s*=\s*[\"'](?:\*|latest|>=|~=)[^\"']*[\"']",
    re.IGNORECASE,
)
ENV_SECRET_PATTERN = re.compile(
    r"(?:environment|env)\s*=\s*\{[^\}]*(?:password|secret|api[_-]?key|token|credential)",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git\+https?://|git@)[^\s\"']+(?![^\n]*(?:commit|rev|tag)\s*=)",
    re.IGNORECASE,
)


@dataclass
class PantsFinding:
    """A security or best-practice issue in a Pants configuration file."""

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
class PantsInfo:
    """Parsed metadata about a Pants configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    targets: list[str] = field(default_factory=list)


@dataclass
class PantsStats:
    """Aggregate Pants analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_pants_file(path: Path) -> bool:
    """Return True if the path looks like a Pants configuration file."""
    name = path.name
    if name in PANTS_CONFIG_NAMES or name in PANTS_BUILD_NAMES:
        return True
    if name.endswith(".pants") or name == "pants":
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if PANTS_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in PANTS_CONFIG_NAMES:
        return "pants.toml"
    if name in PANTS_BUILD_NAMES:
        return "build"
    return "unknown"


class PantsAnalyzer:
    """Audit Pants BUILD files and pants.toml for security issues.

    Scans for hardcoded secrets, insecure PyPI/Docker registries, unpinned pants_version,
    curl-pipe-to-shell in shell_command targets, privileged docker_image settings,
    sensitive local paths, and secrets in environment dicts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PantsFinding] | None = None
        self._stats: PantsStats | None = None
        self._infos: list[PantsInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Pants configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_pants_file(path):
                found.append(path)
        return found

    def _extract_block(self, lines: list[str], start: int) -> str:
        """Return text from a rule opening line through its closing parenthesis."""
        depth = 0
        parts: list[str] = []
        for line in lines[start:]:
            parts.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0 and "(" in line:
                break
        return "\n".join(parts)

    def _analyze_file(self, path: Path) -> tuple[list[PantsFinding], PantsInfo]:
        findings: list[PantsFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, PantsInfo(path=rel)

        raw_lines = text.splitlines()
        info = PantsInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            target_match = re.match(
                r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
                stripped,
            )
            if target_match and target_match.group(1) not in ("if", "for", "def", "with"):
                info.targets.append(target_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Pants config — use environment variables or secret backends",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Pants config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for registries and artifact sources",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in shell_command — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SHELL_COMMAND_PATTERN.search(line):
                block = self._extract_block(raw_lines, lineno - 1)
                if CURL_PIPE_SHELL_PATTERN.search(block):
                    findings.append(
                        PantsFinding(
                            kind="shell_command_curl_pipe",
                            severity="high",
                            message="shell_command runs curl-pipe-to-shell — vendor and checksum scripts",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged or root container settings — disable privileged docker_image builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_IMAGE_PATTERN.search(line):
                block = self._extract_block(raw_lines, lineno - 1)
                if PRIVILEGED_PATTERN.search(block):
                    findings.append(
                        PantsFinding(
                            kind="docker_image_privileged",
                            severity="high",
                            message="docker_image with privileged settings — avoid privileged container builds",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock reference — avoid host Docker socket in Pants docker_image targets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="sensitive_local_path",
                        severity="high",
                        message="sensitive host path referenced — avoid bundling credentials in build targets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ENV_SECRET_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="environment_secret",
                        severity="high",
                        message="secret in environment dict — use Pants secrets or runtime env injection",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOOSE_PANTS_VERSION_PATTERN.search(line):
                findings.append(
                    PantsFinding(
                        kind="unpinned_pants_version",
                        severity="medium",
                        message="loose pants_version constraint — pin to an exact Pants release",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PYPI_REPO_PATTERN.search(line) or DOCKER_REGISTRY_PATTERN.search(line):
                block = self._extract_block(raw_lines, lineno - 1) if "(" in line else line
                if INSECURE_HTTP_PATTERN.search(block):
                    findings.append(
                        PantsFinding(
                            kind="insecure_registry",
                            severity="medium",
                            message="insecure HTTP registry/index — use HTTPS for PyPI and Docker registries",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if PYTHON_REQUIREMENTS_PATTERN.search(line):
                block = self._extract_block(raw_lines, lineno - 1)
                if UNPINNED_GIT_PATTERN.search(block):
                    findings.append(
                        PantsFinding(
                            kind="unpinned_git_dependency",
                            severity="medium",
                            message="git dependency without commit/rev pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git+" in line.lower() or "git@" in line.lower()
            ):
                findings.append(
                    PantsFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="git URL without commit pin — pin to immutable revision",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[PantsFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PantsFinding] = []
        infos: list[PantsInfo] = []
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
        self._stats = PantsStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PantsStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PantsInfo]:
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
        """Scaffold a hardened pants.toml with pinned version and HTTPS registries."""
        return """\
[GLOBAL]
pants_version = "2.21.0"
backend_packages = [
    "pants.backend.python",
    "pants.backend.docker",
]

[python]
interpreter_constraints = [">=3.10,<3.13"]

[pypi]
# Use the default PyPI index over HTTPS; add private indexes with auth via env vars.

[docker.registries.example]
address = "registry.example.com"
default = true
# Use DOCKER_CONFIG or credential helpers — never hardcode passwords here.
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Pants configs: none found"
        return (
            f"Pants configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Pants analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            targets = ", ".join(info.targets[:8]) if info.targets else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): {len(info.targets)} target(s)"
            )
            lines.append(f"    targets: {targets}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
