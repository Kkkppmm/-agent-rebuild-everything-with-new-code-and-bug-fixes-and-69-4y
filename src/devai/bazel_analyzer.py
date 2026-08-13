"""BazelAnalyzer — audit Bazel BUILD files and .bazelrc for security and build hardening."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BAZEL_BUILD_NAMES = ("BUILD", "BUILD.bazel")
BAZEL_WORKSPACE_NAMES = ("WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel")
BAZEL_RC_NAMES = (".bazelrc", ".bazelrc.local")
BAZEL_MARKER_PATTERN = re.compile(
    r"(?:^\s*(?:load|package|rule|http_archive|git_repository|genrule|cc_library|py_library|"
    r"java_library|go_library|sh_binary|container_image)\b|^\s*build\s*--)",
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
HTTP_ARCHIVE_PATTERN = re.compile(r"http_archive\s*\(", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"sha256\s*=", re.IGNORECASE)
CHECKSUM_PATTERN = re.compile(r"(?:integrity|checksum|sha512)\s*=", re.IGNORECASE)
GIT_REPOSITORY_PATTERN = re.compile(r"git_repository\s*\(", re.IGNORECASE)
COMMIT_PATTERN = re.compile(r"(?:commit|tag)\s*=", re.IGNORECASE)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
NO_SANDBOX_PATTERN = re.compile(
    r"(?:no-sandbox|no-sandbox|requires-network|local|standalone)",
    re.IGNORECASE,
)
SANDBOX_DISABLE_PATTERN = re.compile(
    r"(?:spawn_strategy\s*=\s*standalone|genrule_strategy\s*=\s*standalone|"
    r"build\s+--spawn_strategy=standalone|build\s+--genrule_strategy=standalone)",
    re.IGNORECASE,
)
BIND_PATTERN = re.compile(r"\bbind\s*\(", re.IGNORECASE)
LOCAL_REPO_PATTERN = re.compile(r"local_repository\s*\(", re.IGNORECASE)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:privileged\s*=\s*True|run_as_root\s*=\s*True|"
    r"docker_run_flags\s*=\s*[\"'][^\"']*--privileged)",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
UNPINNED_GIT_URL_PATTERN = re.compile(
    r"(?:git\+https?://|git@)[^\s\"']+(?![^\n]*(?:commit|tag)\s*=)",
    re.IGNORECASE,
)


@dataclass
class BazelFinding:
    """A security or best-practice issue in a Bazel configuration file."""

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
class BazelInfo:
    """Parsed metadata about a Bazel configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    rules: list[str] = field(default_factory=list)
    loads: list[str] = field(default_factory=list)


@dataclass
class BazelStats:
    """Aggregate Bazel analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_bazel_file(path: Path) -> bool:
    """Return True if the path looks like a Bazel configuration file."""
    name = path.name
    if name in BAZEL_BUILD_NAMES or name in BAZEL_WORKSPACE_NAMES or name in BAZEL_RC_NAMES:
        return True
    if name.endswith(".bzl") and any(
        part in ("bazel", "build", "tools", "third_party") for part in path.parts
    ):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if BAZEL_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


def _file_kind(path: Path) -> str:
    name = path.name
    if name in BAZEL_BUILD_NAMES:
        return "build"
    if name in ("WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"):
        return "workspace"
    if name.startswith(".bazelrc"):
        return "bazelrc"
    if name.endswith(".bzl"):
        return "starlark"
    return "unknown"


class BazelAnalyzer:
    """Audit Bazel BUILD files, WORKSPACE/MODULE.bazel, and .bazelrc for security issues.

    Scans for hardcoded secrets, unpinned http_archive/git_repository rules, sandbox
    disabling, curl-pipe-to-shell in genrules, privileged container settings, sensitive
    local_repository paths, and deprecated bind() usage.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BazelFinding] | None = None
        self._stats: BazelStats | None = None
        self._infos: list[BazelInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Bazel configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_bazel_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[BazelFinding], BazelInfo]:
        findings: list[BazelFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BazelInfo(path=rel)

        raw_lines = text.splitlines()
        info = BazelInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            load_match = re.match(r"load\s*\(\s*[\"']([^\"']+)[\"']", stripped)
            if load_match:
                info.loads.append(load_match.group(1))

            rule_match = re.match(
                r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
                stripped,
            )
            if rule_match and rule_match.group(1) not in ("load", "if", "for", "def"):
                info.rules.append(rule_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    BazelFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Bazel config — use repository_rule secrets or bazelrc user files",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    BazelFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Bazel config — use credential helpers or secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    BazelFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL — use HTTPS for external dependencies",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HTTP_ARCHIVE_PATTERN.search(line):
                block = self._extract_rule_block(raw_lines, lineno - 1)
                if not SHA256_PATTERN.search(block) and not CHECKSUM_PATTERN.search(block):
                    findings.append(
                        BazelFinding(
                            kind="http_archive_no_checksum",
                            severity="high",
                            message="http_archive without sha256/checksum — pin with integrity verification",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if GIT_REPOSITORY_PATTERN.search(line):
                block = self._extract_rule_block(raw_lines, lineno - 1)
                if not COMMIT_PATTERN.search(block):
                    findings.append(
                        BazelFinding(
                            kind="git_repository_unpinned",
                            severity="high",
                            message="git_repository without commit/tag pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    BazelFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in genrule — vendor scripts with checksum verification",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if NO_SANDBOX_PATTERN.search(line) and (
                "tags" in line.lower() or "spawn_strategy" in line.lower()
            ):
                findings.append(
                    BazelFinding(
                        kind="sandbox_disabled",
                        severity="medium",
                        message="sandbox disabled or network-required tag — restrict to trusted genrules only",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SANDBOX_DISABLE_PATTERN.search(line):
                findings.append(
                    BazelFinding(
                        kind="sandbox_strategy_disabled",
                        severity="medium",
                        message="global sandbox strategy disabled — prefer sandboxed builds in .bazelrc",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if BIND_PATTERN.search(line):
                findings.append(
                    BazelFinding(
                        kind="bind_usage",
                        severity="low",
                        message="deprecated bind() rule — migrate to alias() or repository rules",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LOCAL_REPO_PATTERN.search(line):
                block = self._extract_rule_block(raw_lines, lineno - 1)
                if SENSITIVE_PATH_PATTERN.search(block):
                    findings.append(
                        BazelFinding(
                            kind="sensitive_local_path",
                            severity="high",
                            message="local_repository points to sensitive host path — avoid bundling credentials",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    BazelFinding(
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
                    BazelFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock reference — avoid host Docker socket in Bazel rules",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_URL_PATTERN.search(line) and (
                "git+" in line.lower() or "git@" in line.lower()
            ):
                findings.append(
                    BazelFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="git URL without commit pin — pin to immutable revision",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def _extract_rule_block(self, lines: list[str], start: int) -> str:
        """Return text from a rule opening line through its closing parenthesis."""
        depth = 0
        parts: list[str] = []
        for line in lines[start:]:
            parts.append(line)
            depth += line.count("(") - line.count(")")
            if depth <= 0 and "(" in line:
                break
        return "\n".join(parts)

    def analyze(self) -> list[BazelFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BazelFinding] = []
        infos: list[BazelInfo] = []
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
        self._stats = BazelStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BazelStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BazelInfo]:
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
        """Scaffold a hardened MODULE.bazel with pinned dependencies."""
        return """\
module(
    name = "my_project",
    version = "1.0.0",
)

bazel_dep(name = "rules_python", version = "0.33.2")

http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "example_dep",
    urls = ["https://github.com/example/repo/archive/v1.0.0.tar.gz"],
    sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
    strip_prefix = "repo-1.0.0",
)
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Bazel configs: none found"
        return (
            f"Bazel configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Bazel analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            rules = ", ".join(info.rules[:8]) if info.rules else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): {len(info.rules)} rule(s), "
                f"{len(info.loads)} load(s)"
            )
            lines.append(f"    rules: {rules}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
