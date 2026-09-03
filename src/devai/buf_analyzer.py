"""BufAnalyzer — audit buf.yaml and buf.gen.yaml for protobuf toolchain security."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

BUF_CONFIG_NAMES = (
    "buf.yaml",
    "buf.yml",
    "buf.gen.yaml",
    "buf.gen.yml",
    "buf.work.yaml",
    "buf.work.yml",
    "buf.lock",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
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
BREAKING_DISABLED_PATTERN = re.compile(
    r"breaking\s*:\s*(?:use\s*:\s*(?:NONE|OFF)|except\s*:\s*\[\s*\*\s*\])|"
    r"\"breaking\"\s*:\s*\{[^}]*\"use\"\s*:\s*\"(?:NONE|OFF)\"",
    re.IGNORECASE,
)
LINT_DISABLED_PATTERN = re.compile(
    r"lint\s*:\s*(?:use\s*:\s*(?:NONE|OFF)|except\s*:\s*\[\s*\*\s*\])|"
    r"\"lint\"\s*:\s*\{[^}]*\"use\"\s*:\s*\"(?:NONE|OFF)\"",
    re.IGNORECASE,
)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"remote\s*:\s*[\"']?buf\.build/[^\"'\s]+[\"']?",
    re.IGNORECASE,
)
UNPINNED_PLUGIN_PATTERN = re.compile(
    r"plugin\s*:\s*[\"']?[^\"'\s]+[\"']?(?![\s\S]{0,40}(?:version|revision|commit))",
    re.IGNORECASE,
)
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:@|#|ref=|rev=)(?:main|master|HEAD|develop|trunk)\b|"
    r"github\.com/[^\"'\s]+/(?:main|master|HEAD|develop|trunk)",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LOCAL_PLUGIN_PATH_PATTERN = re.compile(
    r"plugin\s*:\s*[\"']?(?:\.\.?/|/tmp/|/var/tmp/)[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
DISABLED_WIRE_COMPAT_PATTERN = re.compile(
    r"WIRE_JSON|WIRE|FILE\s+except\s*:\s*\[\s*\*\s*\]",
    re.IGNORECASE,
)


@dataclass
class BufFinding:
    """A security or best-practice issue in a Buf configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BufInfo:
    """Parsed metadata about a Buf configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    modules: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    breaking_rules: str = ""
    lint_rules: str = ""


@dataclass
class BufStats:
    """Aggregate Buf analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_buf_file(path: Path) -> bool:
    return path.name.lower() in BUF_CONFIG_NAMES


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("buf.gen"):
        return "gen"
    if name.startswith("buf.work"):
        return "work"
    if name == "buf.lock":
        return "lock"
    return "module"


class BufAnalyzer:
    """Audit Buf protobuf toolchain configs for security issues.

    Scans buf.yaml, buf.gen.yaml, buf.work.yaml, and buf.lock for hardcoded
    secrets, insecure HTTP plugin registries, disabled lint/breaking rules,
    unpinned remote plugins, credentials in git URLs, curl-pipe-to-shell in
    plugin options, and local plugin paths from writable directories.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BufFinding] | None = None
        self._stats: BufStats | None = None
        self._infos: list[BufInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Buf configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_buf_file(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BufFinding],
        info: BufInfo,
    ) -> None:
        stripped = line.strip()
        if stripped.startswith("#"):
            return

        module_match = re.search(r"^\s*-\s*path\s*:\s*[\"']?([^\"'\s#]+)", stripped)
        if module_match:
            info.modules.append(module_match.group(1))

        plugin_match = re.search(r"plugin\s*:\s*[\"']?([^\"'\s#]+)", stripped, re.IGNORECASE)
        if plugin_match:
            info.plugins.append(plugin_match.group(1))

        breaking_match = re.search(r"breaking\s*:\s*use\s*:\s*([A-Z_]+)", stripped, re.IGNORECASE)
        if breaking_match:
            info.breaking_rules = breaking_match.group(1)

        lint_match = re.search(r"lint\s*:\s*use\s*:\s*([A-Z_]+)", stripped, re.IGNORECASE)
        if lint_match:
            info.lint_rules = lint_match.group(1)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Buf config — use environment variables or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Buf config — remove credentials from protobuf toolchain files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in Buf config — use HTTPS for remote plugins and registries",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or token env vars for plugin sources",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl/wget piped to shell in Buf config — vendor scripts with checksum verification",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="plugin or module ref pinned to moving branch — pin commit SHA or version tag",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOCAL_PLUGIN_PATH_PATTERN.search(line):
            findings.append(
                BufFinding(
                    kind="local_plugin_path",
                    severity="medium",
                    message="local plugin path from writable directory — pin remote plugins with versions",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _scan_document(self, text: str, rel: str, findings: list[BufFinding]) -> None:
        if BREAKING_DISABLED_PATTERN.search(text):
            findings.append(
                BufFinding(
                    kind="breaking_disabled",
                    severity="medium",
                    message="Buf breaking change detection disabled — enable FILE or WIRE breaking rules",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if LINT_DISABLED_PATTERN.search(text):
            findings.append(
                BufFinding(
                    kind="lint_disabled",
                    severity="medium",
                    message="Buf lint rules disabled — enable DEFAULT or MINIMAL lint rules",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if REMOTE_PLUGIN_PATTERN.search(text) and UNPINNED_PLUGIN_PATTERN.search(text):
            findings.append(
                BufFinding(
                    kind="unpinned_remote_plugin",
                    severity="low",
                    message="remote Buf plugin without explicit version — pin plugin versions for reproducible builds",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if DISABLED_WIRE_COMPAT_PATTERN.search(text):
            findings.append(
                BufFinding(
                    kind="wire_compat_disabled",
                    severity="low",
                    message="wire compatibility checks weakened — keep breaking rules enabled for API stability",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[BufFinding], BufInfo]:
        findings: list[BufFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, BufInfo(path=rel, file_kind=file_kind)

        raw_lines = text.splitlines()
        info = BufInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        if file_kind != "lock":
            self._scan_document(text, rel, findings)
        return findings, info

    def analyze(self) -> list[BufFinding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BufFinding] = []
        infos: list[BufInfo] = []
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
        self._stats = BufStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BufStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BufInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold a hardened buf.yaml snippet."""
        return """\
# buf.yaml — hardened defaults for protobuf projects
version: v2
modules:
  - path: proto
lint:
  use:
    - DEFAULT
breaking:
  use:
    - FILE
# Pin remote plugins in buf.gen.yaml with explicit versions
# Avoid credentials in plugin URLs — use buf registry auth tokens via env vars
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Buf configs: none found"
        return (
            f"Buf configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Buf analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            plugins = ", ".join(info.plugins[:8]) if info.plugins else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.modules)} module(s), {len(info.plugins)} plugin(s)"
            )
            lines.append(f"    plugins: {plugins}")
            if info.lint_rules:
                lines.append(f"    lint: {info.lint_rules}")
            if info.breaking_rules:
                lines.append(f"    breaking: {info.breaking_rules}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
