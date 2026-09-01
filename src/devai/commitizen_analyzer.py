"""CommitizenAnalyzer — audit Commitizen configs for bump-hook security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".cz.toml",
    "cz.toml",
    "commitizen.toml",
    ".commitizen.toml",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|exec\s*\(|\bos\.system\s*\()",
    re.IGNORECASE,
)
BUMP_HOOK_PATTERN = re.compile(
    r"(?:bump[_-]?message|changelog[_-]?incremental|post[_-]?bump|pre[_-]?bump|"
    r"changelog[_-]?file|update[_-]?changelog|commit[_-]?message)",
    re.IGNORECASE,
)
HOOK_COMMAND_PATTERN = re.compile(
    r"(?:bump[_-]?message|post[_-]?bump|pre[_-]?bump|changelog[_-]?incremental)\s*=\s*"
    r"[\"'].*(?:curl|wget|eval|exec|bash|sh\s+-c)",
    re.IGNORECASE,
)
MUTABLE_TAG_PATTERN = re.compile(
    r"(?:tag[_-]?format|version[_-]?scheme)\s*=\s*[\"'][^\"']*\{version\}[^\"']*[\"']|"
    r"(?:major_version_zero|update[_-]?changelog[_-]?on[_-]?bump)\s*=\s*false",
    re.IGNORECASE,
)
UNPINNED_VERSION_PROVIDER_PATTERN = re.compile(
    r"(?:version[_-]?provider|version[_-]?scheme)\s*=\s*[\"'](?:pep440|semver)[\"']",
    re.IGNORECASE,
)
COMMITIZEN_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.commitizen\]|^\[commitizen\]|commitizen\s*=)",
    re.IGNORECASE | re.MULTILINE,
)
ALLOW_CUSTOM_HOOKS_PATTERN = re.compile(
    r"(?:allow[_-]?custom[_-]?hooks|custom[_-]?hooks)\s*=\s*true",
    re.IGNORECASE,
)
INSECURE_CHANGELOG_PATTERN = re.compile(
    r"(?:changelog[_-]?file|changelog[_-]?path)\s*=\s*[\"']\.\./",
    re.IGNORECASE,
)


@dataclass
class CommitizenFinding:
    """A security or best-practice issue in a Commitizen configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CommitizenInfo:
    """Parsed metadata about a Commitizen configuration file."""

    path: str
    lines: int = 0
    version: str | None = None
    tag_format: str | None = None
    bump_hooks: list[str] = field(default_factory=list)


@dataclass
class CommitizenStats:
    """Aggregate Commitizen analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class CommitizenAnalyzer:
    """Audit Commitizen configuration for bump-hook security risks.

    Scans pyproject.toml [tool.commitizen], .cz.toml, and commitizen.toml for
    hardcoded secrets, dangerous bump hooks, insecure HTTP URLs, curl|sh patterns,
    changelog paths outside the project, and custom hook settings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CommitizenFinding] | None = None
        self._stats: CommitizenStats | None = None
        self._infos: list[CommitizenInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Commitizen configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
                if COMMITIZEN_MARKER_PATTERN.search(text):
                    found.append(pyproject)
            except OSError:
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CommitizenFinding],
        info: CommitizenInfo,
        in_commitizen_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        version_match = re.search(
            r"(?:^|\s)version\s*=\s*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if version_match and in_commitizen_section:
            info.version = version_match.group(1)

        tag_match = re.search(
            r"tag[_-]?format\s*=\s*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if tag_match:
            info.tag_format = tag_match.group(1)

        if BUMP_HOOK_PATTERN.search(stripped):
            hook_name = stripped.split("=", 1)[0].strip()
            if hook_name and hook_name not in info.bump_hooks:
                info.bump_hooks.append(hook_name)

        if not in_commitizen_section and rel != "pyproject.toml":
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Commitizen config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Commitizen config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Commitizen config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line) or DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="dangerous_hook",
                    severity="high",
                    message="dangerous command in Commitizen config — avoid eval/exec and remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HOOK_COMMAND_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="unsafe_bump_hook",
                    severity="high",
                    message="bump hook runs shell/download command — review for supply-chain risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_CHANGELOG_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="changelog_path_traversal",
                    severity="high",
                    message="changelog path points outside project — path traversal risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_CUSTOM_HOOKS_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="custom_hooks_enabled",
                    severity="medium",
                    message="custom hooks enabled — ensure hook scripts are reviewed and pinned",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MUTABLE_TAG_PATTERN.search(line):
            findings.append(
                CommitizenFinding(
                    kind="mutable_tag_config",
                    severity="low",
                    message="tag format or changelog bump settings may allow inconsistent releases",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[CommitizenFinding], CommitizenInfo]:
        findings: list[CommitizenFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, CommitizenInfo(path=rel)

        info = CommitizenInfo(path=rel, lines=len(raw_lines))
        in_commitizen = rel != "pyproject.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            stripped = raw.strip()
            if stripped in ("[tool.commitizen]", "[commitizen]"):
                in_commitizen = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                if rel == "pyproject.toml":
                    in_commitizen = stripped.lower() in ("[tool.commitizen]", "[commitizen]")
                continue
            self._scan_line(raw, lineno, rel, findings, info, in_commitizen)

        return findings, info

    def analyze(self) -> list[CommitizenFinding]:
        """Scan Commitizen config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CommitizenFinding] = []
        infos: list[CommitizenInfo] = []
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
        self._stats = CommitizenStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CommitizenStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CommitizenInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0 or stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_template(self) -> str:
        return """\
# Generated by DevAI CommitizenAnalyzer
[tool.commitizen]
name = "cz_conventional_commits"
version = "0.0.0"
tag_format = "v$version"
version_scheme = "pep440"
version_provider = "pep621"
update_changelog_on_bump = true
major_version_zero = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Commitizen: no config files found"
        return (
            f"Commitizen: {stats.config_files} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Commitizen configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            version = info.version or "unknown"
            tag = info.tag_format or "default"
            lines.append(f"  - {info.path}: version={version}, tag_format={tag}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
