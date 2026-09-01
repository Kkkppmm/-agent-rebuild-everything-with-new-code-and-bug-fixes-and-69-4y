"""TowncrierAnalyzer — audit Towncrier changelog configs for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "towncrier.toml",
    ".towncrier.toml",
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
TOWNCRIER_MARKER_PATTERN = re.compile(
    r"(?:^\[tool\.towncrier\]|^\[towncrier\]|towncrier\s*=)",
    re.IGNORECASE | re.MULTILINE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:directory|filename|template|issue[_-]?link|title[_-]?format)\s*=\s*[\"']\.\./",
    re.IGNORECASE,
)
UNSAFE_TEMPLATE_PATTERN = re.compile(
    r"(?:template|title[_-]?format|issue[_-]?link)\s*=\s*[\"'][^\"']*(?:\{\{|\{%|eval|exec)",
    re.IGNORECASE,
)
FRAGMENT_OUTSIDE_PATTERN = re.compile(
    r"(?:directory|under[_-]?directory)\s*=\s*[\"'](?:/etc/|/tmp/|\.ssh/)",
    re.IGNORECASE,
)
INSECURE_ISSUE_LINK_PATTERN = re.compile(
    r"issue[_-]?link\s*=\s*[\"']http://",
    re.IGNORECASE,
)
CREATE_IF_MISSING_DISABLED_PATTERN = re.compile(
    r"create[_-]?if[_-]?missing\s*=\s*false",
    re.IGNORECASE,
)
WRAPPED_NEWS_PATTERN = re.compile(
    r"wrap[_-]?text\s*=\s*false",
    re.IGNORECASE,
)
EMPTY_FRAGMENTS_PATTERN = re.compile(
    r"(?:directory|filename)\s*=\s*[\"'][\"']",
    re.IGNORECASE,
)


@dataclass
class TowncrierFinding:
    """A security or best-practice issue in a Towncrier configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TowncrierInfo:
    """Parsed metadata about a Towncrier configuration file."""

    path: str
    lines: int = 0
    directory: str | None = None
    filename: str | None = None
    package: str | None = None


@dataclass
class TowncrierStats:
    """Aggregate Towncrier analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


class TowncrierAnalyzer:
    """Audit Towncrier changelog configuration for security risks.

    Scans pyproject.toml [tool.towncrier], towncrier.toml, and .towncrier.toml
    for hardcoded secrets, path traversal in fragment directories, unsafe
    Jinja templates, insecure HTTP issue links, and missing changelog safeguards.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TowncrierFinding] | None = None
        self._stats: TowncrierStats | None = None
        self._infos: list[TowncrierInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Towncrier configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
                if TOWNCRIER_MARKER_PATTERN.search(text):
                    found.append(pyproject)
            except OSError:
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[TowncrierFinding],
        info: TowncrierInfo,
        in_towncrier_section: bool,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        dir_match = re.search(
            r"(?:directory|under[_-]?directory)\s*=\s*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if dir_match:
            info.directory = dir_match.group(1)

        filename_match = re.search(
            r"filename\s*=\s*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if filename_match:
            info.filename = filename_match.group(1)

        package_match = re.search(
            r"package\s*=\s*[\"']([^\"']+)[\"']",
            stripped,
            re.IGNORECASE,
        )
        if package_match:
            info.package = package_match.group(1)

        if not in_towncrier_section and rel != "pyproject.toml":
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Towncrier config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Towncrier config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Towncrier config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PATH_TRAVERSAL_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="path_traversal",
                    severity="high",
                    message="Towncrier path points outside project — path traversal risk",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FRAGMENT_OUTSIDE_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="sensitive_fragment_path",
                    severity="high",
                    message="fragment directory in sensitive system path — review access controls",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_TEMPLATE_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="unsafe_template",
                    severity="high",
                    message="Towncrier template may allow code injection — use safe Jinja defaults",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_ISSUE_LINK_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="insecure_issue_link",
                    severity="medium",
                    message="issue_link uses HTTP — use HTTPS for issue tracker URLs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CREATE_IF_MISSING_DISABLED_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="create_if_missing_disabled",
                    severity="low",
                    message="create_if_missing=false may cause release failures — review changelog workflow",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EMPTY_FRAGMENTS_PATTERN.search(line):
            findings.append(
                TowncrierFinding(
                    kind="empty_path",
                    severity="medium",
                    message="empty directory or filename in Towncrier config — review changelog paths",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[TowncrierFinding], TowncrierInfo]:
        findings: list[TowncrierFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TowncrierInfo(path=rel)

        info = TowncrierInfo(path=rel, lines=len(raw_lines))
        in_towncrier = rel != "pyproject.toml"

        for lineno, raw in enumerate(raw_lines, start=1):
            stripped = raw.strip()
            if stripped in ("[tool.towncrier]", "[towncrier]"):
                in_towncrier = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                if rel == "pyproject.toml":
                    in_towncrier = stripped.lower() in ("[tool.towncrier]", "[towncrier]")
                continue
            self._scan_line(raw, lineno, rel, findings, info, in_towncrier)

        return findings, info

    def analyze(self) -> list[TowncrierFinding]:
        """Scan Towncrier config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TowncrierFinding] = []
        infos: list[TowncrierInfo] = []
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
        self._stats = TowncrierStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TowncrierStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TowncrierInfo]:
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
# Generated by DevAI TowncrierAnalyzer
[tool.towncrier]
package = "my_package"
directory = "changelog.d"
filename = "CHANGELOG.md"
title_format = "## [{version}] - {project_date}"
issue_format = "[#{issue}](https://github.com/org/repo/issues/{issue})"
create_if_missing = true
wrap = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Towncrier: no config files found"
        return (
            f"Towncrier: {stats.config_files} config(s), {stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Towncrier configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            directory = info.directory or "default"
            filename = info.filename or "default"
            lines.append(f"  - {info.path}: directory={directory}, filename={filename}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
