"""MdBookAnalyzer — audit book.toml for mdBook documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "book.toml",
)

MDBOOK_MARKERS = (
    "title",
    "authors",
    "src",
    "language",
    "output.html",
    "preprocessor",
    "build",
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
CREDENTIAL_IN_URL_PATTERN = re.compile(
    r"(?:git[-_]repository[-_]url|site[-_]url|edit[-_]url[-_]template)\s*=\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
REMOTE_JS_PATTERN = re.compile(
    r"(?:additional[-_]js|mathjax[-_]support)\s*=\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
REMOTE_CSS_PATTERN = re.compile(
    r"(?:additional[-_]css)\s*=\s*\[[^\]]*https?://",
    re.IGNORECASE,
)
REMOTE_JS_LINE_PATTERN = re.compile(
    r"^\s*['\"]https?://[^\s\"']+['\"]",
    re.IGNORECASE,
)
PLAYGROUND_ENABLED_PATTERN = re.compile(
    r"(?:playground|playpen)\s*=\s*\{[^\}]*editable\s*=\s*true",
    re.IGNORECASE,
)
PLAYGROUND_LINE_PATTERN = re.compile(
    r"^\s*editable\s*=\s*true\b",
    re.IGNORECASE,
)
GIT_TOKEN_PATTERN = re.compile(
    r"(?:git[-_]repository[-_]url|edit[-_]url[-_]template)\s*=\s*[^\n]*(?:ghp_|github_pat_|glpat-)",
    re.IGNORECASE,
)
OPEN_REDIRECT_PATTERN = re.compile(
    r"(?:redirect|destination)\s*=\s*['\"]https?://",
    re.IGNORECASE,
)
INSECURE_CNAME_PATTERN = re.compile(
    r"cname\s*=\s*['\"]http://",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
GOOGLE_ANALYTICS_INLINE_PATTERN = re.compile(
    r"(?:google-analytics|gtag)\s*=\s*['\"]?[A-Z]{2}-[A-Z0-9-]+['\"]?",
    re.IGNORECASE,
)


@dataclass
class MdBookFinding:
    """A security or best-practice issue in an mdBook configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MdBookInfo:
    """Parsed metadata about an mdBook configuration file."""

    path: str
    lines: int = 0
    title: str | None = None
    src: str | None = None
    has_html_output: bool = False
    has_playground: bool = False


@dataclass
class MdBookStats:
    """Aggregate mdBook analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_mdbook_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker.lower() in lowered for marker in MDBOOK_MARKERS)


def _is_mdbook_config(path: Path) -> bool:
    if path.name not in CONFIG_NAMES:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_mdbook_config(content)


class MdBookAnalyzer:
    """Audit mdBook configuration for documentation security and hygiene risks.

    Scans book.toml for hardcoded secrets, remote script includes, editable
  playgrounds, git tokens in repository URLs, and insecure site URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[MdBookFinding] | None = None
        self._stats: MdBookStats | None = None
        self._infos: list[MdBookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return mdBook configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file() and _is_mdbook_config(path):
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_mdbook_config(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MdBookFinding],
        info: MdBookInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section == "output.html":
                info.has_html_output = True
            if "playground" in section or "playpen" in section:
                info.has_playground = True
            return section

        if stripped.startswith("title") and "=" in stripped:
            _, _, value = stripped.partition("=")
            info.title = value.strip().strip("'\"")
        if stripped.startswith("src") and "=" in stripped:
            _, _, value = stripped.partition("=")
            info.src = value.strip().strip("'\"")

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in mdBook config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in mdBook config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in mdBook config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in repository URL — remove user:pass@"),
            (GIT_TOKEN_PATTERN, "git_token", "high", "git token in repository URL — rotate and use CI secrets"),
            (REMOTE_JS_PATTERN, "remote_script", "medium", "additional-js loads remote script — pin version and self-host assets"),
            (REMOTE_CSS_PATTERN, "remote_stylesheet", "low", "additional-css loads remote stylesheet — pin version or self-host assets"),
            (PLAYGROUND_ENABLED_PATTERN, "editable_playground", "medium", "editable Rust playground enabled — restrict to trusted examples"),
            (OPEN_REDIRECT_PATTERN, "open_redirect", "medium", "redirect points to external URL — validate destination allowlist"),
            (INSECURE_CNAME_PATTERN, "insecure_cname", "medium", "cname uses HTTP — use HTTPS for custom domains"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in mdBook config — avoid dynamic code execution in config"),
            (GOOGLE_ANALYTICS_INLINE_PATTERN, "inline_analytics", "low", "inline analytics ID — prefer env-based configuration"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    MdBookFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if section in ("output.html", "output.html.playground") and REMOTE_JS_LINE_PATTERN.search(line):
            findings.append(
                MdBookFinding(
                    kind="remote_script",
                    severity="medium",
                    message="additional-js loads remote script — pin version and self-host assets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if section in ("output.html.playground", "output.html.playpen") and PLAYGROUND_LINE_PATTERN.search(line):
            findings.append(
                MdBookFinding(
                    kind="editable_playground",
                    severity="medium",
                    message="editable Rust playground enabled — restrict to trusted examples",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[MdBookFinding], MdBookInfo]:
        findings: list[MdBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MdBookInfo(path=rel)

        info = MdBookInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

        return findings, info

    def analyze(self) -> list[MdBookFinding]:
        """Scan mdBook configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MdBookFinding] = []
        infos: list[MdBookInfo] = []
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
        self._stats = MdBookStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MdBookStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MdBookInfo]:
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
        """Scaffold a hardened mdBook configuration template."""
        return """\
# Generated by DevAI MdBookAnalyzer
[book]
title = "My Project Docs"
authors = ["Dev Team"]
language = "en"
src = "src"

[build]
create-missing = false

[output.html]
site-url = "https://example.com/"
git-repository-url = "https://github.com/org/repo"
edit-url-template = "https://github.com/org/repo/edit/main/{path}"
additional-css = []
additional-js = []

[output.html.playground]
editable = false
copyable = true
line-numbers = true
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "mdBook configs: none found"
        return (
            f"mdBook configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "mdBook analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
