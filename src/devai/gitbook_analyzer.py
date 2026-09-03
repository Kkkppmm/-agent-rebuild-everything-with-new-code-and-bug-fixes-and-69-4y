"""GitBookAnalyzer — audit .gitbook.yaml and book.json for documentation security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

YAML_CONFIG_NAMES = (
    ".gitbook.yaml",
    ".gitbook.yml",
    "gitbook.yaml",
    "gitbook.yml",
)
JSON_CONFIG_NAMES = ("book.json",)

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
    r"://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
ROOT_PARENT_PATTERN = re.compile(
    r"^\s*root\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)
EXTERNAL_SCRIPT_PATTERN = re.compile(
    r"(?:<script[^>]+src|javascript:)\s*=\s*['\"]?(?:https?://|//)",
    re.IGNORECASE,
)
DANGEROUS_PLUGIN_PATTERN = re.compile(
    r"(?:gitbook-plugin-)?(?:ga|google-analytics|disqus|livereload|sharing|"
    r"custom-favicon|theme-api|sitemap|livereload)",
    re.IGNORECASE,
)
VARIABLES_SECRET_PATTERN = re.compile(
    r"(?:variables|env)\s*:[^\n]*(?:secret|token|password|api[_-]?key)",
    re.IGNORECASE,
)
REMOTE_PLUGIN_PATTERN = re.compile(
    r"(?:https?://|git\+https?://)[^\s\"']+",
    re.IGNORECASE,
)
STRUCTURE_PARENT_PATTERN = re.compile(
    r"(?:readme|summary)\s*:\s*['\"]?\.\./",
    re.IGNORECASE,
)


@dataclass
class GitBookFinding:
    """A security or best-practice issue in a GitBook configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class GitBookInfo:
    """Parsed metadata about a GitBook configuration file."""

    path: str
    lines: int = 0
    format: str = "yaml"
    title: str | None = None
    plugins: list[str] = field(default_factory=list)
    has_variables: bool = False


@dataclass
class GitBookStats:
    """Aggregate GitBook analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_yaml_config(path: Path) -> bool:
    return path.name in YAML_CONFIG_NAMES


def _is_json_config(path: Path) -> bool:
    return path.name in JSON_CONFIG_NAMES


class GitBookAnalyzer:
    """Audit GitBook configuration for documentation security and hygiene risks.

    Scans .gitbook.yaml/.gitbook.yml and book.json for hardcoded secrets,
    insecure URLs, parent-directory roots, remote plugins, and tracking scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GitBookFinding] | None = None
        self._stats: GitBookStats | None = None
        self._infos: list[GitBookInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return GitBook configuration paths found in the project."""
        found: list[Path] = []
        for name in YAML_CONFIG_NAMES + JSON_CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and (
                _is_yaml_config(path) or _is_json_config(path)
            ) and path not in found:
                found.append(path)
        return found

    def _add_finding(
        self,
        findings: list[GitBookFinding],
        kind: str,
        severity: str,
        message: str,
        rel: str,
        lineno: int,
        line: str,
    ) -> None:
        findings.append(
            GitBookFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=rel,
                lineno=lineno,
                line=line,
            )
        )

    def _scan_yaml_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GitBookFinding],
        info: GitBookInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if key in ("plugins", "pluginsConfig", "variables", "redirects"):
                section = key
            else:
                section = key

        if stripped.startswith("title:"):
            info.title = stripped.split(":", 1)[1].strip().strip("'\"")

        if section == "plugins" and stripped.startswith("- "):
            plugin = stripped[2:].strip().strip("'\"")
            if plugin:
                info.plugins.append(plugin.split(":")[0])

        if section == "variables":
            info.has_variables = True

        checks = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in GitBook config — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in GitBook config — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in GitBook config — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL — remove user:pass@"),
            (ROOT_PARENT_PATTERN, "root_parent_path", "medium", "root points outside project — restrict to trusted directories"),
            (STRUCTURE_PARENT_PATTERN, "structure_parent_path", "medium", "readme/summary path escapes project — use local paths"),
            (DANGEROUS_PLUGIN_PATTERN, "tracking_plugin", "low", "tracking/analytics plugin may leak visitor data — review privacy settings"),
            (VARIABLES_SECRET_PATTERN, "variables_secret", "high", "secret-like value in variables block — use CI secrets instead"),
            (REMOTE_PLUGIN_PATTERN, "remote_plugin", "high", "remote plugin URL — only install trusted local plugins"),
            (EXTERNAL_SCRIPT_PATTERN, "external_script", "medium", "external script reference — self-host or pin with SRI"),
        ]
        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                self._add_finding(findings, kind, severity, message, rel, lineno, line)

        return section

    def _analyze_yaml(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, GitBookInfo(path=rel, format="yaml")

        info = GitBookInfo(path=rel, lines=len(raw_lines), format="yaml")
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_yaml_line(line, lineno, rel, findings, info, section)

        return findings, info

    def _analyze_json(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        findings: list[GitBookFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, GitBookInfo(path=rel, format="json")

        info = GitBookInfo(path=rel, lines=len(raw_lines), format="json")

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            if '"title"' in stripped:
                match = re.search(r'"title"\s*:\s*"([^"]+)"', stripped)
                if match:
                    info.title = match.group(1)

            if '"plugins"' in stripped or stripped.startswith('"gitbook-plugin'):
                plugin_match = re.search(r'"([^"]+)"', stripped)
                if plugin_match:
                    info.plugins.append(plugin_match.group(1))

            checks = [
                (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in book.json — use env vars or CI secrets"),
                (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in book.json — rotate and use env vars"),
                (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in book.json — use HTTPS endpoints"),
                (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL — remove user:pass@"),
                (DANGEROUS_PLUGIN_PATTERN, "tracking_plugin", "low", "tracking/analytics plugin may leak visitor data — review privacy settings"),
                (REMOTE_PLUGIN_PATTERN, "remote_plugin", "high", "remote plugin URL — only install trusted local plugins"),
            ]
            for pattern, kind, severity, message in checks:
                if pattern.search(line):
                    self._add_finding(findings, kind, severity, message, rel, lineno, line)

        try:
            data = json.loads(content)
            if isinstance(data, dict):
                plugins = data.get("plugins", [])
                if isinstance(plugins, list):
                    info.plugins = [str(p) for p in plugins]
                if data.get("variables"):
                    info.has_variables = True
        except json.JSONDecodeError:
            self._add_finding(
                findings,
                "invalid_json",
                "medium",
                "book.json is not valid JSON — fix syntax before publishing",
                rel,
                1,
                raw_lines[0] if raw_lines else "",
            )

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[GitBookFinding], GitBookInfo]:
        if _is_json_config(path):
            return self._analyze_json(path)
        return self._analyze_yaml(path)

    def analyze(self) -> list[GitBookFinding]:
        """Scan GitBook configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GitBookFinding] = []
        infos: list[GitBookInfo] = []
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
        self._stats = GitBookStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GitBookStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GitBookInfo]:
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
        """Scaffold a hardened GitBook configuration template."""
        return """\
# Generated by DevAI GitBookAnalyzer
root: ./

structure:
  readme: README.md
  summary: SUMMARY.md

# Use local plugins only; avoid tracking/analytics plugins unless required
plugins: []

# Store secrets in CI environment variables, not in config
variables: {}

redirects: {}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "GitBook configs: none found"
        return (
            f"GitBook configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "GitBook analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
