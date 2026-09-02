"""MkDocsAnalyzer — audit MkDocs configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = ("mkdocs.yml", "mkdocs.yaml")

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
DEV_ADDR_PUBLIC_PATTERN = re.compile(
    r"dev_addr\s*:\s*['\"]?0\.0\.0\.0",
    re.IGNORECASE,
)
STRICT_FALSE_PATTERN = re.compile(
    r"^\s*strict\s*:\s*(?:false|no|0)\s*(?:#.*)?$",
    re.IGNORECASE,
)
HOOKS_PATTERN = re.compile(r"^\s*hooks\s*:", re.IGNORECASE)
HOOK_MODULE_PATTERN = re.compile(
    r"^\s*-\s*['\"]?([a-zA-Z0-9_.]+)['\"]?\s*(?:#.*)?$",
)
EXTERNAL_SCRIPT_PATTERN = re.compile(
    r"^\s*-\s*['\"]?(https?://[^'\"]+)['\"]?\s*(?:#.*)?$",
    re.IGNORECASE,
)
SNIPPETS_BASE_PATH_PATTERN = re.compile(
    r"base_path\s*:\s*['\"]?(?:\.|/|\.\./|/)['\"]?\s*(?:#.*)?$",
    re.IGNORECASE,
)
JAVASCRIPT_URI_PATTERN = re.compile(
    r"(?:edit_uri|site_url|repo_url)\s*:\s*['\"]?(?:javascript|data):",
    re.IGNORECASE,
)
REMOTE_THEME_PATTERN = re.compile(
    r"^\s*name\s*:\s*['\"]?(?:git\+)?https?://[^'\"]+['\"]?\s*(?:#.*)?$",
    re.IGNORECASE,
)
UNPINNED_GIT_THEME_PATTERN = re.compile(
    r"git\+https?://[^'\"]+['\"]?\s*$",
    re.IGNORECASE,
)
GOOGLE_ANALYTICS_PATTERN = re.compile(
    r"google_analytics\s*:\s*['\"]?[A-Z]{1,2}-[A-Z0-9-]+['\"]?\s*(?:#.*)?$",
    re.IGNORECASE,
)
PRIVACY_DISABLED_PATTERN = re.compile(
    r"^\s*#\s*-\s*privacy\b|^\s*privacy\s*:\s*(?:false|no|0|null)\s*(?:#.*)?$",
    re.IGNORECASE,
)
VALIDATION_DISABLED_PATTERN = re.compile(
    r"^\s*#\s*-\s*validation\b|^\s*validation\s*:\s*(?:false|no|0)\s*(?:#.*)?$",
    re.IGNORECASE,
)
MACROS_INCLUDE_PATTERN = re.compile(
    r"include_yaml\s*:\s*['\"]?(?:/|\.\./)[^'\"]*['\"]?\s*(?:#.*)?$",
    re.IGNORECASE,
)


@dataclass
class MkDocsFinding:
    """A security or best-practice issue in an MkDocs configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class MkDocsInfo:
    """Parsed metadata about an MkDocs configuration file."""

    path: str
    lines: int = 0
    has_hooks: bool = False
    has_dev_addr: bool = False
    has_extra_javascript: bool = False
    has_extra_css: bool = False
    strict_enabled: bool | None = None
    site_name: str = ""


@dataclass
class MkDocsStats:
    """Aggregate MkDocs analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_mkdocs_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


class MkDocsAnalyzer:
    """Audit MkDocs configuration for documentation hygiene and security risks.

    Scans `mkdocs.yml` and `mkdocs.yaml` for exposed dev servers, arbitrary hooks,
    insecure URLs, disabled validation, broad snippet base paths, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[MkDocsFinding] | None = None
        self._stats: MkDocsStats | None = None
        self._infos: list[MkDocsInfo] | None = None
        self._in_hooks = False
        self._in_extra_javascript = False
        self._in_extra_css = False
        self._in_theme = False

    def config_files(self) -> list[Path]:
        """Return MkDocs configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("mkdocs.y*ml")):
            if path.is_file() and path not in found and _is_mkdocs_config(path):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[MkDocsFinding],
        info: MkDocsInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped:
            return

        if stripped.startswith("#"):
            if PRIVACY_DISABLED_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="privacy_disabled",
                        severity="medium",
                        message="privacy plugin disabled or commented — third-party assets may leak visitor data",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if VALIDATION_DISABLED_PATTERN.search(line):
                findings.append(
                    MkDocsFinding(
                        kind="validation_disabled",
                        severity="low",
                        message="validation plugin disabled — broken links and nav issues may ship to production",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            return

        if HOOKS_PATTERN.search(line):
            self._in_hooks = True
            info.has_hooks = True
            findings.append(
                MkDocsFinding(
                    kind="hooks_enabled",
                    severity="high",
                    message="hooks execute arbitrary Python modules at build time — review carefully",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
            return

        if re.match(r"^\s*extra_javascript\s*:", line, re.IGNORECASE):
            self._in_extra_javascript = True
            info.has_extra_javascript = True
            self._in_extra_css = False
            self._in_hooks = False
            return

        if re.match(r"^\s*extra_css\s*:", line, re.IGNORECASE):
            self._in_extra_css = True
            info.has_extra_css = True
            self._in_extra_javascript = False
            self._in_hooks = False
            return

        if re.match(r"^\s*theme\s*:", line, re.IGNORECASE):
            self._in_theme = True
            self._in_hooks = False
            self._in_extra_javascript = False
            self._in_extra_css = False
            return

        if re.match(r"^\s*\w", line) and not line.startswith((" ", "\t", "-")):
            self._in_hooks = False
            self._in_extra_javascript = False
            self._in_extra_css = False
            self._in_theme = False

        if re.match(r"^\s*dev_addr\s*:", line, re.IGNORECASE):
            info.has_dev_addr = True

        if DEV_ADDR_PUBLIC_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="dev_addr_public",
                    severity="high",
                    message="dev_addr binds to 0.0.0.0 — exposes MkDocs dev server on all interfaces",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if STRICT_FALSE_PATTERN.search(line):
            info.strict_enabled = False
            findings.append(
                MkDocsFinding(
                    kind="strict_disabled",
                    severity="medium",
                    message="strict: false disables MkDocs config validation — typos may go unnoticed",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif re.match(r"^\s*strict\s*:\s*(?:true|yes|1)\s*(?:#.*)?$", line, re.IGNORECASE):
            info.strict_enabled = True

        if re.match(r"^\s*site_name\s*:", line, re.IGNORECASE):
            match = re.search(r"site_name\s*:\s*['\"]?([^'\"#]+)['\"]?", line, re.IGNORECASE)
            if match:
                info.site_name = match.group(1).strip()

        if self._in_hooks and HOOK_MODULE_PATTERN.match(line):
            module = HOOK_MODULE_PATTERN.match(line)
            if module:
                findings.append(
                    MkDocsFinding(
                        kind="hook_module",
                        severity="medium",
                        message=f"hook module '{module.group(1)}' runs at build time — verify it is trusted",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if (self._in_extra_javascript or self._in_extra_css) and (
            match := EXTERNAL_SCRIPT_PATTERN.match(line)
        ):
            url = match.group(1)
            findings.append(
                MkDocsFinding(
                    kind="external_asset",
                    severity="medium",
                    message=f"external asset without integrity check: {url}",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if self._in_theme and REMOTE_THEME_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="remote_theme",
                    severity="medium",
                    message="remote theme from URL — pin to a specific commit or use a packaged theme",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
            if UNPINNED_GIT_THEME_PATTERN.search(line) and "@" not in line:
                findings.append(
                    MkDocsFinding(
                        kind="unpinned_git_theme",
                        severity="high",
                        message="git theme URL without ref pin — supply chain risk on every build",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if SNIPPETS_BASE_PATH_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="snippets_base_path_broad",
                    severity="high",
                    message="pymdownx.snippets base_path is too broad — may include sensitive files",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if JAVASCRIPT_URI_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="dangerous_uri",
                    severity="high",
                    message="javascript: or data: URI in MkDocs config — potential XSS vector",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GOOGLE_ANALYTICS_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="google_analytics_legacy",
                    severity="low",
                    message="legacy google_analytics config — prefer the privacy plugin for GDPR compliance",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PRIVACY_DISABLED_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="privacy_disabled",
                    severity="medium",
                    message="privacy plugin disabled or commented — third-party assets may leak visitor data",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VALIDATION_DISABLED_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="validation_disabled",
                    severity="low",
                    message="validation plugin disabled — broken links and nav issues may ship to production",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if MACROS_INCLUDE_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="macros_external_include",
                    severity="high",
                    message="macros include_yaml references path outside project — may leak secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in MkDocs config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in MkDocs config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                MkDocsFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in MkDocs config — avoid remote code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[MkDocsFinding], MkDocsInfo]:
        findings: list[MkDocsFinding] = []
        rel = str(path.relative_to(self.root))

        self._in_hooks = False
        self._in_extra_javascript = False
        self._in_extra_css = False
        self._in_theme = False

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, MkDocsInfo(path=rel)

        info = MkDocsInfo(path=rel, lines=len(raw_lines))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[MkDocsFinding]:
        """Scan MkDocs configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[MkDocsFinding] = []
        infos: list[MkDocsInfo] = []
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
        self._stats = MkDocsStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> MkDocsStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[MkDocsInfo]:
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
        """Scaffold a hardened MkDocs configuration template."""
        return """\
site_name: My Project Docs
site_url: https://example.com/docs/
repo_url: https://github.com/org/repo
repo_name: org/repo
edit_uri: edit/main/docs/

strict: true

theme:
  name: material
  features:
    - content.code.copy
    - navigation.sections

plugins:
  - search
  - privacy
  - validation:
      nav:
        omitted_files: warn
        not_found: warn
      links:
        not_found: warn

markdown_extensions:
  - admonition
  - pymdownx.highlight
  - pymdownx.superfences
  - pymdownx.snippets:
      check_paths: true

dev_addr: 127.0.0.1:8000
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "mkdocs configs: none found"
        return (
            f"mkdocs configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "mkdocs config analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            strict = (
                "default"
                if info.strict_enabled is None
                else ("true" if info.strict_enabled else "false")
            )
            lines.append(
                f"  - {info.path}: site_name={info.site_name or 'unset'}, strict={strict}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
