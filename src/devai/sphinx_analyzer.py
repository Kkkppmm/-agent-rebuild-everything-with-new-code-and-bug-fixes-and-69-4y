"""SphinxAnalyzer — audit Sphinx conf.py for documentation security and hygiene risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAME = "conf.py"
SPHINX_MARKERS = (
    "sphinx",
    "extensions",
    "html_theme",
    "master_doc",
    "project",
    "release",
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
    r"(?:html_baseurl|baseurl|repo_url|edit_uri)\s*=\s*[^\n]*://[^:\s/]+:[^@\s/]+@",
    re.IGNORECASE,
)
SYS_PATH_PARENT_PATTERN = re.compile(
    r"sys\.path\.(?:insert|append)\s*\([^)]*(?:\.\./|/tmp/|/etc/)",
    re.IGNORECASE,
)
EVAL_EXEC_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
OS_SYSTEM_PATTERN = re.compile(r"\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen)\s*\(", re.IGNORECASE)
NITPICKY_FALSE_PATTERN = re.compile(r"^\s*nitpicky\s*=\s*False\b", re.IGNORECASE)
BROAD_LINKCHECK_IGNORE_PATTERN = re.compile(
    r"linkcheck_ignore\s*=\s*\[[^\]]*(?:\*|http://|https://\*)",
    re.IGNORECASE,
)
AUTODOC_ALL_MEMBERS_PATTERN = re.compile(
    r"autodoc_default_options\s*=\s*\{[^\}]*['\"]members['\"]\s*:\s*True",
    re.IGNORECASE,
)
MOCK_IMPORTS_WILDCARD_PATTERN = re.compile(
    r"autodoc_mock_imports\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
INTERACTIVE_EXTENSION_PATTERN = re.compile(
    r"['\"]sphinxcontrib\.(?:programoutput|shell|bash)['\"]",
    re.IGNORECASE,
)
VIEWCODE_IMPORT_PATTERN = re.compile(
    r"['\"]sphinx\.ext\.viewcode['\"]",
    re.IGNORECASE,
)


@dataclass
class SphinxFinding:
    """A security or best-practice issue in a Sphinx configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class SphinxInfo:
    """Parsed metadata about a Sphinx configuration file."""

    path: str
    lines: int = 0
    project: str | None = None
    extensions: list[str] = field(default_factory=list)
    has_intersphinx: bool = False
    has_viewcode: bool = False


@dataclass
class SphinxStats:
    """Aggregate Sphinx analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_sphinx_config(content: str) -> bool:
    lowered = content.lower()
    return any(marker in lowered for marker in SPHINX_MARKERS)


def _is_sphinx_conf(path: Path) -> bool:
    if path.name != CONFIG_NAME:
        return False
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _looks_like_sphinx_config(content)


class SphinxAnalyzer:
    """Audit Sphinx conf.py for documentation security and hygiene risks.

    Scans conf.py for hardcoded secrets, unsafe sys.path manipulation,
    eval/exec usage, insecure intersphinx URLs, and overly permissive autodoc.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SphinxFinding] | None = None
        self._stats: SphinxStats | None = None
        self._infos: list[SphinxInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Sphinx conf.py paths found in the project."""
        found: list[Path] = []
        preferred_dirs = ("docs", "doc", "sphinx", "documentation")
        for dirname in preferred_dirs:
            path = self.root / dirname / CONFIG_NAME
            if path.is_file() and _is_sphinx_conf(path):
                found.append(path)
        root_conf = self.root / CONFIG_NAME
        if root_conf.is_file() and _is_sphinx_conf(root_conf) and root_conf not in found:
            found.append(root_conf)
        for path in sorted(self.root.rglob(CONFIG_NAME)):
            if path.is_file() and _is_sphinx_conf(path) and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[SphinxFinding],
        info: SphinxInfo,
        section: str,
    ) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return section

        if stripped.startswith(("html_js_files", "html_script_tags")) and "=" in stripped:
            section = "html_js_files"
        elif stripped == "]" and section == "html_js_files":
            section = ""

        if stripped.startswith("project ="):
            info.project = stripped.split("=", 1)[1].strip().strip("'\"")

        if "extensions" in stripped and ("[" in stripped or stripped.endswith("=")):
            for match in re.finditer(r"['\"]([^'\"]+)['\"]", stripped):
                ext = match.group(1)
                if "." in ext or ext.startswith("sphinx"):
                    info.extensions.append(ext)

        if "intersphinx_mapping" in stripped:
            info.has_intersphinx = True

        if VIEWCODE_IMPORT_PATTERN.search(stripped):
            info.has_viewcode = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high", "hardcoded secret in Sphinx conf.py — use env vars or CI secrets"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high", "AWS access key in Sphinx conf.py — rotate and use env vars"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "medium", "insecure HTTP URL in Sphinx conf.py — use HTTPS endpoints"),
            (CREDENTIAL_IN_URL_PATTERN, "credential_in_url", "high", "credentials embedded in URL setting — remove user:pass@"),
            (SYS_PATH_PARENT_PATTERN, "unsafe_sys_path", "high", "sys.path includes parent or system directory — restrict to project paths"),
            (EVAL_EXEC_PATTERN, "eval_exec", "high", "eval/exec in Sphinx conf.py — avoid dynamic code execution in config"),
            (OS_SYSTEM_PATTERN, "shell_execution", "high", "shell/subprocess call in Sphinx conf.py — avoid command execution in config"),
            (NITPICKY_FALSE_PATTERN, "nitpicky_false", "medium", "nitpicky = False disables broken-reference warnings — keep nitpicky enabled"),
            (BROAD_LINKCHECK_IGNORE_PATTERN, "broad_linkcheck_ignore", "low", "linkcheck_ignore is too broad — narrow ignored URLs"),
            (AUTODOC_ALL_MEMBERS_PATTERN, "autodoc_all_members", "low", "autodoc_default_options exposes all members — document only public API"),
            (MOCK_IMPORTS_WILDCARD_PATTERN, "mock_imports_wildcard", "medium", "autodoc_mock_imports uses wildcard — mock only required modules"),
            (INTERACTIVE_EXTENSION_PATTERN, "interactive_extension", "high", "sphinxcontrib shell/program extensions execute commands during build"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(line):
                findings.append(
                    SphinxFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if section == "html_js_files" and re.search(r"https?://", stripped):
            findings.append(
                SphinxFinding(
                    kind="external_script",
                    severity="medium",
                    message="html_js_files loads remote script — pin version and self-host assets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        return section

    def _analyze_file(self, path: Path) -> tuple[list[SphinxFinding], SphinxInfo]:
        findings: list[SphinxFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, SphinxInfo(path=rel)

        info = SphinxInfo(path=rel, lines=len(raw_lines))
        section = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            section = self._scan_line(line, lineno, rel, findings, info, section)

        return findings, info

    def analyze(self) -> list[SphinxFinding]:
        """Scan Sphinx configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SphinxFinding] = []
        infos: list[SphinxInfo] = []
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
        self._stats = SphinxStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SphinxStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SphinxInfo]:
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
        """Scaffold a hardened Sphinx conf.py template."""
        return """\
# Generated by DevAI SphinxAnalyzer
import os
import sys

project = "My Project"
copyright = "2026, My Organization"
author = "My Organization"
release = "1.0.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

nitpicky = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# Self-host assets instead of loading remote scripts
html_js_files: list[str] = []
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Sphinx configs: none found"
        return (
            f"Sphinx configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Sphinx analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for finding in self._findings or []:
            lines.append(f"  - {finding.format()}")
        return "\n".join(lines)
