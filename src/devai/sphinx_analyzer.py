"""SphinxAnalyzer — audit Sphinx conf.py documentation configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONF_NAMES = ("conf.py",)
SPHINX_DIRS = ("docs", "doc", "sphinx", "documentation")

DANGEROUS_EXEC_PATTERN = re.compile(
    r"(os\.system|subprocess\.|eval\s*\(|exec\s*\(|__import__\s*\()",
    re.IGNORECASE,
)
SECRET_IN_CONFIG_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*=\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
HTML_THEME_DEV_PATTERN = re.compile(
    r"html_theme_options\s*=\s*\{[^}]*dev_mode\s*:\s*True",
    re.IGNORECASE,
)
INSECURE_EXTENSION_PATTERN = re.compile(
    r"extensions\s*=\s*\[[^\]]*['\"]sphinxcontrib\.programoutput['\"]",
    re.IGNORECASE,
)
AUTODOC_DEFAULT_ALL_PATTERN = re.compile(
    r"autodoc_default_options\s*=\s*\{[^}]*['\"]members['\"]\s*:\s*True",
    re.IGNORECASE,
)
MISSING_INTERSPHINX_PATTERN = re.compile(r"intersphinx_mapping", re.IGNORECASE)
EVAL_RST_PATTERN = re.compile(r"eval_rst\s*=", re.IGNORECASE)
HTTP_BASE_URL_PATTERN = re.compile(
    r"(html_baseurl|base_url)\s*=\s*['\"]http://",
    re.IGNORECASE,
)


@dataclass
class SphinxFinding:
    """A security or best-practice issue in a Sphinx conf.py file."""

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
class SphinxInfo:
    """Parsed metadata about a Sphinx conf.py file."""

    path: str
    project: str | None = None
    extensions: list[str] = field(default_factory=list)
    html_theme: str | None = None
    has_intersphinx: bool = False
    lines: int = 0


@dataclass
class SphinxStats:
    """Aggregate Sphinx conf.py analysis statistics."""

    config_files: int
    findings: int
    extensions: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_sphinx_conf(path: Path) -> bool:
    if path.name != "conf.py":
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(SPHINX_DIRS):
        return True
    return any(d in parts for d in SPHINX_DIRS)


class SphinxAnalyzer:
    """Audit Sphinx conf.py files for dangerous exec patterns, secrets, and weak defaults.

    Scans documentation conf.py for subprocess/eval usage, hardcoded secrets,
    dev_mode theme options, risky extensions, and missing intersphinx mappings.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[SphinxFinding] | None = None
        self._stats: SphinxStats | None = None
        self._infos: list[SphinxInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Sphinx conf.py paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("conf.py")):
            if path.is_file() and _is_sphinx_conf(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[SphinxFinding], SphinxInfo]:
        findings: list[SphinxFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, SphinxInfo(path=rel)

        info = SphinxInfo(path=rel, lines=len(raw_lines))
        in_extensions = False
        extensions_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("project =") or line.startswith("project="):
                info.project = line.split("=", 1)[1].strip().strip("'\"")
                continue

            if line.startswith("html_theme =") or line.startswith("html_theme="):
                info.html_theme = line.split("=", 1)[1].strip().strip("'\"")
                continue

            if MISSING_INTERSPHINX_PATTERN.search(line):
                info.has_intersphinx = True

            if line.startswith("extensions") and "=" in line:
                inline = line.split("=", 1)[1].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    for item in inline[1:-1].split(","):
                        ext = item.strip().strip("'\"")
                        if ext:
                            info.extensions.append(ext)
                else:
                    in_extensions = True
                    extensions_indent = len(raw) - len(raw.lstrip())
                continue

            if in_extensions:
                current_indent = len(raw) - len(raw.lstrip())
                if current_indent <= extensions_indent and not line.startswith("'") and not line.startswith('"'):
                    in_extensions = False
                elif line.startswith("'") or line.startswith('"'):
                    ext = line.strip().strip("'\",\n")
                    if ext:
                        info.extensions.append(ext)

            if DANGEROUS_EXEC_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="dangerous_exec",
                        severity="high",
                        message="conf.py uses exec/subprocess — review for code injection risk",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_IN_CONFIG_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="secret_in_config",
                        severity="high",
                        message="potential secret hardcoded in conf.py — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HTML_THEME_DEV_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="dev_mode_theme",
                        severity="medium",
                        message="html_theme_options enables dev_mode — disable for production builds",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_EXTENSION_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="risky_extension",
                        severity="medium",
                        message="sphinxcontrib.programoutput can execute shell commands — review usage",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EVAL_RST_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="eval_rst",
                        severity="high",
                        message="eval_rst enabled — arbitrary Python execution in docs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HTTP_BASE_URL_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="http_base_url",
                        severity="medium",
                        message="base URL uses http:// — prefer https:// for production docs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AUTODOC_DEFAULT_ALL_PATTERN.search(line):
                findings.append(
                    SphinxFinding(
                        kind="autodoc_all_members",
                        severity="low",
                        message="autodoc_default_options exposes all members — consider explicit API surface",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.extensions and not info.has_intersphinx:
            findings.append(
                SphinxFinding(
                    kind="missing_intersphinx",
                    severity="low",
                    message="no intersphinx_mapping — cross-project doc links may be missing",
                    path=rel,
                    lineno=0,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[SphinxFinding]:
        """Scan Sphinx conf.py files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[SphinxFinding] = []
        infos: list[SphinxInfo] = []
        paths = self.config_files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        total_extensions = sum(len(i.extensions) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = SphinxStats(
            config_files=len(paths),
            findings=len(findings),
            extensions=total_extensions,
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> SphinxStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[SphinxInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no config files)."""
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
        """Scaffold a hardened Sphinx conf.py template snippet."""
        return """\
# Generated by DevAI SphinxAnalyzer
import os

project = "My Project"
copyright = "2026, My Org"
author = "My Org"

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

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# Use environment variables for secrets — never hardcode tokens here
# api_key = os.environ.get("DOCS_API_KEY")
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Sphinx: no conf.py files found"
        return (
            f"Sphinx: {stats.config_files} conf.py file(s), {stats.extensions} extension(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Sphinx configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  extensions: {stats.extensions}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            project = info.project or "unnamed"
            theme = info.html_theme or "default"
            ext_count = len(info.extensions)
            lines.append(f"  - {info.path}: {project}, theme={theme}, {ext_count} extension(s)")
            for ext in info.extensions[:8]:
                lines.append(f"      - {ext}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
