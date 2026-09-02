"""Pep723Analyzer — audit PEP 723 inline script metadata blocks in Python files."""

from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PEP723_START_PATTERN = re.compile(r"^#\s*///\s*script\s*$", re.IGNORECASE)
PEP723_END_PATTERN = re.compile(r"^#\s*///\s*$")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
UNPINNED_DEP_PATTERN = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\[[^\]]+\])?\s*$",
)
LOOSE_VERSION_PATTERN = re.compile(
    r"(?:==\s*[\"']?\*[\"']?|[=<>!~]+\s*[\"']?\*[\"']?|"
    r"[=<>!~]+\s*[\"']?latest[\"']?|"
    r"(?<![=<>!~])>=\s*[\"']?\d|(?<![=<>!~])<=\s*[\"']?\d|"
    r"(?<![=<>!~])>\s*[\"']?\d|(?<![=<>!~])<\s*[\"']?\d)",
    re.IGNORECASE,
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:@main\b|@master\b|@HEAD\b|@develop\b|branch=main\b|branch=master\b)",
    re.IGNORECASE,
)
SCRIPT_DIR_NAMES = ("scripts", "bin", "tools", "cli")
STDLIB_MODULES = frozenset(
    {
        "__future__",
        "abc",
        "argparse",
        "ast",
        "asyncio",
        "base64",
        "collections",
        "contextlib",
        "copy",
        "csv",
        "dataclasses",
        "datetime",
        "enum",
        "functools",
        "hashlib",
        "http",
        "importlib",
        "inspect",
        "io",
        "itertools",
        "json",
        "logging",
        "math",
        "os",
        "pathlib",
        "re",
        "shutil",
        "socket",
        "sqlite3",
        "string",
        "subprocess",
        "sys",
        "tempfile",
        "textwrap",
        "threading",
        "time",
        "tomllib",
        "traceback",
        "typing",
        "unittest",
        "urllib",
        "uuid",
        "warnings",
        "xml",
        "zipfile",
    }
)


@dataclass
class Pep723Finding:
    """A security or best-practice issue in a PEP 723 metadata block."""

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
class Pep723BlockInfo:
    """Parsed metadata about a PEP 723 inline script block."""

    path: str
    start_line: int
    end_line: int
    requires_python: str = ""
    dependencies: list[str] = field(default_factory=list)
    valid_toml: bool = True


@dataclass
class Pep723Stats:
    """Aggregate PEP 723 analysis statistics."""

    scripts: int = 0
    blocks: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_script_candidate(path: Path) -> bool:
    """Return True if the Python file looks like a standalone script."""
    if path.name.startswith("test_") or path.name.endswith("_test.py"):
        return False
    if any(part in SCRIPT_DIR_NAMES for part in path.parts):
        return True
    if path.name in ("__main__.py", "manage.py", "wsgi.py", "asgi.py"):
        return True
    return False


def _extract_pep723_blocks(text: str) -> list[tuple[int, int, list[str]]]:
    """Extract PEP 723 blocks as (start_line, end_line, comment_lines)."""
    blocks: list[tuple[int, int, list[str]]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if PEP723_START_PATTERN.match(lines[i].strip()):
            start = i + 1
            comment_lines: list[str] = []
            i += 1
            while i < len(lines):
                stripped = lines[i].strip()
                if PEP723_END_PATTERN.match(stripped):
                    blocks.append((start, i + 1, comment_lines))
                    break
                if stripped.startswith("#"):
                    content = stripped[1:]
                    if content.startswith(" "):
                        content = content[1:]
                    comment_lines.append(content)
                i += 1
        i += 1
    return blocks


def _parse_block_toml(comment_lines: list[str]) -> tuple[dict, bool]:
    """Parse TOML from PEP 723 comment lines."""
    toml_text = "\n".join(comment_lines)
    if not toml_text.strip():
        return {}, True
    try:
        return tomllib.loads(toml_text), True
    except tomllib.TOMLDecodeError:
        return {}, False


def _third_party_imports(text: str) -> set[str]:
    """Return top-level third-party module names imported in the file."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return {m for m in modules if m not in STDLIB_MODULES}


def _has_main_guard(text: str) -> bool:
    """Return True if the file contains a __main__ guard."""
    return '__name__' in text and '__main__' in text


class Pep723Analyzer:
    """Audit PEP 723 inline script metadata blocks in Python files.

    Scans standalone scripts for PEP 723 metadata blocks and checks for
    missing metadata, invalid TOML, unpinned dependencies, insecure source
    URLs, hardcoded secrets, and loose version constraints.
  """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[Pep723Finding] | None = None
        self._stats: Pep723Stats | None = None
        self._blocks: list[Pep723BlockInfo] | None = None

    def scripts(self) -> list[Path]:
        """Return Python script paths that may contain PEP 723 metadata."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file():
                continue
            if any(part.startswith(".") or part in {"__pycache__", "venv", ".venv", "node_modules"}
                   for part in path.parts):
                continue
            if _is_script_candidate(path) or path.suffix == ".py":
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[Pep723Finding], list[Pep723BlockInfo]]:
        findings: list[Pep723Finding] = []
        blocks_info: list[Pep723BlockInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, blocks_info

        is_candidate = _is_script_candidate(path) or _has_main_guard(text)
        pep723_blocks = _extract_pep723_blocks(text)
        third_party = _third_party_imports(text)

        if is_candidate and third_party and not pep723_blocks:
            findings.append(
                Pep723Finding(
                    kind="missing_metadata",
                    severity="medium",
                    message=(
                        "script imports third-party packages without PEP 723 metadata — "
                        "add a /// script block with dependencies for reproducible runs"
                    ),
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        for start_line, end_line, comment_lines in pep723_blocks:
            data, valid = _parse_block_toml(comment_lines)
            requires_python = str(data.get("requires-python", ""))
            deps = data.get("dependencies", [])
            if not isinstance(deps, list):
                deps = []
            deps = [str(d) for d in deps]

            block_info = Pep723BlockInfo(
                path=rel,
                start_line=start_line,
                end_line=end_line,
                requires_python=requires_python,
                dependencies=deps,
                valid_toml=valid,
            )
            blocks_info.append(block_info)

            if not valid:
                findings.append(
                    Pep723Finding(
                        kind="invalid_toml",
                        severity="high",
                        message="invalid TOML in PEP 723 metadata block",
                        path=rel,
                        lineno=start_line,
                        line=comment_lines[0] if comment_lines else "",
                    )
                )
                continue

            if not deps:
                findings.append(
                    Pep723Finding(
                        kind="empty_dependencies",
                        severity="low",
                        message="PEP 723 block has no dependencies — declare required packages",
                        path=rel,
                        lineno=start_line,
                        line="",
                    )
                )

            if not requires_python:
                findings.append(
                    Pep723Finding(
                        kind="missing_requires_python",
                        severity="low",
                        message="PEP 723 block missing requires-python — pin minimum Python version",
                        path=rel,
                        lineno=start_line,
                        line="",
                    )
                )

            for dep_lineno_offset, dep in enumerate(deps):
                dep_lineno = start_line + dep_lineno_offset
                dep_line = dep

                if HARDCODED_SECRET_PATTERN.search(dep):
                    findings.append(
                        Pep723Finding(
                            kind="hardcoded_secret",
                            severity="high",
                            message="hardcoded secret in PEP 723 dependency — use environment variables",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

                if PYPI_TOKEN_PATTERN.search(dep):
                    findings.append(
                        Pep723Finding(
                            kind="pypi_token",
                            severity="high",
                            message="PyPI token in PEP 723 dependency — use index URL env vars",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

                if INSECURE_HTTP_PATTERN.search(dep):
                    findings.append(
                        Pep723Finding(
                            kind="insecure_http",
                            severity="medium",
                            message="insecure HTTP URL in dependency — use HTTPS sources",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

                if SCM_CREDENTIALS_PATTERN.search(dep):
                    findings.append(
                        Pep723Finding(
                            kind="scm_credentials",
                            severity="high",
                            message="credentials embedded in VCS URL — use token env vars or SSH keys",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

                if UNPINNED_DEP_PATTERN.match(dep.strip()):
                    findings.append(
                        Pep723Finding(
                            kind="unpinned_dependency",
                            severity="low",
                            message="unpinned dependency — pin with == for reproducible script runs",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

                if LOOSE_VERSION_PATTERN.search(dep):
                    findings.append(
                        Pep723Finding(
                            kind="loose_version",
                            severity="medium",
                            message="loose version constraint — pin exact versions in script metadata",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

                if GIT_DEP_UNPINNED_PATTERN.search(dep):
                    findings.append(
                        Pep723Finding(
                            kind="unpinned_git_dep",
                            severity="medium",
                            message="git dependency pinned to moving branch — pin to tag or commit SHA",
                            path=rel,
                            lineno=dep_lineno,
                            line=dep_line,
                        )
                    )

        return findings, blocks_info

    def analyze(self) -> list[Pep723Finding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[Pep723Finding] = []
        blocks: list[Pep723BlockInfo] = []
        paths = self.scripts()
        script_count = 0

        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if _is_script_candidate(path) or _has_main_guard(text) or _extract_pep723_blocks(text):
                script_count += 1
            file_findings, file_blocks = self._analyze_file(path)
            findings.extend(file_findings)
            blocks.extend(file_blocks)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._blocks = blocks
        self._stats = Pep723Stats(
            scripts=script_count,
            blocks=len(blocks),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> Pep723Stats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def blocks(self) -> list[Pep723BlockInfo]:
        """Return parsed PEP 723 block metadata."""
        if self._blocks is None:
            self.analyze()
        return self._blocks  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no scripts)."""
        self.analyze()
        stats = self.stats
        if stats.scripts == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_template(self) -> str:
        """Scaffold a PEP 723 metadata block template."""
        return """\
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests==2.31.0",
# ]
# ///
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.scripts == 0:
            return "PEP 723 scripts: none found"
        return (
            f"PEP 723 scripts: {stats.scripts} script(s), {stats.blocks} block(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "PEP 723 inline script metadata analysis:",
            f"  scripts: {stats.scripts}",
            f"  blocks: {stats.blocks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for block in self.blocks[:15]:
            deps = ", ".join(block.dependencies[:8]) if block.dependencies else "none"
            lines.append(
                f"  - {block.path}:{block.start_line} "
                f"(requires-python={block.requires_python or 'unset'}, deps={deps})"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
