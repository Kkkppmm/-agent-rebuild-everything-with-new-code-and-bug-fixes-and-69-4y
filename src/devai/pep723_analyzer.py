"""Pep723Analyzer — audit PEP 723 inline script metadata blocks in Python files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

PEP723_BLOCK_START = re.compile(r"^#\s///\s(?P<type>[a-zA-Z0-9-]+)\s*$")
PEP723_BLOCK_END = re.compile(r"^#\s///\s*$")
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|pypi[_-]?token)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
PYPI_TOKEN_PATTERN = re.compile(r"[\"']?pypi-[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SCM_CREDENTIALS_PATTERN = re.compile(
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
UNPINNED_DEP_PATTERN = re.compile(
    r'^["\']?[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\[[^\]]+\])?["\']?\s*$',
)
LOOSE_VERSION_PATTERN = re.compile(
    r'["\']?[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\[[^\]]+\])?["\']?\s*(?:>=|<=|>|<|~=|!=)\s*["\']?\d',
)
GIT_DEP_UNPINNED_PATTERN = re.compile(
    r"(?:@(?:main|master|HEAD|develop)\b|branch\s*=\s*[\"'](?:main|master|HEAD|develop)[\"'])",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)


@dataclass
class Pep723Finding:
    """A security or best-practice issue in a PEP 723 script metadata block."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class Pep723ScriptInfo:
    """Parsed metadata about a PEP 723 script block."""

    path: str
    lineno: int
    dependencies: list[str] = field(default_factory=list)
    requires_python: str | None = None


@dataclass
class Pep723Stats:
    """Aggregate PEP 723 analysis statistics."""

    scripts: int = 0
    blocks: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _should_skip_dir(name: str) -> bool:
    return name in DEFAULT_IGNORE_DIRS or name.startswith(".")


def _extract_block_content(lines: list[str], start: int) -> tuple[str, int] | None:
    """Extract PEP 723 block content starting at start index. Returns (content, end_lineno)."""
    if start >= len(lines):
        return None
    match = PEP723_BLOCK_START.match(lines[start])
    if not match:
        return None

    content_lines: list[str] = []
    lineno = start + 1
    while lineno < len(lines):
        raw = lines[lineno]
        if PEP723_BLOCK_END.match(raw):
            return "\n".join(content_lines), lineno
        if raw.startswith("#"):
            if len(raw) >= 2 and raw[1] == " ":
                content_lines.append(raw[2:])
            else:
                content_lines.append(raw[1:])
            lineno += 1
            continue
        break
    return None


class Pep723Analyzer:
    """Audit PEP 723 inline script metadata for dependency hygiene and security risks.

    Scans Python files for `# /// script` blocks and checks for unpinned dependencies,
    hardcoded secrets, insecure HTTP URLs, credentials in git URLs, and missing
    requires-python constraints.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[Pep723Finding] | None = None
        self._stats: Pep723Stats | None = None
        self._infos: list[Pep723ScriptInfo] | None = None

    def script_files(self) -> list[Path]:
        """Return Python files that may contain PEP 723 metadata."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*.py")):
            if any(part in DEFAULT_IGNORE_DIRS for part in path.parts):
                continue
            if path.name.startswith("."):
                continue
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            except OSError:
                continue
            if "# /// script" in head or "# ///script" in head:
                found.append(path)
        return found

    def _parse_dependencies(self, content: str) -> tuple[list[str], str | None]:
        deps: list[str] = []
        requires_python: str | None = None
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("requires-python"):
                match = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', stripped)
                if match:
                    requires_python = match.group(1)
            if stripped == "dependencies = [":
                in_deps = True
                continue
            if in_deps:
                if stripped == "]":
                    in_deps = False
                    continue
                dep = stripped.rstrip(",").strip().strip("\"'")
                if dep:
                    deps.append(dep)
        return deps, requires_python

    def _scan_block(
        self,
        path: Path,
        rel: str,
        block_type: str,
        content: str,
        start_lineno: int,
        findings: list[Pep723Finding],
        infos: list[Pep723ScriptInfo],
    ) -> None:
        if block_type != "script":
            return

        deps, requires_python = self._parse_dependencies(content)
        info = Pep723ScriptInfo(
            path=rel,
            lineno=start_lineno + 1,
            dependencies=deps,
            requires_python=requires_python,
        )
        infos.append(info)

        if not requires_python:
            findings.append(
                Pep723Finding(
                    kind="missing_requires_python",
                    severity="low",
                    message="PEP 723 script missing requires-python — pin compatible Python versions",
                    path=rel,
                    lineno=start_lineno + 1,
                    line="",
                )
            )

        if not deps:
            findings.append(
                Pep723Finding(
                    kind="missing_dependencies",
                    severity="low",
                    message="PEP 723 script block has no dependencies listed",
                    path=rel,
                    lineno=start_lineno + 1,
                    line="",
                )
            )

        for dep_lineno_offset, dep in enumerate(deps):
            lineno = start_lineno + 2 + dep_lineno_offset
            if HARDCODED_SECRET_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in PEP 723 dependency — use env vars",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if PYPI_TOKEN_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="pypi_token",
                        severity="high",
                        message="PyPI token in PEP 723 dependency — use keyring or env vars",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if AWS_ACCESS_KEY_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in PEP 723 dependency",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if INSECURE_HTTP_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL in PEP 723 dependency — use HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if SCM_CREDENTIALS_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in PEP 723 dependency URL",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if UNPINNED_DEP_PATTERN.match(dep) and "@" not in dep and "://" not in dep:
                findings.append(
                    Pep723Finding(
                        kind="unpinned_dependency",
                        severity="medium",
                        message=f"unpinned dependency '{dep}' — pin with == for reproducibility",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if LOOSE_VERSION_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="loose_version",
                        severity="medium",
                        message=f"loose version constraint in '{dep}' — prefer exact pins",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )
            if GIT_DEP_UNPINNED_PATTERN.search(dep):
                findings.append(
                    Pep723Finding(
                        kind="unpinned_git_dep",
                        severity="medium",
                        message="git dependency pinned to moving branch — pin to tag or commit SHA",
                        path=rel,
                        lineno=lineno,
                        line=dep,
                    )
                )

        for lineno_offset, line in enumerate(content.splitlines()):
            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    Pep723Finding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in PEP 723 metadata",
                        path=rel,
                        lineno=start_lineno + 1 + lineno_offset,
                        line=line,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[Pep723Finding], list[Pep723ScriptInfo]]:
        findings: list[Pep723Finding] = []
        infos: list[Pep723ScriptInfo] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, infos

        script_block_count = 0
        idx = 0
        while idx < len(raw_lines):
            match = PEP723_BLOCK_START.match(raw_lines[idx])
            if not match:
                idx += 1
                continue
            block_type = match.group("type")
            extracted = _extract_block_content(raw_lines, idx)
            if extracted is None:
                findings.append(
                    Pep723Finding(
                        kind="unclosed_block",
                        severity="medium",
                        message=f"unclosed PEP 723 '{block_type}' metadata block",
                        path=rel,
                        lineno=idx + 1,
                        line=raw_lines[idx],
                    )
                )
                idx += 1
                continue
            content, end_idx = extracted
            if block_type == "script":
                script_block_count += 1
                if script_block_count > 1:
                    findings.append(
                        Pep723Finding(
                            kind="duplicate_script_block",
                            severity="high",
                            message="multiple PEP 723 script blocks in one file — only one allowed",
                            path=rel,
                            lineno=idx + 1,
                            line=raw_lines[idx],
                        )
                    )
            self._scan_block(path, rel, block_type, content, idx, findings, infos)
            idx = end_idx + 1

        return findings, infos

    def analyze(self) -> list[Pep723Finding]:
        """Scan Python files for PEP 723 metadata and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[Pep723Finding] = []
        infos: list[Pep723ScriptInfo] = []
        paths = self.script_files()
        block_count = 0

        for path in paths:
            file_findings, file_infos = self._analyze_file(path)
            findings.extend(file_findings)
            infos.extend(file_infos)
            block_count += len(file_infos)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = Pep723Stats(
            scripts=len(paths),
            blocks=block_count,
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> Pep723Stats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[Pep723ScriptInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened PEP 723 script metadata block."""
        return '''\
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "httpx==0.27.0",
#   "rich==13.7.0",
# ]
# ///
'''

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.scripts == 0:
            return "PEP 723 scripts: none found"
        return (
            f"PEP 723 scripts: {stats.scripts} file(s), {stats.blocks} block(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "PEP 723 analysis:",
            f"  scripts: {stats.scripts}",
            f"  blocks: {stats.blocks}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos[:15]:
            deps = ", ".join(info.dependencies[:6]) if info.dependencies else "none"
            lines.append(
                f"  - {info.path}:{info.lineno}: "
                f"requires-python={info.requires_python or 'unset'}, deps={deps}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
