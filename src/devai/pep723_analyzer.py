"""Pep723Analyzer — audit PEP 723 inline script metadata blocks for security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

PEP723_START = re.compile(r"^#\s*///\s*script\s*$", re.IGNORECASE)
PEP723_END = re.compile(r"^#\s*///\s*$")
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
UNPINNED_GIT_REF_PATTERN = re.compile(
    r"(?:@|#|ref=|rev=)(?:main|master|HEAD|develop|trunk)\b|"
    r"github\.com/[^\"'\s]+/(?:main|master|HEAD|develop|trunk)",
    re.IGNORECASE,
)
TRUSTED_HOST_PATTERN = re.compile(
    r"--trusted-host\b|--index-url\s+http://",
    re.IGNORECASE,
)
WILDCARD_VERSION_PATTERN = re.compile(
    r"[\"'][^\"']*==\s*\*[\"']|[\"'][^\"']*\*[\"']",
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
PIP_INSTALL_URL_PATTERN = re.compile(
    r"pip\s+install\s+(?:--[^\s]+\s+)*https?://",
    re.IGNORECASE,
)


@dataclass
class Pep723Finding:
    """A security or best-practice issue in a PEP 723 script block."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class Pep723Info:
    """Parsed metadata from a PEP 723 script block."""

    path: str
    start_line: int
    end_line: int
    dependencies: list[str] = field(default_factory=list)
    requires_python: str = ""


@dataclass
class Pep723Stats:
    """Aggregate statistics from PEP 723 analysis."""

    scripts: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _extract_block_lines(lines: list[str], start: int) -> tuple[list[str], int]:
    """Return comment lines inside a PEP 723 block and the closing line index."""
    block: list[str] = []
    for idx in range(start + 1, len(lines)):
        line = lines[idx]
        if PEP723_END.match(line.strip()):
            return block, idx
        if line.strip().startswith("#"):
            block.append(line.lstrip("#").strip())
        else:
            break
    return block, start


def _parse_dependencies(block_lines: list[str]) -> list[str]:
    """Extract dependency strings from TOML-like block content."""
    deps: list[str] = []
    in_deps = False
    for line in block_lines:
        stripped = line.strip()
        if stripped.startswith("dependencies"):
            in_deps = True
            inline = re.search(r"\[(.*)\]", stripped)
            if inline:
                inner = inline.group(1)
                for part in re.findall(r"[\"']([^\"']+)[\"']", inner):
                    deps.append(part)
            continue
        if in_deps:
            if stripped == "]":
                in_deps = False
                continue
            match = re.search(r"[\"']([^\"']+)[\"']", stripped)
            if match:
                deps.append(match.group(1))
    return deps


def _parse_requires_python(block_lines: list[str]) -> str:
    for line in block_lines:
        match = re.match(r"requires-python\s*=\s*[\"']([^\"']+)[\"']", line.strip())
        if match:
            return match.group(1)
    return ""


class Pep723Analyzer:
    """Audit PEP 723 inline script metadata for security issues.

    Scans Python files for ``# /// script`` blocks and checks dependencies for
    hardcoded secrets, insecure HTTP index URLs, credentials in git URLs,
    unpinned git refs, pip trusted-host bypasses, wildcard versions, and
    curl-pipe-to-shell patterns in dependency specs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[Pep723Finding] | None = None
        self._stats: Pep723Stats | None = None
        self._infos: list[Pep723Info] | None = None

    def scripts(self) -> list[Path]:
        """Return Python files containing PEP 723 script blocks."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(PEP723_START.match(line.strip()) for line in text.splitlines()):
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[Pep723Finding],
    ) -> None:
        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in PEP 723 block — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in PEP 723 block — never embed credentials in scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in PEP 723 dependencies — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in git/HTTP URL — use SSH or token env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_GIT_REF_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="unpinned_git_ref",
                    severity="medium",
                    message="unpinned git ref (main/master/HEAD) — pin to tag or commit SHA",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if TRUSTED_HOST_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="trusted_host_bypass",
                    severity="medium",
                    message="pip trusted-host or HTTP index-url bypass — avoid TLS verification skips",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WILDCARD_VERSION_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="wildcard_version",
                    severity="low",
                    message="wildcard dependency version — pin explicit versions for reproducibility",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl piped to shell in PEP 723 block — vendor scripts with checksums",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PIP_INSTALL_URL_PATTERN.search(line):
            findings.append(
                Pep723Finding(
                    kind="pip_url_install",
                    severity="medium",
                    message="pip install from URL without lockfile — prefer pinned PyPI packages",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[Pep723Finding], list[Pep723Info]]:
        findings: list[Pep723Finding] = []
        infos: list[Pep723Info] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, infos

        raw_lines = text.splitlines()
        idx = 0
        while idx < len(raw_lines):
            if PEP723_START.match(raw_lines[idx].strip()):
                block_lines, end_idx = _extract_block_lines(raw_lines, idx)
                info = Pep723Info(
                    path=rel,
                    start_line=idx + 1,
                    end_line=end_idx + 1,
                    dependencies=_parse_dependencies(block_lines),
                    requires_python=_parse_requires_python(block_lines),
                )
                infos.append(info)
                for offset, block_line in enumerate(block_lines, start=idx + 2):
                    self._scan_line(block_line, offset, rel, findings)
                idx = end_idx + 1
            else:
                idx += 1

        return findings, infos

    def analyze(self) -> list[Pep723Finding]:
        """Run analysis and return all findings."""
        if self._findings is not None:
            return self._findings

        findings: list[Pep723Finding] = []
        infos: list[Pep723Info] = []
        paths = self.scripts()
        seen_files: set[str] = set()

        for path in paths:
            file_findings, file_infos = self._analyze_file(path)
            findings.extend(file_findings)
            infos.extend(file_infos)
            seen_files.add(str(path.relative_to(self.root)))

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = Pep723Stats(
            scripts=len(infos),
            files=len(seen_files),
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
    def infos(self) -> list[Pep723Info]:
        """Return parsed script block metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

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

    def generate_hardened_block(self) -> str:
        """Scaffold a hardened PEP 723 script block."""
        return '''\
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests==2.32.3",
# ]
# ///
'''

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.scripts == 0:
            return "PEP 723 scripts: none found"
        return (
            f"PEP 723 scripts: {stats.scripts} block(s) in {stats.files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "PEP 723 script metadata analysis:",
            f"  scripts: {stats.scripts}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            deps = ", ".join(info.dependencies[:6]) if info.dependencies else "none"
            py = info.requires_python or "unspecified"
            lines.append(
                f"  - {info.path}:{info.start_line}-{info.end_line} "
                f"(requires-python={py}, deps={len(info.dependencies)})"
            )
            lines.append(f"    dependencies: {deps}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
