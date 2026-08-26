"""DenoAnalyzer — audit deno.json, deno.jsonc, and import maps for permission and import risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DENO_CONFIG_NAMES = ("deno.json", "deno.jsonc")
IMPORT_MAP_NAMES = ("import_map.json", "import-map.json")
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
    r"(?:git\+https?://|https?://)[^:@\s]+:[^@\s]+@",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config)",
    re.IGNORECASE,
)
ALLOW_ALL_PATTERN = re.compile(
    r"(?:--allow-all\b|\"allow-all\"|permissions\s*[=:]\s*\[?\s*\"all\"|"
    r"\"--allow-all\")",
    re.IGNORECASE,
)
BROAD_PERMISSION_PATTERN = re.compile(
    r"(?:--allow-read(?:\s|$)|"
    r"--allow-write(?:\s|$)|"
    r"--allow-net(?:\s|$)|"
    r"--allow-run(?:\s|$)|"
    r"--allow-env(?:\s|$)|"
    r"\"allow-read\"|\"allow-write\"|\"allow-net\"|\"allow-run\"|\"allow-env\")",
    re.IGNORECASE,
)
UNVERSIONED_IMPORT_PATTERN = re.compile(
    r"(?:https?://[^\s\"']+)(?![^\n]*@\d)",
    re.IGNORECASE,
)
DYNAMIC_IMPORT_PATTERN = re.compile(
    r"(?:npm:|jsr:|node:)[^\s\"']+#(?:main|master|HEAD|develop)\b|"
    r"[\"']git\+[^\"']+#(?:main|master|HEAD|develop)[\"']?",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
UNSTABLE_PATTERN = re.compile(
    r"(?:--unstable\b|\"unstable\"|unstable\s*[=:]\s*true)",
    re.IGNORECASE,
)


@dataclass
class DenoFinding:
    """A security or best-practice issue in a Deno configuration file."""

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
class DenoInfo:
    """Parsed metadata about a Deno configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    imports: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)


@dataclass
class DenoStats:
    """Aggregate Deno analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_deno_file(path: Path) -> bool:
    """Return True if the path looks like a Deno configuration file."""
    return path.name in DENO_CONFIG_NAMES or path.name in IMPORT_MAP_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name.startswith("deno."):
        return "deno_config"
    if "import" in name:
        return "import_map"
    return "unknown"


class DenoAnalyzer:
    """Audit Deno configuration for permission and import security issues.

    Scans deno.json/jsonc and import maps for overly broad permissions,
    hardcoded secrets, HTTP imports, unversioned remote imports, unpinned
    npm/jsr dependencies, and dangerous task scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DenoFinding] | None = None
        self._stats: DenoStats | None = None
        self._infos: list[DenoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Deno configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_deno_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[DenoFinding], DenoInfo]:
        findings: list[DenoFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DenoInfo(path=rel)

        raw_lines = text.splitlines()
        info = DenoInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            import_match = re.search(r"\"([^\"]+)\"\s*:\s*\"([^\"]+)\"", stripped)
            if import_match:
                info.imports.append(import_match.group(1))
            task_match = re.search(r"\"([a-zA-Z0-9_-]+)\"\s*:\s*\"deno\b", stripped)
            if task_match:
                info.tasks.append(task_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Deno config — use env vars or Deno secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="aws_key",
                        severity="high",
                        message="AWS access key in Deno config — rotate and use env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if SCM_CREDENTIALS_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="scm_credentials",
                        severity="high",
                        message="credentials embedded in URL — use SSH keys or token env vars",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if ALLOW_ALL_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="allow_all",
                        severity="high",
                        message="--allow-all or equivalent — use least-privilege permission flags",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if BROAD_PERMISSION_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="broad_permission",
                        severity="medium",
                        message="broad Deno permission — scope read/write/net/run/env with --deny-* where possible",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="HTTP import or URL — prefer HTTPS and versioned imports",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if UNVERSIONED_IMPORT_PATTERN.search(line) and (
                "http://" in line or "https://" in line
            ):
                findings.append(
                    DenoFinding(
                        kind="unversioned_import",
                        severity="medium",
                        message="remote import without version pin — use versioned npm/jsr or URL imports",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if DYNAMIC_IMPORT_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="unpinned_dependency",
                        severity="medium",
                        message="unpinned npm/jsr/git dependency — pin to explicit versions or commits",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl|wget piped to shell — verify task scripts and use pinned installers",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if DANGEROUS_SCRIPT_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="dangerous_script",
                        severity="high",
                        message="dangerous shell pattern in Deno task — review run commands",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if SENSITIVE_PATH_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="sensitive_path",
                        severity="medium",
                        message="sensitive path referenced — restrict read permissions for credential paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            if UNSTABLE_PATTERN.search(line):
                findings.append(
                    DenoFinding(
                        kind="unstable_feature",
                        severity="low",
                        message="unstable Deno feature enabled — document and pin Deno version in CI",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[DenoFinding]:
        """Run analysis and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DenoFinding] = []
        infos: list[DenoInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = DenoStats(
            configs=len({p.parent for p in paths} if paths else []),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DenoStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DenoInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened deno.json snippet with least-privilege defaults."""
        return """\
{
  "tasks": {
    "start": "deno run --allow-net=localhost --allow-read=./src main.ts",
    "test": "deno test --allow-read=./tests,./src"
  },
  "imports": {
    "@std/": "jsr:@std/"
  },
  "compilerOptions": {
    "strict": true
  }
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Deno configs: none found"
        return (
            f"Deno configs: {stats.configs} project(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Deno analysis:",
            f"  projects: {stats.configs}",
            f"  files: {stats.files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            imports = ", ".join(info.imports[:6]) if info.imports else "none"
            tasks = ", ".join(info.tasks[:6]) if info.tasks else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.imports)} import(s), {len(info.tasks)} task(s)"
            )
            lines.append(f"      imports: {imports}")
            if info.tasks:
                lines.append(f"      tasks: {tasks}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
