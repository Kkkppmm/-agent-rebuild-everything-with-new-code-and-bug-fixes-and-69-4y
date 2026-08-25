"""DenoAnalyzer — audit deno.json, deno.jsonc, and deno.lock for security."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DENO_CONFIG_NAMES = ("deno.json", "deno.jsonc")
DENO_LOCK_NAMES = ("deno.lock",)
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
    r"(?:\.ssh/|\.aws/|/etc/passwd|/etc/shadow|\.kube/config|\.env\b)",
    re.IGNORECASE,
)
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|child_process|nc\s+-|/dev/tcp)",
    re.IGNORECASE,
)
ALLOW_ALL_PATTERN = re.compile(
    r"(?:--allow-all|\"allowAll\"\s*:\s*true|permissions\s*=\s*\[\s*\"all\"\s*\])",
    re.IGNORECASE,
)
UNPINNED_IMPORT_PATTERN = re.compile(
    r"(?:npm:|jsr:)[^\"'\s]+@(?:latest|\*)|"
    r"https?://[^\"'\s]+(?:main|master|HEAD|develop)(?:/|\"|'|$)",
    re.IGNORECASE,
)
UNSAFE_RUN_PATTERN = re.compile(
    r"(?:--allow-run|--allow-all|allow-run|allowRun)",
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
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class DenoInfo:
    """Parsed metadata from a Deno configuration file."""

    path: str
    lines: int = 0
    file_kind: str = "unknown"
    imports: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)


@dataclass
class DenoStats:
    """Aggregate statistics from Deno analysis."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    name = path.name
    if name in DENO_CONFIG_NAMES:
        return "config"
    if name in DENO_LOCK_NAMES:
        return "lockfile"
    return "unknown"


def _is_deno_file(path: Path) -> bool:
    return path.name in (*DENO_CONFIG_NAMES, *DENO_LOCK_NAMES)


def _strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments for JSONC parsing."""
    result: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if escape:
            result.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and in_string:
            result.append(ch)
            escape = True
            i += 1
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            i += 1
            continue
        if not in_string and ch == "/" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "/":
                while i < len(text) and text[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        result.append(ch)
        i += 1
    return "".join(result)


class DenoAnalyzer:
    """Audit Deno configuration for security issues.

    Scans deno.json, deno.jsonc, and deno.lock for hardcoded secrets,
    overly permissive --allow-all flags, insecure HTTP imports, unpinned
    npm:/jsr: specifiers, credentials in git URLs, and dangerous task scripts.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root).resolve()
        self._findings: list[DenoFinding] | None = None
        self._stats: DenoStats | None = None
        self._infos: list[DenoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Deno configuration paths found in the project."""
        paths: list[Path] = []
        for path in self.root.rglob("*"):
            if path.is_file() and _is_deno_file(path):
                paths.append(path)
        return sorted(set(paths))

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[DenoFinding],
        info: DenoInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            return

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
                    message="AWS access key in Deno config — use credential helpers or secret stores",
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
                    message="insecure HTTP import URL — use HTTPS for remote modules",
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
                    message="credentials embedded in import URL — use import maps with env-based auth",
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
                    message="curl|sh pattern in config — avoid piping remote scripts to shell",
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
                    message="sensitive host path reference — avoid bundling credentials in tasks",
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
                    message="dangerous script in Deno task — review task commands",
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
                    message="--allow-all or allowAll enabled — grant least-privilege permissions instead",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_IMPORT_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="unpinned_import",
                    severity="medium",
                    message="unpinned import specifier — pin npm:/jsr: versions or commit SHAs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSAFE_RUN_PATTERN.search(line) and "deno run" in line.lower():
            findings.append(
                DenoFinding(
                    kind="allow_run",
                    severity="medium",
                    message="--allow-run in task — subprocess execution should be narrowly scoped",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        import_match = re.match(r'^\s*"([^"]+)"\s*:', stripped)
        if import_match and info.file_kind == "config":
            key = import_match.group(1)
            if key not in info.imports and key not in ("tasks", "imports", "compilerOptions"):
                info.imports.append(key)

    def _analyze_file(self, path: Path) -> tuple[list[DenoFinding], DenoInfo]:
        findings: list[DenoFinding] = []
        rel = str(path.relative_to(self.root))
        file_kind = _file_kind(path)
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, DenoInfo(path=rel, file_kind=file_kind)

        info = DenoInfo(path=rel, lines=len(raw_lines), file_kind=file_kind)

        in_tasks = False
        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.rstrip()
            stripped = line.strip()
            if re.match(r'^\s*"tasks"\s*:', stripped):
                in_tasks = True
            elif in_tasks and re.match(r'^\s*"[a-zA-Z]', stripped) and '"tasks"' not in stripped:
                task_match = re.match(r'^\s*"([a-zA-Z0-9_-]+)"\s*:', stripped)
                if task_match and task_match.group(1) not in info.tasks:
                    info.tasks.append(task_match.group(1))
            self._scan_line(line, lineno, rel, findings, info)

        if file_kind == "config":
            try:
                cleaned = _strip_jsonc_comments(raw_text)
                data = json.loads(cleaned)
                if isinstance(data, dict):
                    imports = data.get("imports") or {}
                    if isinstance(imports, dict):
                        for key, value in imports.items():
                            if key not in info.imports:
                                info.imports.append(key)
                            if isinstance(value, str):
                                if INSECURE_HTTP_PATTERN.search(value):
                                    findings.append(
                                        DenoFinding(
                                            kind="insecure_http",
                                            severity="medium",
                                            message=f"insecure HTTP import for '{key}' — use HTTPS",
                                            path=rel,
                                            lineno=1,
                                            line=f'"{key}": "{value}"',
                                        )
                                    )
                                if UNPINNED_IMPORT_PATTERN.search(value):
                                    findings.append(
                                        DenoFinding(
                                            kind="unpinned_import",
                                            severity="medium",
                                            message=f"unpinned import for '{key}' — pin version or commit",
                                            path=rel,
                                            lineno=1,
                                            line=f'"{key}": "{value}"',
                                        )
                                    )
                    compiler = data.get("compilerOptions") or {}
                    if isinstance(compiler, dict):
                        lib = compiler.get("lib") or []
                        if "deno.unstable" in str(lib):
                            findings.append(
                                DenoFinding(
                                    kind="unstable_api",
                                    severity="low",
                                    message="deno.unstable lib enabled — review unstable API usage before production",
                                    path=rel,
                                    lineno=1,
                                    line="compilerOptions.lib includes deno.unstable",
                                )
                            )
            except json.JSONDecodeError:
                findings.append(
                    DenoFinding(
                        kind="invalid_json",
                        severity="medium",
                        message="deno config is not valid JSON/JSONC — fix syntax before deployment",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[DenoFinding]:
        """Run analysis and return all findings."""
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
            configs=len(paths),
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
        """Scaffold a hardened deno.json snippet."""
        return """\
{
  "tasks": {
    "dev": "deno run --allow-net --allow-read=./src main.ts",
    "test": "deno test --allow-read=./src,./tests"
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
            f"Deno configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Deno analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            imports = ", ".join(info.imports[:6]) if info.imports else "none"
            tasks = ", ".join(info.tasks[:6]) if info.tasks else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): imports={imports}, tasks={tasks}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
