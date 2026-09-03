"""DenoAnalyzer — audit deno.json, deno.jsonc, import maps, and deno.lock for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DENO_CONFIG_NAMES = ("deno.json", "deno.jsonc")
DENO_LOCK_NAMES = ("deno.lock",)
IMPORT_MAP_NAMES = ("import_map.json",)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"[\"']?[^\"'\s${}][^\"'<]*[\"']?",
    re.IGNORECASE,
)
NPM_TOKEN_PATTERN = re.compile(r"[\"']?npm_[A-Za-z0-9_-]{20,}[\"']?", re.IGNORECASE)
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
DANGEROUS_SCRIPT_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|nc\s+-|/dev/tcp|Deno\.run\s*\(\s*\{[^}]*cmd\s*:\s*\[)",
    re.IGNORECASE,
)
ALLOW_ALL_PATTERN = re.compile(
    r"[\"']?(?:allow-all|allowAll|all)[\"']?\s*:\s*true\b",
    re.IGNORECASE,
)
WILDCARD_PERMISSION_PATTERN = re.compile(
    r"[\"'](?:read|write|run|net|env|sys|ffi|import)[\"']\s*:\s*\[\s*[\"']\*[\"']\s*\]",
    re.IGNORECASE,
)
FFI_ENABLED_PATTERN = re.compile(
    r"[\"']ffi[\"']\s*:\s*(?:true|\[\s*[\"']\*[\"']\s*\])",
    re.IGNORECASE,
)
LOCK_DISABLED_PATTERN = re.compile(
    r"[\"']lock[\"']\s*:\s*false\b",
    re.IGNORECASE,
)
UNPINNED_JSR_PATTERN = re.compile(
    r"jsr:[^/\s\"']+/[^@\s\"']+(?:[\"']|\s|$)",
    re.IGNORECASE,
)
UNPINNED_DENO_LAND_PATTERN = re.compile(
    r"https?://deno\.land/(?:x|std)/[^@\s\"']+/(?:mod|[^@\s\"']+\.(?:ts|js|tsx|jsx))(?:[\"']|\s|$)",
    re.IGNORECASE,
)
DYNAMIC_NPM_PATTERN = re.compile(
    r"npm:[^@\s\"']*(?:@(?:\*|latest|LATEST)|:[\"']?(?:\*|latest|LATEST)[\"']?)",
    re.IGNORECASE,
)
UNSTABLE_RISKY_PATTERN = re.compile(
    r"[\"']unstable[\"']\s*:\s*\[[^\]]*(?:ffi|kv|cron|worker|http|net)",
    re.IGNORECASE,
)
INSECURE_TLS_PATTERN = re.compile(
    r"(?:rejectUnauthorized|verify\s*=\s*false|DENO_TLS_CA_STORE\s*=\s*system)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)


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
    """Parsed metadata about a Deno configuration file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    imports: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)


@dataclass
class DenoStats:
    """Aggregate Deno analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments from JSONC for parsing."""
    result: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if in_string:
            result.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                break
            i = end + 2
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            i = end
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def _file_kind(path: Path) -> str:
    name = path.name
    if name in DENO_CONFIG_NAMES:
        return "deno_config"
    if name in DENO_LOCK_NAMES:
        return "lock"
    if name in IMPORT_MAP_NAMES:
        return "import_map"
    return "unknown"


def _has_deno_lock(directory: Path) -> bool:
    return any((directory / name).exists() for name in DENO_LOCK_NAMES)


def _looks_like_deno_project(root: Path) -> bool:
    if any((root / name).exists() for name in (*DENO_CONFIG_NAMES, *DENO_LOCK_NAMES)):
        return True
    if any((root / name).exists() for name in IMPORT_MAP_NAMES):
        return True
    for pattern in ("deno.json", "deno.jsonc", "deno.lock"):
        if any(root.rglob(pattern)):
            return True
    return False


class DenoAnalyzer:
    """Audit Deno configuration for security and supply-chain risks.

    Scans deno.json, deno.jsonc, import_map.json, and deno.lock for hardcoded
    secrets, overly permissive runtime permissions, disabled lockfiles, insecure
    remote imports, unpinned JSR/npm specifiers, and dangerous task scripts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DenoFinding] | None = None
        self._stats: DenoStats | None = None
        self._infos: list[DenoInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Deno configuration paths found in the project."""
        if not _looks_like_deno_project(self.root):
            return []

        found: list[Path] = []
        for name in (*DENO_CONFIG_NAMES, *DENO_LOCK_NAMES, *IMPORT_MAP_NAMES):
            path = self.root / name
            if path.is_file():
                found.append(path)

        for pattern in ("deno.json", "deno.jsonc", "deno.lock", "import_map.json"):
            for path in sorted(self.root.rglob(pattern)):
                if path.is_file() and path not in found:
                    found.append(path)

        return found

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

        import_match = re.search(
            r"[\"']([^\"']+(?:@|/)[^\"']+)[\"']\s*:\s*[\"']([^\"']+)[\"']",
            stripped,
        )
        if import_match:
            info.imports.append(import_match.group(2))

        task_match = re.search(r"[\"']([^\"']+)[\"']\s*:\s*[\"']([^\"']+)[\"']", stripped)
        if task_match and "task" in info.file_kind:
            info.tasks.append(task_match.group(1))

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Deno config — use env vars or CI secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if NPM_TOKEN_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="npm_token",
                    severity="high",
                    message="npm token in Deno config — use NPM_TOKEN env var interpolation",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Deno config — rotate and use secret stores",
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
                    message="insecure HTTP import or registry URL — use HTTPS for Deno remote modules",
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
                    message="credentials embedded in import URL — use token env vars or SSH keys",
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
                    message="curl/wget piped to shell in Deno config — vendor scripts with checksum verification",
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
                    message="dangerous command in Deno config — review tasks and lifecycle hooks",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if ALLOW_ALL_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="allow_all_permissions",
                    severity="high",
                    message="allow-all permissions enabled — grant least-privilege read/net/env scopes",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if WILDCARD_PERMISSION_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="wildcard_permission",
                    severity="high",
                    message="wildcard permission scope — restrict read/write/net/run to required paths and hosts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if FFI_ENABLED_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="ffi_enabled",
                    severity="medium",
                    message="FFI permission enabled — disable unless native libraries are required",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if LOCK_DISABLED_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="lock_disabled",
                    severity="medium",
                    message="lockfile disabled — enable lock: true and commit deno.lock for reproducible builds",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_JSR_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="unpinned_jsr_import",
                    severity="medium",
                    message="JSR import without version — pin jsr:@scope/pkg@version for supply-chain safety",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNPINNED_DENO_LAND_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="unpinned_remote_import",
                    severity="medium",
                    message="deno.land import without version — pin remote URL to tag or version path",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DYNAMIC_NPM_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="dynamic_npm_spec",
                    severity="medium",
                    message="npm: specifier uses wildcard — pin npm:package@version and commit deno.lock",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if UNSTABLE_RISKY_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="risky_unstable_feature",
                    severity="low",
                    message="risky unstable feature enabled — review ffi/kv/net unstable flags before production",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_TLS_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="insecure_tls",
                    severity="high",
                    message="TLS verification bypass — keep certificate validation enabled for remote imports",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if EVAL_PATTERN.search(line):
            findings.append(
                DenoFinding(
                    kind="eval_usage",
                    severity="high",
                    message="eval in Deno config — avoid dynamic code execution in tasks and scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_config(
        self, path: Path, rel: str
    ) -> tuple[list[DenoFinding], DenoInfo]:
        findings: list[DenoFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DenoInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = DenoInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        try:
            data = json.loads(_strip_jsonc_comments(text))
        except json.JSONDecodeError:
            findings.append(
                DenoFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="Deno config is not valid JSON/JSONC — fix syntax before publishing",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return findings, info

        imports = data.get("imports", {})
        if isinstance(imports, dict):
            for alias, target in imports.items():
                target_str = str(target)
                info.imports.append(target_str)
                if target_str.startswith("npm:") and "@" not in target_str.split("npm:", 1)[-1]:
                    findings.append(
                        DenoFinding(
                            kind="unpinned_npm_import",
                            severity="medium",
                            message=f"import {alias} uses unpinned npm: specifier — pin npm:package@version",
                            path=rel,
                            lineno=1,
                            line=f"{alias}: {target_str}",
                        )
                    )

        tasks = data.get("tasks", {})
        if isinstance(tasks, dict):
            for name, command in tasks.items():
                info.tasks.append(str(name))
                command_str = str(command)
                if DANGEROUS_SCRIPT_PATTERN.search(command_str):
                    findings.append(
                        DenoFinding(
                            kind="dangerous_task",
                            severity="high",
                            message=f"dangerous task {name} — review Deno task scripts before CI execution",
                            path=rel,
                            lineno=1,
                            line=command_str,
                        )
                    )
                if CURL_PIPE_SHELL_PATTERN.search(command_str):
                    findings.append(
                        DenoFinding(
                            kind="curl_pipe_shell",
                            severity="high",
                            message=f"curl/wget piped to shell in task {name} — vendor scripts locally",
                            path=rel,
                            lineno=1,
                            line=command_str,
                        )
                    )

        permissions = data.get("permissions", data.get("permission", {}))
        if isinstance(permissions, dict):
            for key in permissions:
                info.permissions.append(str(key))
            if permissions.get("allow-all") is True or permissions.get("allowAll") is True:
                findings.append(
                    DenoFinding(
                        kind="allow_all_permissions",
                        severity="high",
                        message="permissions.allow-all is true — use least-privilege scopes",
                        path=rel,
                        lineno=1,
                        line="allow-all: true",
                    )
                )

        if path.name in DENO_CONFIG_NAMES and not _has_deno_lock(path.parent):
            lock_setting = data.get("lock")
            if lock_setting is not False:
                findings.append(
                    DenoFinding(
                        kind="missing_lockfile",
                        severity="low",
                        message="deno.lock missing — commit lockfile for reproducible remote imports",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def _analyze_text_file(self, path: Path, rel: str) -> tuple[list[DenoFinding], DenoInfo]:
        findings: list[DenoFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, DenoInfo(path=rel, file_kind=_file_kind(path))

        raw_lines = text.splitlines()
        info = DenoInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))

        for lineno, line in enumerate(raw_lines, start=1):
            self._scan_line(line, lineno, rel, findings, info)

        return findings, info

    def _analyze_file(self, path: Path) -> tuple[list[DenoFinding], DenoInfo]:
        rel = str(path.relative_to(self.root))
        if path.name in (*DENO_CONFIG_NAMES, *IMPORT_MAP_NAMES):
            return self._analyze_json_config(path, rel)
        return self._analyze_text_file(path, rel)

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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DenoInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold hardened deno.json defaults."""
        return """\
{
  // deno.json — hardened defaults for Deno projects
  "lock": true,
  "nodeModulesDir": false,
  "compilerOptions": {
    "strict": true
  },
  "permissions": {
    "read": ["./"],
    "write": ["./"],
    "net": ["registry.npmjs.org", "jsr.io", "deno.land"],
    "env": ["NODE_ENV", "DENO_ENV"]
  },
  "imports": {
    "@std/": "jsr:@std/"
  },
  "tasks": {
    "dev": "deno run --watch main.ts",
    "test": "deno test --allow-read=./ --allow-env=NODE_ENV"
  }
}
"""

    def summary(self) -> str:
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
        self.analyze()
        stats = self.stats
        lines = [
            "Deno analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            imports = ", ".join(info.imports[:8]) if info.imports else "none"
            tasks = ", ".join(info.tasks[:8]) if info.tasks else "none"
            permissions = ", ".join(info.permissions[:8]) if info.permissions else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"{len(info.imports)} import(s), {len(info.tasks)} task(s)"
            )
            lines.append(f"    imports: {imports}")
            lines.append(f"    tasks: {tasks}")
            lines.append(f"    permissions: {permissions}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
