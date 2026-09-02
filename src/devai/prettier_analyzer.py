"""PrettierAnalyzer — audit Prettier configuration files for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.js",
    ".prettierrc.cjs",
    ".prettierrc.mjs",
    ".prettierrc.yaml",
    ".prettierrc.yml",
    "prettier.config.js",
    "prettier.config.mjs",
    "prettier.config.cjs",
)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:[\"']?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[\"']?)\s*[=:]\s*"
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DANGEROUS_SHELL_PATTERN = re.compile(
    r"(?:rm\s+-rf\s+/|chmod\s+777|eval\s*\(|"
    r"\bsh\s+-c\b|\bsudo\b)",
    re.IGNORECASE,
)
INSECURE_PLUGIN_PATTERN = re.compile(
    r"(?:require|import)\s*\(\s*[\"']http://",
    re.IGNORECASE,
)
PROCESS_ENV_SECRET_PATTERN = re.compile(
    r"process\.env\.(?:[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|"
    r"PRIVATE[_-]?KEY|AUTH)[A-Z0-9_]*)",
    re.IGNORECASE,
)


@dataclass
class PrettierFinding:
    """A security or best-practice issue in a Prettier configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class PrettierInfo:
    """Parsed metadata about a Prettier configuration file."""

    path: str
    lines: int = 0
    plugins: list[str] = field(default_factory=list)
    overrides: int = 0
    file_kind: str = ""


@dataclass
class PrettierStats:
    """Aggregate Prettier analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith(".prettierrc.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".json") or name == ".prettierrc":
        return "json"
    if name.endswith((".js", ".cjs", ".mjs")):
        return "javascript"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class PrettierAnalyzer:
    """Audit Prettier configuration files for security risks.

    Scans .prettierrc.*, prettier.config.js, and package.json prettier config
    for hardcoded secrets, insecure HTTP plugin URLs, curl|sh patterns,
    dangerous shell commands, and process.env secret references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[PrettierFinding] | None = None
        self._stats: PrettierStats | None = None
        self._infos: list[PrettierInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Prettier configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".prettierrc*")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("prettier.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "prettier" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[PrettierFinding],
        info: PrettierInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for value in _extract_string_literals(stripped):
            if "prettier-plugin" in value and value not in info.plugins:
                info.plugins.append(value)

        plugin_match = re.search(r'["\']?plugins["\']?\s*:', stripped, re.IGNORECASE)
        if plugin_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.plugins:
                    info.plugins.append(value)

        if re.search(r'["\']?overrides["\']?\s*:', stripped, re.IGNORECASE):
            info.overrides += 1

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Prettier config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Prettier config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Prettier config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="scm_credentials",
                    severity="high",
                    message="credentials embedded in URL — use SSH keys or secret stores",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Prettier config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Prettier config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_PLUGIN_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="insecure_plugin",
                    severity="high",
                    message="Prettier plugin loaded over insecure HTTP — use HTTPS or local packages",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROCESS_ENV_SECRET_PATTERN.search(line):
            findings.append(
                PrettierFinding(
                    kind="secret_env_reference",
                    severity="medium",
                    message="process.env secret reference in Prettier config — avoid committing env values",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_content(
        self,
        text: str,
        rel: str,
        findings: list[PrettierFinding],
        info: PrettierInfo,
        *,
        from_package: bool = False,
    ) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                PrettierFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="Prettier config is not valid JSON — fix syntax before relying on settings",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return

        if from_package:
            config = data.get("prettier", {})
        else:
            config = data

        if not isinstance(config, dict):
            return

        plugins = config.get("plugins", [])
        if isinstance(plugins, list):
            info.plugins.extend(str(p) for p in plugins if str(p) not in info.plugins)
            for plugin in plugins:
                plugin_str = str(plugin)
                if INSECURE_HTTP_PATTERN.search(plugin_str):
                    findings.append(
                        PrettierFinding(
                            kind="insecure_http",
                            severity="high",
                            message="insecure HTTP plugin URL — use HTTPS or local packages",
                            path=rel,
                            lineno=1,
                            line=plugin_str,
                        )
                    )

        overrides = config.get("overrides", [])
        if isinstance(overrides, list):
            info.overrides = len(overrides)

    def _analyze_file(self, path: Path) -> tuple[list[PrettierFinding], PrettierInfo]:
        findings: list[PrettierFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, PrettierInfo(path=rel, file_kind=_file_kind(path))

        info = PrettierInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        from_package = path.name == "package.json"

        if from_package or path.suffix == ".json" or path.name == ".prettierrc":
            self._analyze_json_content(
                raw_text, rel, findings, info, from_package=from_package
            )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[PrettierFinding]:
        """Scan Prettier configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[PrettierFinding] = []
        infos: list[PrettierInfo] = []
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
        self._stats = PrettierStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> PrettierStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[PrettierInfo]:
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
        """Scaffold a hardened Prettier configuration template."""
        return """\
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "all",
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "endOfLine": "lf",
  "arrowParens": "always",
  "bracketSpacing": true,
  "plugins": []
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Prettier: no config files found"
        return (
            f"Prettier: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Prettier configuration analysis:",
            self.summary(),
            f"Health score: {self.health_score()}",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        if stats.config_files == 0:
            lines.append("No Prettier config files found.")
        return "\n".join(lines)
