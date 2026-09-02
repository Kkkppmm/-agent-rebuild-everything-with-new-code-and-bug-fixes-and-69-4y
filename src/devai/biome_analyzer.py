"""BiomeAnalyzer — audit Biome configuration files for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    "biome.json",
    "biome.jsonc",
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
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r'["\']?(?:noDangerouslySetInnerHtml|noGlobalEval|noDebugger|'
    r"noBlankTarget|noDangerouslySetInnerHtml|noGlobalEval|"
    r"noSecretsInObjects|noAccumulatingSpread)[\"']?\s*:\s*"
    r"(?:[\"']?(?:off|false|0)[\"']?)",
    re.IGNORECASE,
)
VCS_IGNORE_DISABLED_PATTERN = re.compile(
    r'["\']?useIgnoreFile["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)
VCS_DISABLED_PATTERN = re.compile(
    r'["\']?vcs["\']?\s*:\s*\{[^}]*["\']?enabled["\']?\s*:\s*(?:false|0)',
    re.IGNORECASE,
)


@dataclass
class BiomeFinding:
    """A security or best-practice issue in a Biome configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class BiomeInfo:
    """Parsed metadata about a Biome configuration file."""

    path: str
    lines: int = 0
    linter_enabled: bool = True
    formatter_enabled: bool = True
    rules: list[str] = field(default_factory=list)
    vcs_enabled: bool = False
    use_ignore_file: bool = True
    file_kind: str = ""


@dataclass
class BiomeStats:
    """Aggregate Biome analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".jsonc"):
        return "jsonc"
    if name.endswith(".json"):
        return "json"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


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
        if text[i : i + 2] == "//":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if text[i : i + 2] == "/*":
            end = text.find("*/", i + 2)
            i = end + 2 if end != -1 else len(text)
            continue
        result.append(ch)
        i += 1
    return "".join(result)


class BiomeAnalyzer:
    """Audit Biome configuration files for security risks.

    Scans biome.json and biome.jsonc for hardcoded secrets, insecure HTTP
    schema URLs, disabled security rules (noDangerouslySetInnerHtml,
    noGlobalEval, noDebugger), disabled VCS ignore integration, curl|sh
    patterns, and dangerous shell commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[BiomeFinding] | None = None
        self._stats: BiomeStats | None = None
        self._infos: list[BiomeInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Biome configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob("biome.json")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("biome.jsonc")):
            if path.is_file() and path not in found:
                found.append(path)
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[BiomeFinding],
        info: BiomeInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                BiomeFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Biome config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                BiomeFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Biome config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                BiomeFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Biome config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                BiomeFinding(
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
                BiomeFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Biome config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                BiomeFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Biome config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line):
            findings.append(
                BiomeFinding(
                    kind="disabled_security_rule",
                    severity="medium",
                    message="security-related Biome rule disabled — review before merging",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if VCS_IGNORE_DISABLED_PATTERN.search(line):
            info.use_ignore_file = False
            findings.append(
                BiomeFinding(
                    kind="vcs_ignore_disabled",
                    severity="medium",
                    message="vcs.useIgnoreFile disabled — .gitignore patterns may not apply to Biome",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'["\']?linter["\']?\s*:\s*\{[^}]*["\']?enabled["\']?\s*:\s*false', stripped, re.IGNORECASE):
            info.linter_enabled = False
            findings.append(
                BiomeFinding(
                    kind="linter_disabled",
                    severity="low",
                    message="Biome linter disabled — security rules will not run",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        for value in _extract_string_literals(stripped):
            if "/" in value and value not in info.rules:
                info.rules.append(value)

    def _analyze_json_content(
        self,
        text: str,
        rel: str,
        findings: list[BiomeFinding],
        info: BiomeInfo,
    ) -> None:
        cleaned = _strip_jsonc_comments(text)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            findings.append(
                BiomeFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="Biome config is not valid JSON — fix syntax before relying on rules",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return

        if not isinstance(data, dict):
            return

        linter = data.get("linter", {})
        if isinstance(linter, dict):
            if linter.get("enabled") is False:
                info.linter_enabled = False
                findings.append(
                    BiomeFinding(
                        kind="linter_disabled",
                        severity="low",
                        message="Biome linter disabled — security rules will not run",
                        path=rel,
                        lineno=1,
                        line="linter.enabled: false",
                    )
                )
            rules = linter.get("rules", {})
            if isinstance(rules, dict):
                self._check_rules_dict(rules, rel, findings, info)

        formatter = data.get("formatter", {})
        if isinstance(formatter, dict) and formatter.get("enabled") is False:
            info.formatter_enabled = False

        vcs = data.get("vcs", {})
        if isinstance(vcs, dict):
            info.vcs_enabled = vcs.get("enabled", False) is True
            if vcs.get("useIgnoreFile") is False:
                info.use_ignore_file = False
                findings.append(
                    BiomeFinding(
                        kind="vcs_ignore_disabled",
                        severity="medium",
                        message="vcs.useIgnoreFile disabled — .gitignore patterns may not apply",
                        path=rel,
                        lineno=1,
                        line="vcs.useIgnoreFile: false",
                    )
                )

        schema = data.get("$schema", "")
        if isinstance(schema, str) and INSECURE_HTTP_PATTERN.search(schema):
            findings.append(
                BiomeFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP $schema URL — use HTTPS",
                    path=rel,
                    lineno=1,
                    line=schema,
                )
            )

    def _check_rules_dict(
        self,
        rules: dict,
        rel: str,
        findings: list[BiomeFinding],
        info: BiomeInfo,
        prefix: str = "",
    ) -> None:
        security_rules = (
            "noDangerouslySetInnerHtml",
            "noGlobalEval",
            "noDebugger",
            "noBlankTarget",
            "noSecretsInObjects",
            "noAccumulatingSpread",
        )
        for key, value in rules.items():
            full_key = f"{prefix}/{key}" if prefix else key
            if key in info.rules:
                pass
            else:
                info.rules.append(full_key)
            if isinstance(value, dict):
                self._check_rules_dict(value, rel, findings, info, full_key)
            elif value in ("off", False, 0) and any(
                sr.lower() in key.lower() for sr in security_rules
            ):
                findings.append(
                    BiomeFinding(
                        kind="disabled_security_rule",
                        severity="medium",
                        message=f"security rule '{full_key}' disabled in Biome config",
                        path=rel,
                        lineno=1,
                        line=full_key,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[BiomeFinding], BiomeInfo]:
        findings: list[BiomeFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, BiomeInfo(path=rel, file_kind=_file_kind(path))

        info = BiomeInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        self._analyze_json_content(raw_text, rel, findings, info)

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[BiomeFinding]:
        """Scan Biome configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[BiomeFinding] = []
        infos: list[BiomeInfo] = []
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
        self._stats = BiomeStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> BiomeStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[BiomeInfo]:
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
        """Scaffold a hardened Biome configuration template."""
        return """\
{
  "$schema": "https://biomejs.dev/schemas/1.9.4/schema.json",
  "vcs": {
    "enabled": true,
    "clientKind": "git",
    "useIgnoreFile": true
  },
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "security": {
        "noDangerouslySetInnerHtml": "error",
        "noGlobalEval": "error"
      },
      "suspicious": {
        "noDebugger": "error"
      }
    }
  },
  "formatter": {
    "enabled": true
  },
  "organizeImports": {
    "enabled": true
  }
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Biome: no config files found"
        return (
            f"Biome: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Biome configuration analysis:",
            self.summary(),
            f"Health score: {self.health_score()}",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        if stats.config_files == 0:
            lines.append("No biome.json or biome.jsonc found.")
        return "\n".join(lines)
