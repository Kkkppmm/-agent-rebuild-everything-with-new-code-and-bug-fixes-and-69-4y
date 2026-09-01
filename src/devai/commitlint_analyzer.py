"""CommitlintAnalyzer — audit Commitlint configuration files for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".commitlintrc",
    ".commitlintrc.json",
    ".commitlintrc.js",
    ".commitlintrc.cjs",
    ".commitlintrc.mjs",
    ".commitlintrc.yaml",
    ".commitlintrc.yml",
    "commitlint.config.js",
    "commitlint.config.mjs",
    "commitlint.config.cjs",
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
INSECURE_EXTENDS_PATTERN = re.compile(
    r"(?:require|import)\s*\(\s*[\"']http://",
    re.IGNORECASE,
)
PROCESS_ENV_SECRET_PATTERN = re.compile(
    r"process\.env\.(?:[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|"
    r"PRIVATE[_-]?KEY|AUTH)[A-Z0-9_]*)",
    re.IGNORECASE,
)
CUSTOM_PARSER_EVAL_PATTERN = re.compile(
    r'["\']?parserPreset["\']?\s*:.*\beval\b|'
    r'["\']?parser["\']?\s*:.*\beval\b',
    re.IGNORECASE,
)


@dataclass
class CommitlintFinding:
    """A security or best-practice issue in a Commitlint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class CommitlintInfo:
    """Parsed metadata about a Commitlint configuration file."""

    path: str
    lines: int = 0
    extends: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    file_kind: str = ""


@dataclass
class CommitlintStats:
    """Aggregate Commitlint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith(".commitlintrc.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.endswith(".json") or name == ".commitlintrc":
        return "json"
    if name.endswith((".js", ".cjs", ".mjs")):
        return "javascript"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class CommitlintAnalyzer:
    """Audit Commitlint configuration files for security risks.

    Scans .commitlintrc.*, commitlint.config.js, and package.json commitlint config
    for hardcoded secrets, insecure HTTP extends URLs, eval in custom parsers,
    curl|sh patterns, dangerous shell commands, and process.env secret references.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CommitlintFinding] | None = None
        self._stats: CommitlintStats | None = None
        self._infos: list[CommitlintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return Commitlint configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".commitlintrc*")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("commitlint.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "commitlint" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[CommitlintFinding],
        info: CommitlintInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        extends_match = re.search(r'["\']?extends["\']?\s*:', stripped, re.IGNORECASE)
        if extends_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.extends:
                    info.extends.append(value)

        rules_match = re.search(r'["\']?rules["\']?\s*:', stripped, re.IGNORECASE)
        if rules_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.rules:
                    info.rules.append(value)

        if CUSTOM_PARSER_EVAL_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="eval_parser",
                    severity="high",
                    message="eval in Commitlint parser config — use safe parser presets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in Commitlint config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in Commitlint config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in Commitlint config — use HTTPS",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
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
                CommitlintFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in Commitlint config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in Commitlint config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_EXTENDS_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="insecure_extends",
                    severity="high",
                    message="Commitlint extends loaded over insecure HTTP — use HTTPS or local packages",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROCESS_ENV_SECRET_PATTERN.search(line):
            findings.append(
                CommitlintFinding(
                    kind="secret_env_reference",
                    severity="medium",
                    message="process.env secret reference in Commitlint config — avoid committing env values",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_content(
        self,
        text: str,
        rel: str,
        findings: list[CommitlintFinding],
        info: CommitlintInfo,
        *,
        from_package: bool = False,
    ) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                CommitlintFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="Commitlint config is not valid JSON — fix syntax before relying on settings",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return

        if from_package:
            config = data.get("commitlint", {})
        else:
            config = data

        if not isinstance(config, dict):
            return

        extends = config.get("extends", [])
        if isinstance(extends, list):
            info.extends.extend(str(e) for e in extends if str(e) not in info.extends)
            for ext in extends:
                ext_str = str(ext)
                if INSECURE_HTTP_PATTERN.search(ext_str):
                    findings.append(
                        CommitlintFinding(
                            kind="insecure_http",
                            severity="high",
                            message="insecure HTTP extends URL — use HTTPS or local packages",
                            path=rel,
                            lineno=1,
                            line=ext_str,
                        )
                    )

        rules = config.get("rules", {})
        if isinstance(rules, dict):
            for rule_name in rules:
                if rule_name not in info.rules:
                    info.rules.append(rule_name)

    def _analyze_file(self, path: Path) -> tuple[list[CommitlintFinding], CommitlintInfo]:
        findings: list[CommitlintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, CommitlintInfo(path=rel, file_kind=_file_kind(path))

        info = CommitlintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        from_package = path.name == "package.json"

        if from_package or path.suffix == ".json" or path.name == ".commitlintrc":
            self._analyze_json_content(
                raw_text, rel, findings, info, from_package=from_package
            )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[CommitlintFinding]:
        """Scan Commitlint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CommitlintFinding] = []
        infos: list[CommitlintInfo] = []
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
        self._stats = CommitlintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CommitlintStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CommitlintInfo]:
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
        """Scaffold a hardened Commitlint configuration template."""
        return """\
{
  "extends": ["@commitlint/config-conventional"],
  "rules": {
    "type-enum": [2, "always", [
      "feat", "fix", "docs", "style", "refactor",
      "perf", "test", "build", "ci", "chore", "revert"
    ]],
    "subject-max-length": [2, "always", 72],
    "body-max-line-length": [2, "always", 100]
  }
}
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "Commitlint: no config files found"
        return (
            f"Commitlint: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Commitlint configuration analysis:",
            self.summary(),
            f"Health score: {self.health_score()}",
        ]
        for finding in self._findings or []:
            lines.append(finding.format())
        if stats.config_files == 0:
            lines.append("No Commitlint config files found.")
        return "\n".join(lines)
