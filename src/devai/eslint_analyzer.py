"""ESLintAnalyzer — audit ESLint configuration files for security risks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".eslintrc",
    ".eslintrc.json",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.yaml",
    ".eslintrc.yml",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
)

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
    r'["\']?(?:no-eval|no-implied-eval|no-new-func|no-script-url|'
    r"security/detect-eval-with-expression|security/detect-non-literal-regexp|"
    r"security/detect-object-injection|security/detect-unsafe-regex)[\"']?\s*:\s*"
    r"(?:[\"']?(?:0|off|false)[\"']?)",
    re.IGNORECASE,
)
PROCESS_ENV_SECRET_PATTERN = re.compile(
    r"process\.env\.(?:[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|"
    r"PRIVATE[_-]?KEY|AUTH)[A-Z0-9_]*)",
    re.IGNORECASE,
)
GLOBAL_EVAL_PATTERN = re.compile(
    r'["\']?globals["\']?\s*:.*\b(?:eval|Function)\b',
    re.IGNORECASE,
)


@dataclass
class ESLintFinding:
    """A security or best-practice issue in an ESLint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ESLintInfo:
    """Parsed metadata about an ESLint configuration file."""

    path: str
    lines: int = 0
    extends: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    envs: list[str] = field(default_factory=list)
    file_kind: str = ""


@dataclass
class ESLintStats:
    """Aggregate ESLint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_config_file(path: Path) -> bool:
    return path.name in CONFIG_NAMES or path.name.startswith(".eslintrc.")


def _file_kind(path: Path) -> str:
    name = path.name
    if name.startswith("eslint.config."):
        return "flat"
    if name.endswith(".json") or name == ".eslintrc":
        return "json"
    if name.endswith((".js", ".cjs", ".mjs")):
        return "javascript"
    if name.endswith((".yaml", ".yml")):
        return "yaml"
    return "unknown"


def _extract_string_literals(line: str) -> list[str]:
    return re.findall(r'["\']([^"\'\\]*(?:\\.[^"\'\\]*)*)["\']', line)


class ESLintAnalyzer:
    """Audit ESLint configuration files for security risks.

    Scans .eslintrc.*, eslint.config.js, and package.json eslintConfig for
    hardcoded secrets, insecure HTTP extends URLs, disabled security rules,
    eval globals, curl-pipe-to-shell in overrides, and process.env secret
    references in rule configuration.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ESLintFinding] | None = None
        self._stats: ESLintStats | None = None
        self._infos: list[ESLintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return ESLint configuration paths found in the project."""
        found: list[Path] = []
        for name in CONFIG_NAMES:
            path = self.root / name
            if path.is_file():
                found.append(path)
        for path in sorted(self.root.rglob(".eslintrc*")):
            if path.is_file() and path not in found:
                found.append(path)
        for path in sorted(self.root.rglob("eslint.config.*")):
            if path.is_file() and path not in found:
                found.append(path)
        pkg = self.root / "package.json"
        if pkg.is_file():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict) and "eslintConfig" in data:
                    found.append(pkg)
            except (OSError, json.JSONDecodeError):
                pass
        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ESLintFinding],
        info: ESLintInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            return

        for value in _extract_string_literals(stripped):
            if value.startswith("plugin:") and value not in info.extends:
                info.extends.append(value)
            if value.startswith("eslint-plugin-") and value not in info.plugins:
                info.plugins.append(value)

        extend_match = re.search(r'["\']?extends["\']?\s*:', stripped, re.IGNORECASE)
        if extend_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.extends:
                    info.extends.append(value)

        plugin_match = re.search(r'["\']?plugins["\']?\s*:', stripped, re.IGNORECASE)
        if plugin_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.plugins:
                    info.plugins.append(value)

        env_match = re.search(r'["\']?env["\']?\s*:', stripped, re.IGNORECASE)
        if env_match:
            for value in _extract_string_literals(stripped):
                if value and value not in info.envs:
                    info.envs.append(value)

        rule_match = re.search(r'["\']?rules["\']?\s*:', stripped, re.IGNORECASE)
        if rule_match or re.match(r'^\s*["\'][^"\']+["\']\s*:', stripped):
            for value in _extract_string_literals(stripped):
                if "/" in value or value.startswith("no-"):
                    if value not in info.rules:
                        info.rules.append(value)

        if HARDCODED_SECRET_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded secret in ESLint config — use env vars or CI secrets",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="aws_access_key",
                    severity="high",
                    message="AWS access key in ESLint config — rotate and use env vars",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="insecure_http",
                    severity="high",
                    message="insecure HTTP URL in extends — use HTTPS for remote configs",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if SCM_CREDENTIALS_PATTERN.search(line):
            findings.append(
                ESLintFinding(
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
                ESLintFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|sh pattern in ESLint config — avoid piping remote scripts",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DANGEROUS_SHELL_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="dangerous_shell",
                    severity="high",
                    message="dangerous shell command in ESLint config",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if DISABLED_SECURITY_RULE_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="disabled_security_rule",
                    severity="medium",
                    message="security-related ESLint rule disabled — review before merging",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if GLOBAL_EVAL_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="eval_global",
                    severity="medium",
                    message="eval or Function enabled as global — increases XSS risk in linted code",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if PROCESS_ENV_SECRET_PATTERN.search(line):
            findings.append(
                ESLintFinding(
                    kind="secret_env_reference",
                    severity="medium",
                    message="process.env secret reference in ESLint config — avoid committing env values",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if re.search(r'["\']?root["\']?\s*:\s*false', stripped, re.IGNORECASE):
            findings.append(
                ESLintFinding(
                    kind="root_false",
                    severity="low",
                    message="root: false may inherit parent ESLint config unexpectedly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _analyze_json_content(
        self,
        text: str,
        rel: str,
        findings: list[ESLintFinding],
        info: ESLintInfo,
        *,
        from_package: bool = False,
    ) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                ESLintFinding(
                    kind="invalid_json",
                    severity="medium",
                    message="ESLint config is not valid JSON — fix syntax before relying on rules",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )
            return

        if from_package:
            config = data.get("eslintConfig", {})
        else:
            config = data

        if not isinstance(config, dict):
            return

        extends = config.get("extends", [])
        if isinstance(extends, str):
            extends = [extends]
        if isinstance(extends, list):
            info.extends.extend(str(e) for e in extends if str(e) not in info.extends)

        plugins = config.get("plugins", [])
        if isinstance(plugins, list):
            info.plugins.extend(str(p) for p in plugins if str(p) not in info.plugins)

        envs = config.get("env", {})
        if isinstance(envs, dict):
            for key, enabled in envs.items():
                if enabled and key not in info.envs:
                    info.envs.append(key)

        rules = config.get("rules", {})
        if isinstance(rules, dict):
            for rule, value in rules.items():
                if rule not in info.rules:
                    info.rules.append(rule)
                if value in (0, "off", False) and re.search(
                    r"no-eval|no-implied-eval|no-new-func|security/", rule, re.IGNORECASE
                ):
                    findings.append(
                        ESLintFinding(
                            kind="disabled_security_rule",
                            severity="medium",
                            message=f"security rule '{rule}' disabled in ESLint config",
                            path=rel,
                            lineno=1,
                            line=rule,
                        )
                    )

        for extend in info.extends:
            if INSECURE_HTTP_PATTERN.search(extend):
                findings.append(
                    ESLintFinding(
                        kind="insecure_http",
                        severity="high",
                        message="insecure HTTP URL in extends — use HTTPS for remote configs",
                        path=rel,
                        lineno=1,
                        line=extend,
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[ESLintFinding], ESLintInfo]:
        findings: list[ESLintFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = raw_text.splitlines()
        except OSError:
            return findings, ESLintInfo(path=rel, file_kind=_file_kind(path))

        info = ESLintInfo(path=rel, lines=len(raw_lines), file_kind=_file_kind(path))
        from_package = path.name == "package.json"

        if from_package or path.suffix == ".json" or path.name == ".eslintrc":
            self._analyze_json_content(
                raw_text, rel, findings, info, from_package=from_package
            )
            return findings, info

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        return findings, info

    def analyze(self) -> list[ESLintFinding]:
        """Scan ESLint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ESLintFinding] = []
        infos: list[ESLintInfo] = []
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
        self._stats = ESLintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ESLintStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ESLintInfo]:
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
        """Scaffold a hardened ESLint flat config template."""
        return """\
// Generated by DevAI ESLintAnalyzer
import js from "@eslint/js";
import security from "eslint-plugin-security";

export default [
  js.configs.recommended,
  security.configs.recommended,
  {
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
    },
  },
];
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "ESLint: no config files found"
        return (
            f"ESLint: {stats.config_files} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "ESLint configuration analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            extends = ", ".join(info.extends[:6]) if info.extends else "none"
            plugins = ", ".join(info.plugins[:6]) if info.plugins else "none"
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"extends={extends}, plugins={plugins}"
            )
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
