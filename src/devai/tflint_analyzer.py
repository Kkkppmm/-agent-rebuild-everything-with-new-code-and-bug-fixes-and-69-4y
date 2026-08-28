"""TflintAnalyzer — audit TFLint HCL configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".tflint.hcl",
    "tflint.hcl",
    ".tflint.hcl.json",
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
RULE_DISABLED_PATTERN = re.compile(
    r'^\s*enabled\s*=\s*false\s*(?:#.*)?$',
    re.IGNORECASE,
)
PLUGIN_NO_VERSION_PATTERN = re.compile(
    r'^\s*source\s*=\s*"[^"]+"\s*$',
    re.IGNORECASE,
)
PLUGIN_VERSION_PATTERN = re.compile(
    r'^\s*version\s*=\s*"',
    re.IGNORECASE,
)
FORCE_FALSE_PATTERN = re.compile(
    r'^\s*force\s*=\s*false\s*(?:#.*)?$',
    re.IGNORECASE,
)
CALL_MODULE_TYPE_NONE_PATTERN = re.compile(
    r'^\s*call_module_type\s*=\s*"none"\s*(?:#.*)?$',
    re.IGNORECASE,
)
DISABLED_SECURITY_RULE_PATTERN = re.compile(
    r'^\s*name\s*=\s*"(?:aws_iam_policy_document_|aws_s3_bucket_|'
    r'aws_security_group_|terraform_unused_declarations|'
    r'aws_instance_invalid_type|aws_db_instance_default_port)"',
    re.IGNORECASE,
)
VARFILE_SENSITIVE_PATTERN = re.compile(
    r'varfile\s*=\s*"[^"]*(?:secret|password|credential|\.env)[^"]*"',
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)

SECURITY_RULE_NAMES = frozenset({
    "aws_iam_policy_document_gov_friendly_arns",
    "aws_s3_bucket_invalid_acl",
    "aws_security_group_rule_invalid_protocol",
    "terraform_unused_declarations",
    "aws_instance_invalid_type",
    "aws_db_instance_default_port",
})


@dataclass
class TflintFinding:
    """A security or best-practice issue in a TFLint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class TflintInfo:
    """Parsed metadata about a TFLint configuration file."""

    path: str
    lines: int = 0
    disabled_rules: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)
    force_enabled: bool = True


@dataclass
class TflintStats:
    """Aggregate TFLint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_tflint_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


class TflintAnalyzer:
    """Audit TFLint configuration for Terraform lint hygiene and security risks.

    Scans `.tflint.hcl` and related config files for disabled security rules,
    unversioned plugins, force=false, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[TflintFinding] | None = None
        self._stats: TflintStats | None = None
        self._infos: list[TflintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return TFLint configuration paths found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_tflint_config(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[TflintFinding], TflintInfo]:
        findings: list[TflintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TflintInfo(path=rel)

        info = TflintInfo(path=rel, lines=len(raw_lines))
        in_rule_block = False
        in_plugin_block = False
        current_rule_name = ""
        plugin_has_source = False
        plugin_has_version = False
        plugin_start_line = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            if re.match(r'^\s*rule\s+"', line):
                in_rule_block = True
                name_match = re.search(r'rule\s+"([^"]+)"', line)
                current_rule_name = name_match.group(1) if name_match else ""
                continue

            if re.match(r'^\s*plugin\s+"', line):
                in_plugin_block = True
                plugin_has_source = False
                plugin_has_version = False
                plugin_start_line = lineno
                plugin_match = re.search(r'plugin\s+"([^"]+)"', line)
                if plugin_match:
                    info.plugins.append(plugin_match.group(1))
                continue

            if in_rule_block and line.strip() == "}":
                in_rule_block = False
                current_rule_name = ""
                continue

            if in_plugin_block and line.strip() == "}":
                if plugin_has_source and not plugin_has_version:
                    findings.append(
                        TflintFinding(
                            kind="plugin_unversioned",
                            severity="medium",
                            message="TFLint plugin without version pin — pin plugin versions for reproducibility",
                            path=rel,
                            lineno=plugin_start_line,
                            line="",
                        )
                    )
                in_plugin_block = False
                continue

            if in_rule_block and RULE_DISABLED_PATTERN.search(line):
                info.disabled_rules.append(current_rule_name)
                if current_rule_name in SECURITY_RULE_NAMES or DISABLED_SECURITY_RULE_PATTERN.search(
                    f'name = "{current_rule_name}"'
                ):
                    findings.append(
                        TflintFinding(
                            kind="security_rule_disabled",
                            severity="high",
                            message=f"TFLint security rule '{current_rule_name}' disabled — keep enabled",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                else:
                    findings.append(
                        TflintFinding(
                            kind="rule_disabled",
                            severity="low",
                            message=f"TFLint rule '{current_rule_name}' disabled — document reason for suppression",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if in_plugin_block:
                if PLUGIN_NO_VERSION_PATTERN.search(line):
                    plugin_has_source = True
                if PLUGIN_VERSION_PATTERN.search(line):
                    plugin_has_version = True

            if FORCE_FALSE_PATTERN.search(line):
                info.force_enabled = False
                findings.append(
                    TflintFinding(
                        kind="force_disabled",
                        severity="medium",
                        message="force=false allows lint violations in CI — enable force for strict enforcement",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CALL_MODULE_TYPE_NONE_PATTERN.search(line):
                findings.append(
                    TflintFinding(
                        kind="call_module_type_none",
                        severity="low",
                        message="call_module_type=none skips module linting — use local or all for coverage",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if VARFILE_SENSITIVE_PATTERN.search(line):
                findings.append(
                    TflintFinding(
                        kind="sensitive_varfile",
                        severity="high",
                        message="varfile references sensitive path — avoid committing secrets via varfiles",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    TflintFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in TFLint config — use environment variables",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TflintFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP URL in TFLint config — use HTTPS endpoints",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TflintFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl|sh pattern in TFLint config — avoid piping remote scripts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if len(info.disabled_rules) >= 5:
            findings.append(
                TflintFinding(
                    kind="many_rules_disabled",
                    severity="medium",
                    message=f"{len(info.disabled_rules)} TFLint rules disabled — minimize suppressions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[TflintFinding]:
        """Scan TFLint config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TflintFinding] = []
        infos: list[TflintInfo] = []
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
        self._stats = TflintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TflintStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TflintInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no configs)."""
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
        """Scaffold a hardened TFLint configuration template."""
        return """\
# Generated by DevAI TflintAnalyzer
# TFLint config — https://github.com/terraform-linters/tflint

config {
  call_module_type = "local"
  force            = true
}

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "TFLint configs: none found"
        return (
            f"TFLint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "TFLint config analysis:",
            f"  config_files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: disabled={len(info.disabled_rules)}, "
                f"plugins={len(info.plugins)}, force={info.force_enabled}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
