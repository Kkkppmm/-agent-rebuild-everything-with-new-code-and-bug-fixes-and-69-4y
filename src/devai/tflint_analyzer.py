"""TflintAnalyzer — audit TFLint configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".tflint.hcl",
    "tflint.hcl",
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
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DISABLED_BY_DEFAULT_PATTERN = re.compile(
    r"^\s*disabled_by_default\s*=\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
RULE_BLOCK_PATTERN = re.compile(
    r"^\s*rule\s+[\"']([^\"']+)[\"']\s*\{",
    re.IGNORECASE,
)
PLUGIN_BLOCK_PATTERN = re.compile(
    r"^\s*plugin\s+[\"']([^\"']+)[\"']\s*\{",
    re.IGNORECASE,
)
ENABLED_FALSE_PATTERN = re.compile(
    r"^\s*enabled\s*=\s*false\s*(?:#.*)?$",
    re.IGNORECASE,
)
FORCE_TRUE_PATTERN = re.compile(
    r"^\s*force\s*=\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
CALL_MODULE_TYPE_ALL_PATTERN = re.compile(
    r"^\s*call_module_type\s*=\s*[\"']?all[\"']?\s*(?:#.*)?$",
    re.IGNORECASE,
)
PLUGIN_VERSION_PATTERN = re.compile(
    r"^\s*version\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
PLUGIN_SOURCE_PATTERN = re.compile(
    r"^\s*source\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
IGNORE_MODULE_PATTERN = re.compile(
    r"^\s*ignore_module\s*\{",
    re.IGNORECASE,
)
MODULE_SOURCE_PATTERN = re.compile(
    r"^\s*module_source\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
VAR_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z_][\w]*)\s*=\s*[\"']([^\"']+)[\"']",
)

# Security-sensitive TFLint rules grouped by concern.
VERSION_RULES = frozenset(
    {
        "terraform_required_version",
        "terraform_required_providers",
        "terraform_typed_variables",
    }
)
UNUSED_RULES = frozenset(
    {
        "terraform_unused_declarations",
        "terraform_documented_outputs",
        "terraform_documented_variables",
    }
)
AWS_PUBLIC_ACCESS_RULES = frozenset(
    {
        "aws_s3_bucket_public_access_block",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_acl",
        "aws_s3_bucket_logging",
        "aws_s3_bucket_server_side_encryption_configuration",
        "aws_s3_bucket_versioning",
    }
)
AWS_IAM_RULES = frozenset(
    {
        "aws_iam_policy_document",
        "aws_iam_role_policy",
        "aws_iam_policy",
        "aws_iam_role",
        "aws_iam_user_policy",
    }
)
AWS_NETWORK_RULES = frozenset(
    {
        "aws_security_group_rule",
        "aws_security_group",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpc_security_group_egress_rule",
    }
)


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
    disabled_by_default: bool = False
    call_module_type: str = ""
    ignore_modules: int = 0


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


def _rule_category(rule_name: str) -> str | None:
    lower = rule_name.lower()
    if lower in VERSION_RULES:
        return "version"
    if lower in UNUSED_RULES:
        return "unused"
    if lower in AWS_PUBLIC_ACCESS_RULES:
        return "aws_public_access"
    if lower in AWS_IAM_RULES:
        return "aws_iam"
    if lower in AWS_NETWORK_RULES:
        return "aws_network"
    if lower.startswith("aws_") and any(
        token in lower for token in ("public", "encrypt", "ssl", "tls", "policy", "acl")
    ):
        return "aws_security"
    return None


class TflintAnalyzer:
    """Audit TFLint configuration for lint hygiene and security risks.

    Scans `.tflint.hcl` files for disabled security rules, disabled_by_default,
    unpinned plugins, force=true upgrades, broad ignore_module blocks, and
    hardcoded secrets.
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
        current_rule: str | None = None
        current_plugin: str | None = None
        plugin_has_version = False
        plugin_has_source = False
        plugin_block_start = 0
        in_ignore_module = False
        disabled_rules_in_file: list[str] = []

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            rule_match = RULE_BLOCK_PATTERN.search(line)
            if rule_match:
                current_rule = rule_match.group(1)
                current_plugin = None
                continue

            plugin_match = PLUGIN_BLOCK_PATTERN.search(line)
            if plugin_match:
                current_plugin = plugin_match.group(1)
                info.plugins.append(current_plugin)
                plugin_has_version = False
                plugin_has_source = False
                plugin_block_start = lineno
                current_rule = None
                continue

            if IGNORE_MODULE_PATTERN.search(line):
                in_ignore_module = True
                info.ignore_modules += 1
                continue

            if stripped == "}":
                if current_plugin and not plugin_has_version:
                    findings.append(
                        TflintFinding(
                            kind="plugin_unpinned",
                            severity="medium",
                            message=(
                                f"plugin \"{current_plugin}\" has no version pin — "
                                "pin plugin versions for reproducible lint runs"
                            ),
                            path=rel,
                            lineno=plugin_block_start,
                            line="",
                        )
                    )
                current_rule = None
                current_plugin = None
                in_ignore_module = False
                continue

            if DISABLED_BY_DEFAULT_PATTERN.search(line):
                info.disabled_by_default = True
                findings.append(
                    TflintFinding(
                        kind="disabled_by_default",
                        severity="high",
                        message="disabled_by_default=true — rules must be explicitly enabled; security rules may be skipped",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CALL_MODULE_TYPE_ALL_PATTERN.search(line):
                info.call_module_type = "all"
                findings.append(
                    TflintFinding(
                        kind="call_module_type_all",
                        severity="medium",
                        message="call_module_type=all is deprecated and overly permissive — use local or module",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if FORCE_TRUE_PATTERN.search(line) and current_plugin:
                findings.append(
                    TflintFinding(
                        kind="plugin_force",
                        severity="medium",
                        message=(
                            f"plugin \"{current_plugin}\" uses force=true — "
                            "avoid forcing plugin upgrades without review"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PLUGIN_VERSION_PATTERN.search(line) and current_plugin:
                plugin_has_version = True

            source_match = PLUGIN_SOURCE_PATTERN.search(line)
            if source_match and current_plugin:
                plugin_has_source = True
                source = source_match.group(1)
                if source.startswith("http://"):
                    findings.append(
                        TflintFinding(
                            kind="insecure_plugin_source",
                            severity="high",
                            message=f"plugin \"{current_plugin}\" source uses HTTP — use HTTPS or git source URLs",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            module_source_match = MODULE_SOURCE_PATTERN.search(line)
            if module_source_match:
                module_source = module_source_match.group(1)
                if module_source.startswith("http://"):
                    findings.append(
                        TflintFinding(
                            kind="insecure_module_source",
                            severity="medium",
                            message="ignore_module references HTTP module source — use HTTPS or git refs",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if ENABLED_FALSE_PATTERN.search(line) and current_rule:
                info.disabled_rules.append(current_rule)
                disabled_rules_in_file.append(current_rule)
                category = _rule_category(current_rule)
                if category == "version":
                    findings.append(
                        TflintFinding(
                            kind="version_rule_disabled",
                            severity="high",
                            message=(
                                f"rule \"{current_rule}\" disabled — keep version/provider "
                                "checks enabled for Terraform hygiene"
                            ),
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif category == "aws_public_access":
                    findings.append(
                        TflintFinding(
                            kind="aws_public_access_disabled",
                            severity="high",
                            message=(
                                f"rule \"{current_rule}\" disabled — do not disable S3 "
                                "public-access lint checks"
                            ),
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif category in {"aws_iam", "aws_network", "aws_security"}:
                    findings.append(
                        TflintFinding(
                            kind="aws_security_rule_disabled",
                            severity="high",
                            message=(
                                f"rule \"{current_rule}\" disabled — keep AWS security "
                                "lint rules enabled"
                            ),
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )
                elif category == "unused":
                    findings.append(
                        TflintFinding(
                            kind="unused_rule_disabled",
                            severity="medium",
                            message=(
                                f"rule \"{current_rule}\" disabled — unused declaration "
                                "checks help catch dead infrastructure code"
                            ),
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
                            message=f"rule \"{current_rule}\" disabled — document why this rule is suppressed",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

            if ENABLED_FALSE_PATTERN.search(line) and current_plugin:
                findings.append(
                    TflintFinding(
                        kind="plugin_disabled",
                        severity="medium",
                        message=(
                            f"plugin \"{current_plugin}\" disabled — verify required "
                            "rulesets remain active"
                        ),
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_ignore_module and stripped.startswith("enabled") and "false" in stripped.lower():
                findings.append(
                    TflintFinding(
                        kind="ignore_module_disabled",
                        severity="medium",
                        message="ignore_module block disables module linting — scope ignores narrowly",
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

        if len(disabled_rules_in_file) >= 5:
            findings.append(
                TflintFinding(
                    kind="many_rules_disabled",
                    severity="medium",
                    message=f"{len(disabled_rules_in_file)} rules disabled — review TFLint suppressions regularly",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.ignore_modules >= 3:
            findings.append(
                TflintFinding(
                    kind="many_ignore_modules",
                    severity="medium",
                    message=f"{info.ignore_modules} ignore_module blocks — broad module ignores hide lint issues",
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
# Run: tflint --init && tflint

config {
  call_module_type = "module"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# Example AWS ruleset — pin version after tflint --init
# plugin "aws" {
#   enabled = true
#   version = "0.27.0"
#   source  = "github.com/terraform-linters/tflint-ruleset-aws"
# }
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
                f"  - {info.path}: plugins={len(info.plugins)}, "
                f"disabled_rules={len(info.disabled_rules)}, "
                f"disabled_by_default={info.disabled_by_default}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
