"""YamllintAnalyzer — audit yamllint configuration files for hygiene and security risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAMES = (
    ".yamllint",
    ".yamllint.yaml",
    ".yamllint.yml",
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
EXTENDS_RELAXED_PATTERN = re.compile(
    r"^\s*extends\s*:\s*(?:relaxed|disable)\s*(?:#.*)?$",
    re.IGNORECASE,
)
RULE_DISABLE_PATTERN = re.compile(
    r"^\s{2,}([\w-]+)\s*:\s*disable\s*(?:#.*)?$",
    re.IGNORECASE,
)
RULE_DISABLE_OBJECT_PATTERN = re.compile(
    r"^\s{2,}([\w-]+)\s*:\s*$",
    re.IGNORECASE,
)
DISABLE_TRUE_PATTERN = re.compile(
    r"^\s+disable\s*:\s*true\s*(?:#.*)?$",
    re.IGNORECASE,
)
LINE_LENGTH_HIGH_PATTERN = re.compile(
    r"^\s+max\s*:\s*(?:2[0-9]{2}|[3-9][0-9]{2}|[1-9][0-9]{3,})\s*(?:#.*)?$",
    re.IGNORECASE,
)
IGNORE_SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'])(?:\.github|k8s|kubernetes|deploy(?:ment)?s?|helm|charts?|"
    r"manifests?|\.kube|infra(?:structure)?|terraform|ansible|argocd|flux)(?:/|[\s\"']|$)",
    re.IGNORECASE,
)
IGNORE_WILDCARD_PATTERN = re.compile(
    r"ignore\s*:\s*[^\n]*\*",
    re.IGNORECASE,
)
COMMENTS_SPACES_LOW_PATTERN = re.compile(
    r"min-spaces-from-content\s*:\s*(?:0|1)\s*(?:#.*)?$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)

# Security-sensitive yamllint rules grouped by concern.
TRUTHY_RULES = frozenset({"truthy"})
DUPLICATE_RULES = frozenset({"key-duplicates", "key_duplicates"})
OCTAL_RULES = frozenset({"octal-values", "octal_values"})
DOCUMENT_RULES = frozenset({"document-start", "document_start", "new-line-at-end-of-file", "new_line_at_end_of_file"})
QUOTED_STRING_RULES = frozenset({"quoted-strings", "quoted_strings"})
BRACE_RULES = frozenset({"braces", "brackets", "commas"})


@dataclass
class YamllintFinding:
    """A security or best-practice issue in a yamllint configuration file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class YamllintInfo:
    """Parsed metadata about a yamllint configuration file."""

    path: str
    lines: int = 0
    extends: str = ""
    disabled_rules: list[str] = field(default_factory=list)
    line_length_max: int | None = None
    has_ignore: bool = False


@dataclass
class YamllintStats:
    """Aggregate yamllint analysis statistics."""

    config_files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_yamllint_config(path: Path) -> bool:
    return path.name.lower() in CONFIG_NAMES


def _extract_line_length_max(line: str) -> int | None:
    match = re.search(r"^\s+max\s*:\s*(\d+)\s*(?:#.*)?$", line, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


class YamllintAnalyzer:
    """Audit yamllint configuration for YAML hygiene and security risks.

    Scans `.yamllint`, `.yamllint.yaml`, and `.yamllint.yml` for permissive
    extends profiles, disabled truthy/key-duplicates/octal checks, broad ignore
    patterns that skip CI or deployment YAML, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[YamllintFinding] | None = None
        self._stats: YamllintStats | None = None
        self._infos: list[YamllintInfo] | None = None

    def config_files(self) -> list[Path]:
        """Return yamllint configuration paths found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_yamllint_config(path):
                paths.append(path)
        return paths

    def _record_rule_disable(
        self,
        rule: str,
        lineno: int,
        rel: str,
        line: str,
        findings: list[YamllintFinding],
        info: YamllintInfo,
    ) -> None:
        normalized = rule.lower().replace("_", "-")
        info.disabled_rules.append(normalized)

        if normalized in TRUTHY_RULES:
            findings.append(
                YamllintFinding(
                    kind="truthy_disabled",
                    severity="high",
                    message="truthy rule disabled — YAML yes/on/true coercion can hide misconfigurations",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in DUPLICATE_RULES:
            findings.append(
                YamllintFinding(
                    kind="key_duplicates_disabled",
                    severity="high",
                    message="key-duplicates disabled — duplicate keys silently override values in YAML",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in OCTAL_RULES:
            findings.append(
                YamllintFinding(
                    kind="octal_values_disabled",
                    severity="medium",
                    message="octal-values disabled — verify file mode permissions in manifests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in QUOTED_STRING_RULES:
            findings.append(
                YamllintFinding(
                    kind="quoted_strings_disabled",
                    severity="medium",
                    message="quoted-strings disabled — unquoted scalars may parse inconsistently",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in BRACE_RULES:
            findings.append(
                YamllintFinding(
                    kind="structure_rule_disabled",
                    severity="low",
                    message=f"{normalized} disabled — keep flow-style YAML structure checks enabled",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )
        elif normalized in DOCUMENT_RULES:
            findings.append(
                YamllintFinding(
                    kind="document_rule_disabled",
                    severity="low",
                    message=f"{normalized} disabled — document hygiene checks help catch malformed YAML",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[YamllintFinding],
        info: YamllintInfo,
        *,
        pending_rule: str | None,
    ) -> str | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return pending_rule

        extends_match = re.match(r"^\s*extends\s*:\s*(\S+)", line, re.IGNORECASE)
        if extends_match:
            info.extends = extends_match.group(1).lower()

        if EXTENDS_RELAXED_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="extends_relaxed",
                    severity="high",
                    message="extends=relaxed/disable weakens YAML linting — prefer default or explicit rules",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if line.lower().startswith("ignore:"):
            info.has_ignore = True

        if IGNORE_SENSITIVE_PATH_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="ignore_sensitive_path",
                    severity="high",
                    message="ignore skips CI/deployment YAML paths — lint infrastructure manifests",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if IGNORE_WILDCARD_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="ignore_wildcard",
                    severity="medium",
                    message="wildcard ignore pattern may hide YAML issues — scope ignores narrowly",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        max_length = _extract_line_length_max(line)
        if max_length is not None:
            info.line_length_max = max_length
            if max_length >= 200:
                findings.append(
                    YamllintFinding(
                        kind="line_length_high",
                        severity="medium",
                        message=f"line-length max={max_length} is very high — keep YAML readable and reviewable",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if COMMENTS_SPACES_LOW_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="comments_spaces_low",
                    severity="low",
                    message="comments min-spaces-from-content is very low — keep comment spacing readable",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if HARDCODED_SECRET_PATTERN.search(line) or AWS_ACCESS_KEY_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="hardcoded_secret",
                    severity="high",
                    message="hardcoded credential in yamllint config — use environment variables",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if INSECURE_HTTP_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="insecure_http",
                    severity="medium",
                    message="insecure HTTP URL in yamllint config — use HTTPS endpoints",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        if CURL_PIPE_SHELL_PATTERN.search(line):
            findings.append(
                YamllintFinding(
                    kind="curl_pipe_shell",
                    severity="high",
                    message="curl|wget piped to shell in yamllint config — avoid remote code execution",
                    path=rel,
                    lineno=lineno,
                    line=line,
                )
            )

        rule_disable = RULE_DISABLE_PATTERN.match(line)
        if rule_disable:
            self._record_rule_disable(
                rule_disable.group(1),
                lineno,
                rel,
                line,
                findings,
                info,
            )
            return None

        rule_object = RULE_DISABLE_OBJECT_PATTERN.match(line)
        if rule_object:
            return rule_object.group(1)

        if pending_rule and DISABLE_TRUE_PATTERN.search(line):
            self._record_rule_disable(
                pending_rule,
                lineno,
                rel,
                line,
                findings,
                info,
            )
            return None

        return pending_rule

    def _analyze_file(self, path: Path) -> tuple[list[YamllintFinding], YamllintInfo]:
        findings: list[YamllintFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, YamllintInfo(path=rel)

        info = YamllintInfo(path=rel, lines=len(raw_lines))
        pending_rule: str | None = None

        for lineno, line in enumerate(raw_lines, start=1):
            pending_rule = self._scan_line(
                line,
                lineno,
                rel,
                findings,
                info,
                pending_rule=pending_rule,
            )

        return findings, info

    def analyze(self) -> list[YamllintFinding]:
        """Scan yamllint configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[YamllintFinding] = []
        infos: list[YamllintInfo] = []
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
        self._stats = YamllintStats(
            config_files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> YamllintStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[YamllintInfo]:
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
        """Scaffold a hardened yamllint configuration template."""
        return """\
# Generated by DevAI YamllintAnalyzer
# yamllint — https://yamllint.readthedocs.io/
extends: default

rules:
  line-length:
    max: 120
    allow-non-breakable-inline-mappings: true
  truthy:
    allowed-values: ['true', 'false']
    check-keys: true
  key-duplicates: enable
  octal-values: enable
  quoted-strings: disable
  document-start: disable
  new-line-at-end-of-file: enable
  comments:
    min-spaces-from-content: 2

ignore: |
  .git/
  node_modules/
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.config_files == 0:
            return "yamllint configs: none found"
        return (
            f"yamllint configs: {stats.config_files} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "yamllint analysis:",
            f"  config files: {stats.config_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            extends = info.extends or "default"
            length = info.line_length_max if info.line_length_max is not None else "default"
            lines.append(f"  - {info.path}: extends={extends}, line_length_max={length}")
        for finding in self._findings or []:
            lines.append(f"  ! {finding.format()}")
        return "\n".join(lines)
