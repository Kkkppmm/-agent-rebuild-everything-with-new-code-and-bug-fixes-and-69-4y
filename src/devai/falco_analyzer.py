"""FalcoAnalyzer — audit Falco runtime security rule files for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

FALCO_RULE_PATTERN = re.compile(r"^\s*-\s*rule\s*:", re.IGNORECASE)
FALCO_MACRO_PATTERN = re.compile(r"^\s*-\s*macro\s*:", re.IGNORECASE)
FALCO_LIST_PATTERN = re.compile(r"^\s*-\s*list\s*:", re.IGNORECASE)
FALCO_CRD_PATTERN = re.compile(
    r"^\s*apiVersion\s*:\s*falco\.org/",
    re.IGNORECASE | re.MULTILINE,
)
DISABLED_RULE_PATTERN = re.compile(r"^\s*enabled\s*:\s*false\s*$", re.IGNORECASE)
LOW_PRIORITY_PATTERN = re.compile(
    r"^\s*priority\s*:\s*(?:DEBUG|INFO|NOTICE)\s*$",
    re.IGNORECASE,
)
WILDCARD_CONDITION_PATTERN = re.compile(
    r"^\s*condition\s*:\s*(?:evt\.type\s*=\s*\*|true|1\s*=\s*1)\s*$",
    re.IGNORECASE,
)
BROAD_CONDITION_PATTERN = re.compile(
    r"condition\s*:\s*.*(?:evt\.type\s*=\s*\*|container\.id\s*!=\s*host)",
    re.IGNORECASE,
)
SUPPRESSION_PATTERN = re.compile(
    r"^\s*(?:suppress|exceptions)\s*:",
    re.IGNORECASE,
)
WILDCARD_SUPPRESS_PATTERN = re.compile(
    r"^\s*-\s*[\"']?\*[\"']?\s*(?:#.*)?$",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|auth)\s*[:=]\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#]+)",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|xox[baprs]-)[^\"'\s]*[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|endpoint|registry|api|server)\s*[:=]\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
DROP_OUTPUT_PATTERN = re.compile(
    r"^\s*output\s*:\s*(?:\"\"|''|none|null)\s*$",
    re.IGNORECASE,
)
SKIP_IF_EVIDENCE_PATTERN = re.compile(
    r"^\s*skip-if-evidence\s*:\s*true\s*$",
    re.IGNORECASE,
)
OVERRIDE_APPEND_FALSE_PATTERN = re.compile(
    r"^\s*append\s*:\s*false\s*$",
    re.IGNORECASE,
)
SOURCE_PATTERN = re.compile(
    r"^\s*source\s*:\s*(?:syscall|k8s_audit)\s*$",
    re.IGNORECASE,
)


@dataclass
class FalcoFinding:
    """A security or best-practice issue in a Falco rules file."""

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
class FalcoInfo:
    """Parsed metadata about a Falco rules file."""

    path: str
    rule_count: int = 0
    macro_count: int = 0
    list_count: int = 0
    disabled_rules: int = 0
    lines: int = 0


@dataclass
class FalcoStats:
    """Aggregate Falco analysis statistics."""

    rules_files: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_falco_file(path: Path) -> bool:
    if path.suffix.lower() not in (".yaml", ".yml"):
        return False
    name_lower = path.name.lower()
    if name_lower.startswith("falco") or "falco" in name_lower:
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if FALCO_CRD_PATTERN.search(text):
        return True
    return bool(
        FALCO_RULE_PATTERN.search(text)
        or FALCO_MACRO_PATTERN.search(text)
        or FALCO_LIST_PATTERN.search(text)
    )


class FalcoAnalyzer:
    """Audit Falco runtime security rules for disabled rules, broad conditions, and suppressions.

    Scans YAML rule files for ``- rule:`` entries, detecting enabled: false, wildcard conditions,
    broad exception/suppress blocks, low priorities on security rules, and hardcoded secrets.
    """

    def __init__(self, root: str = ".") -> None:
        self.root = Path(root)
        self._findings: list[FalcoFinding] | None = None
        self._stats: FalcoStats | None = None
        self._infos: list[FalcoInfo] | None = None

    def files(self) -> list[Path]:
        """Return Falco rules files found in the project."""
        paths: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_falco_file(path):
                paths.append(path)
        return paths

    def _analyze_file(self, path: Path) -> tuple[list[FalcoFinding], FalcoInfo]:
        findings: list[FalcoFinding] = []
        rel = str(path.relative_to(self.root))

        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, FalcoInfo(path=rel)

        info = FalcoInfo(path=rel, lines=len(raw_lines))
        in_rule_block = False
        in_suppress_block = False
        current_rule_has_output = False
        current_rule_has_tags = False
        current_rule_has_priority = False
        current_rule_disabled = False

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if FALCO_RULE_PATTERN.search(line):
                if in_rule_block and not current_rule_has_output and not current_rule_disabled:
                    findings.append(
                        FalcoFinding(
                            kind="missing_output",
                            severity="low",
                            message="Falco rule has no output message — alerts may be silent or hard to triage",
                            path=rel,
                            lineno=lineno - 1,
                            line="",
                        )
                    )
                in_rule_block = True
                in_suppress_block = False
                current_rule_has_output = False
                current_rule_has_tags = False
                current_rule_has_priority = False
                current_rule_disabled = False
                info.rule_count += 1
            elif FALCO_MACRO_PATTERN.search(line):
                info.macro_count += 1
                in_rule_block = False
            elif FALCO_LIST_PATTERN.search(line):
                info.list_count += 1
                in_rule_block = False
            elif re.match(r"^\s*-\s*\w", line) and not re.match(r"^\s*-\s*rule\s*:", line, re.IGNORECASE):
                if in_rule_block and re.match(r"^\s*-\s*rule\s*:", line, re.IGNORECASE) is None:
                    if re.match(r"^\s*-\s*(?:macro|list)\s*:", line, re.IGNORECASE):
                        in_rule_block = False

            if SUPPRESSION_PATTERN.search(line):
                in_suppress_block = True
            elif in_suppress_block and re.match(r"^\s*\w", line) and not re.match(r"^\s*-\s*", line):
                if not SUPPRESSION_PATTERN.search(line):
                    in_suppress_block = False

            if in_rule_block:
                if re.search(r"^\s*output\s*:", line, re.IGNORECASE):
                    current_rule_has_output = True
                    if DROP_OUTPUT_PATTERN.search(line):
                        findings.append(
                            FalcoFinding(
                                kind="empty_output",
                                severity="medium",
                                message="Falco rule output is empty — security events will not produce actionable alerts",
                                path=rel,
                                lineno=lineno,
                                line=line,
                            )
                        )
                if re.search(r"^\s*tags\s*:", line, re.IGNORECASE):
                    current_rule_has_tags = True
                if re.search(r"^\s*priority\s*:", line, re.IGNORECASE):
                    current_rule_has_priority = True

            if DISABLED_RULE_PATTERN.search(line):
                if in_rule_block:
                    current_rule_disabled = True
                    info.disabled_rules += 1
                findings.append(
                    FalcoFinding(
                        kind="disabled_rule",
                        severity="high",
                        message="enabled: false disables Falco detection — remove or scope exceptions instead of disabling rules",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_rule_block and LOW_PRIORITY_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="low_priority",
                        severity="medium",
                        message="low priority (DEBUG/INFO/NOTICE) on security rule — raise to WARNING or higher for runtime threats",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if WILDCARD_CONDITION_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="wildcard_condition",
                        severity="high",
                        message="wildcard condition matches all events — tighten evt.type and container filters to reduce noise and blind spots",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )
            elif in_rule_block and BROAD_CONDITION_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="broad_condition",
                        severity="medium",
                        message="overly broad condition may miss host-level threats or generate excessive alerts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if in_suppress_block and WILDCARD_SUPPRESS_PATTERN.match(stripped):
                findings.append(
                    FalcoFinding(
                        kind="wildcard_suppress",
                        severity="high",
                        message="wildcard suppress/exception disables Falco detection broadly — scope exceptions to specific containers or users",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_IF_EVIDENCE_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="skip_if_evidence",
                        severity="medium",
                        message="skip-if-evidence: true may suppress correlated detections — verify exceptions are intentional",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if OVERRIDE_APPEND_FALSE_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="append_false",
                        severity="low",
                        message="append: false overrides built-in Falco rules — ensure custom rules fully replace default coverage",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Falco rules — use environment variables or Kubernetes Secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="hardcoded_token",
                        severity="high",
                        message="hardcoded token in Falco rules — use Secret references instead",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    FalcoFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="cleartext HTTP endpoint in Falco config — use HTTPS for remote outputs and registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if in_rule_block and not current_rule_has_output and not current_rule_disabled:
            findings.append(
                FalcoFinding(
                    kind="missing_output",
                    severity="low",
                    message="Falco rule has no output message — alerts may be silent or hard to triage",
                    path=rel,
                    lineno=len(raw_lines),
                    line=raw_lines[-1] if raw_lines else "",
                )
            )

        if info.rule_count == 0 and info.macro_count == 0 and info.list_count == 0:
            findings.append(
                FalcoFinding(
                    kind="empty_rules_file",
                    severity="low",
                    message="Falco rules file contains no rules, macros, or lists",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0] if raw_lines else "",
                )
            )

        return findings, info

    def analyze(self) -> list[FalcoFinding]:
        """Scan Falco rules files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[FalcoFinding] = []
        infos: list[FalcoInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = FalcoStats(
            rules_files=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> FalcoStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[FalcoInfo]:
        """Return parsed rules file metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no rules files)."""
        self.analyze()
        stats = self.stats
        if stats.rules_files == 0:
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
        """Scaffold a hardened Falco rule template."""
        return """\
- rule: Detect shell in container
  desc: Detect an attempt to spawn a shell inside a container
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_shell_activity
  output: >
    Shell spawned in container (user=%user.name container=%container.name
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
  source: syscall
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.rules_files == 0:
            return "Falco: none found"
        return (
            f"Falco: {stats.rules_files} rules file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Falco rules analysis:",
            f"  rules files: {stats.rules_files}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: rules={info.rule_count}, macros={info.macro_count}, "
                f"lists={info.list_count}, disabled={info.disabled_rules}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
