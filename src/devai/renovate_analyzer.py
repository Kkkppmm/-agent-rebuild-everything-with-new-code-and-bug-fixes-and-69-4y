"""RenovateAnalyzer — audit Renovate configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

RENOVATE_FILENAMES = ("renovate.json", "renovate.json5")
RENOVATE_DIRS = (".github", "")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|npmToken|npmAuthToken|credentials)\s*[:=]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|npm_[A-Za-z0-9]{20,}|pypi-)[^\"'\s]+[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|registryUrl|endpoint)\s*[:=]\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
AUTO_MERGE_TRUE_PATTERN = re.compile(
    r"^\s*[\"']?automerge[\"']?\s*:\s*true\s*,?\s*$",
    re.IGNORECASE,
)
PLATFORM_AUTO_MERGE_PATTERN = re.compile(
    r"^\s*[\"']?platformAutomerge[\"']?\s*:\s*true\s*,?\s*$",
    re.IGNORECASE,
)
VULNERABILITY_ALERTS_DISABLED_PATTERN = re.compile(
    r"^\s*[\"']?vulnerabilityAlerts[\"']?\s*:\s*\{[^}]*[\"']?enabled[\"']?\s*:\s*false",
    re.IGNORECASE,
)
VULNERABILITY_ALERTS_DISABLED_SIMPLE = re.compile(
    r"^\s*[\"']?vulnerabilityAlerts[\"']?\s*:\s*false\s*,?\s*$",
    re.IGNORECASE,
)
POST_UPGRADE_TASKS_PATTERN = re.compile(
    r"^\s*[\"']?postUpgradeTasks[\"']?\s*:\s*\{",
    re.IGNORECASE,
)
POST_UPGRADE_COMMAND_PATTERN = re.compile(
    r"^\s*[\"']?commands[\"']?\s*:\s*\[",
    re.IGNORECASE,
)
HOST_RULES_PATTERN = re.compile(r"^\s*[\"']?hostRules[\"']?\s*:\s*\[", re.IGNORECASE)
PACKAGE_RULES_PATTERN = re.compile(r"^\s*[\"']?packageRules[\"']?\s*:\s*\[", re.IGNORECASE)
GROUP_PATTERN = re.compile(r"^\s*[\"']?groupName[\"']?\s*:", re.IGNORECASE)
MANAGERS_PATTERN = re.compile(
    r"^\s*[\"']?enabledManagers[\"']?\s*:\s*\[([^\]]+)\]",
    re.IGNORECASE,
)
IGNORE_DEPS_PATTERN = re.compile(r"^\s*[\"']?ignoreDeps[\"']?\s*:\s*\[", re.IGNORECASE)
AGGRESSIVE_SCHEDULE_PATTERN = re.compile(
    r"^\s*[\"']?schedule[\"']?\s*:\s*\[[^\]]*(?:every day|every hour|at any time|before 6am every weekday)[^\]]*\]",
    re.IGNORECASE,
)
EXTENDS_PATTERN = re.compile(
    r"^\s*[\"']?extends[\"']?\s*:\s*\[[^\]]*[:/](?:all|default)[^\]]*\]",
    re.IGNORECASE,
)


@dataclass
class RenovateFinding:
    """A security or best-practice issue in a Renovate config."""

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
class RenovateInfo:
    """Parsed metadata about a Renovate config file."""

    path: str
    managers: list[str] = field(default_factory=list)
    has_host_rules: bool = False
    has_package_rules: bool = False
    has_groups: bool = False
    lines: int = 0


@dataclass
class RenovateStats:
    """Aggregate Renovate analysis statistics."""

    configs: int
    files: int
    findings: int
    managers: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_renovate_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower not in RENOVATE_FILENAMES:
        return False
    if path.parent == path.parents[0] or path.parent.name.lower() == ".github":
        return True
    return ".github" in {p.lower() for p in path.parts}


class RenovateAnalyzer:
    """Audit Renovate configs for hardcoded credentials, unsafe automerge, and weak defaults.

    Scans `renovate.json` / `renovate.json5` for host rule secrets, disabled vulnerability
    alerts, post-upgrade shell tasks, aggressive schedules, and missing update groups.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[RenovateFinding] | None = None
        self._stats: RenovateStats | None = None
        self._infos: list[RenovateInfo] | None = None

    def files(self) -> list[Path]:
        """Return Renovate config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_renovate_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[RenovateFinding], RenovateInfo]:
        findings: list[RenovateFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, RenovateInfo(path=rel)

        info = RenovateInfo(path=rel, lines=len(raw_lines))
        automerge_count = 0
        in_post_upgrade = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue

            if HOST_RULES_PATTERN.match(line):
                info.has_host_rules = True

            if PACKAGE_RULES_PATTERN.match(line):
                info.has_package_rules = True

            if GROUP_PATTERN.match(line):
                info.has_groups = True

            managers_match = MANAGERS_PATTERN.match(line)
            if managers_match:
                managers_raw = managers_match.group(1)
                for token in re.findall(r"\"([^\"]+)\"|'([^']+)'", managers_raw):
                    manager = token[0] or token[1]
                    if manager not in info.managers:
                        info.managers.append(manager)

            if POST_UPGRADE_TASKS_PATTERN.match(line):
                in_post_upgrade = True

            if in_post_upgrade and POST_UPGRADE_COMMAND_PATTERN.match(line):
                findings.append(
                    RenovateFinding(
                        kind="post_upgrade_commands",
                        severity="high",
                        message="postUpgradeTasks commands execute shell during updates — restrict and review carefully",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if line.startswith("}") or line.startswith("],"):
                in_post_upgrade = False

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    RenovateFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Renovate config — use platform secrets or hostRules env vars",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    RenovateFinding(
                        kind="insecure_http_registry",
                        severity="high",
                        message="cleartext HTTP registry URL — use HTTPS for private registries",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AUTO_MERGE_TRUE_PATTERN.match(line) or PLATFORM_AUTO_MERGE_PATTERN.match(line):
                automerge_count += 1
                findings.append(
                    RenovateFinding(
                        kind="automerge_enabled",
                        severity="medium",
                        message="automerge enabled — require CI checks and limit to patch/minor updates",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if (
                VULNERABILITY_ALERTS_DISABLED_PATTERN.search(line)
                or VULNERABILITY_ALERTS_DISABLED_SIMPLE.match(line)
            ):
                findings.append(
                    RenovateFinding(
                        kind="vulnerability_alerts_disabled",
                        severity="high",
                        message="vulnerabilityAlerts disabled — keep security alerts enabled",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AGGRESSIVE_SCHEDULE_PATTERN.search(line):
                findings.append(
                    RenovateFinding(
                        kind="aggressive_schedule",
                        severity="medium",
                        message="aggressive update schedule — prefer weekly windows to reduce PR noise",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if IGNORE_DEPS_PATTERN.match(line):
                findings.append(
                    RenovateFinding(
                        kind="ignore_deps",
                        severity="medium",
                        message="ignoreDeps configured — ensure security updates are not suppressed",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if EXTENDS_PATTERN.search(line):
                findings.append(
                    RenovateFinding(
                        kind="broad_extends",
                        severity="low",
                        message="broad extends preset — review inherited rules for automerge and ignore patterns",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if raw_lines and info.has_package_rules and not info.has_groups:
            findings.append(
                RenovateFinding(
                    kind="missing_groups",
                    severity="low",
                    message="packageRules without groupName — group related updates to reduce PR volume",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.has_host_rules and automerge_count > 0:
            findings.append(
                RenovateFinding(
                    kind="host_rules_with_automerge",
                    severity="medium",
                    message="hostRules with automerge — private registry updates should require manual review",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if raw_lines and not info.has_package_rules and not info.has_groups:
            findings.append(
                RenovateFinding(
                    kind="missing_package_rules",
                    severity="low",
                    message="no packageRules defined — add grouping and vulnerability alert handling",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[RenovateFinding]:
        """Scan Renovate config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[RenovateFinding] = []
        infos: list[RenovateInfo] = []
        paths = self.files()
        managers: set[str] = set()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)
            managers.update(info.managers)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = RenovateStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            managers=len(managers),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> RenovateStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[RenovateInfo]:
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Renovate config template."""
        return """\
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"]
  },
  "schedule": ["before 6am on monday"],
  "packageRules": [
    {
      "matchUpdateTypes": ["patch", "pin", "digest"],
      "automerge": true,
      "automergeType": "pr"
    },
    {
      "matchUpdateTypes": ["minor", "major"],
      "automerge": false
    },
    {
      "matchManagers": ["npm", "pip", "github-actions"],
      "groupName": "non-major dependencies",
      "groupSlug": "deps"
    }
  ],
  "hostRules": [
    {
      "matchHost": "registry.example.com",
      "hostType": "npm",
      "encrypted": {
        "token": "encrypted:REPLACE_WITH_RENOVATE_ENCRYPTED_TOKEN"
      }
    }
  ]
}
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Renovate: none found"
        return (
            f"Renovate: {stats.configs} file(s), {stats.managers} manager(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Renovate config analysis:",
            f"  configs: {stats.configs}",
            f"  managers: {stats.managers}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            managers = ", ".join(info.managers[:5]) or "none"
            lines.append(f"  - {info.path}: managers=[{managers}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
