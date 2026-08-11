"""DependabotAnalyzer — audit Dependabot configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

DEPENDABOT_FILENAMES = ("dependabot.yml", "dependabot.yaml")
DEPENDABOT_DIRS = (".github",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_TOKEN_PATTERN = re.compile(
    r"[\"']?(?:ghp_|glpat-|AKIA|npm_[A-Za-z0-9]{20,}|pypi-)[^\"'\s]+[\"']?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"url\s*:\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
INSECURE_EXTERNAL_CODE_PATTERN = re.compile(
    r"^\s*insecure-external-code-execution\s*:\s*allow\s*$",
    re.IGNORECASE,
)
DAILY_SCHEDULE_PATTERN = re.compile(
    r"^\s*interval\s*:\s*[\"']?daily[\"']?\s*$",
    re.IGNORECASE,
)
HIGH_PR_LIMIT_PATTERN = re.compile(
    r"^\s*open-pull-requests-limit\s*:\s*(?:[1-9]\d{1,}|\d{3,})\s*$",
    re.IGNORECASE,
)
MISSING_VERSION_PATTERN = re.compile(r"^\s*version\s*:\s*2\s*$", re.IGNORECASE)
ECOSYSTEM_PATTERN = re.compile(
    r"^\s*package-ecosystem\s*:\s*[\"']?([^\"'\n]+)[\"']?\s*$",
    re.IGNORECASE,
)
GROUPS_PATTERN = re.compile(r"^\s*groups\s*:", re.IGNORECASE)
REVIEWERS_PATTERN = re.compile(r"^\s*(?:reviewers|assignees)\s*:", re.IGNORECASE)
REGISTRY_BLOCK_PATTERN = re.compile(r"^\s*registries\s*:", re.IGNORECASE)


@dataclass
class DependabotFinding:
    """A security or best-practice issue in a Dependabot config."""

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
class DependabotInfo:
    """Parsed metadata about a Dependabot config file."""

    path: str
    ecosystems: list[str] = field(default_factory=list)
    has_groups: bool = False
    has_reviewers: bool = False
    has_registries: bool = False
    lines: int = 0


@dataclass
class DependabotStats:
    """Aggregate Dependabot analysis statistics."""

    configs: int
    files: int
    findings: int
    ecosystems: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_dependabot_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in DEPENDABOT_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    return bool(parts & set(DEPENDABOT_DIRS)) and lower in DEPENDABOT_FILENAMES


class DependabotAnalyzer:
    """Audit Dependabot configs for hardcoded credentials, unsafe settings, and weak defaults.

    Scans `.github/dependabot.yml` for registry secrets, insecure external code execution,
    daily update floods, missing security groups, and cleartext registry URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[DependabotFinding] | None = None
        self._stats: DependabotStats | None = None
        self._infos: list[DependabotInfo] | None = None

    def files(self) -> list[Path]:
        """Return Dependabot config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_dependabot_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[DependabotFinding], DependabotInfo]:
        findings: list[DependabotFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, DependabotInfo(path=rel)

        info = DependabotInfo(path=rel, lines=len(raw_lines))
        has_version = False
        in_updates_block = False
        update_blocks = 0
        blocks_with_daily = 0
        blocks_without_groups = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if MISSING_VERSION_PATTERN.match(line):
                has_version = True

            if REGISTRY_BLOCK_PATTERN.match(line):
                info.has_registries = True

            if GROUPS_PATTERN.match(line):
                info.has_groups = True

            if REVIEWERS_PATTERN.match(line):
                info.has_reviewers = True

            ecosystem_match = ECOSYSTEM_PATTERN.match(line)
            if ecosystem_match:
                ecosystem = ecosystem_match.group(1).strip().strip("\"'")
                if ecosystem not in info.ecosystems:
                    info.ecosystems.append(ecosystem)
                in_updates_block = True
                update_blocks += 1

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_TOKEN_PATTERN.search(line):
                findings.append(
                    DependabotFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential in Dependabot config — use GitHub secrets or Dependabot secrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    DependabotFinding(
                        kind="insecure_http_registry",
                        severity="high",
                        message="cleartext HTTP registry URL — use HTTPS for private registries",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_EXTERNAL_CODE_PATTERN.match(line):
                findings.append(
                    DependabotFinding(
                        kind="insecure_external_code",
                        severity="high",
                        message="insecure-external-code-execution: allow — restrict external code execution in updates",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DAILY_SCHEDULE_PATTERN.match(line) and in_updates_block:
                blocks_with_daily += 1
                findings.append(
                    DependabotFinding(
                        kind="daily_schedule",
                        severity="medium",
                        message="daily update schedule — prefer weekly to reduce PR noise and review fatigue",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HIGH_PR_LIMIT_PATTERN.match(line):
                findings.append(
                    DependabotFinding(
                        kind="high_pr_limit",
                        severity="medium",
                        message="high open-pull-requests-limit — cap PR volume for easier review",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if raw_lines and not has_version:
            findings.append(
                DependabotFinding(
                    kind="missing_version",
                    severity="low",
                    message="missing version: 2 — add explicit Dependabot config version",
                    path=rel,
                    lineno=1,
                    line=raw_lines[0].strip(),
                )
            )

        if update_blocks > 0 and not info.has_groups:
            blocks_without_groups = update_blocks
            findings.append(
                DependabotFinding(
                    kind="missing_groups",
                    severity="low",
                    message="no update groups defined — group security updates to reduce PR noise",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if update_blocks > 0 and not info.has_reviewers:
            findings.append(
                DependabotFinding(
                    kind="missing_reviewers",
                    severity="low",
                    message="no reviewers or assignees configured — route dependency PRs for review",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if blocks_with_daily > 1:
            findings.append(
                DependabotFinding(
                    kind="daily_schedule_all",
                    severity="medium",
                    message="multiple ecosystems on daily schedule — stagger or use weekly intervals",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.has_registries and not info.has_reviewers:
            findings.append(
                DependabotFinding(
                    kind="private_registry_no_reviewers",
                    severity="medium",
                    message="private registry configured without reviewers — require review for registry updates",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[DependabotFinding]:
        """Scan Dependabot config files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[DependabotFinding] = []
        infos: list[DependabotInfo] = []
        paths = self.files()
        ecosystems: set[str] = set()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)
            ecosystems.update(info.ecosystems)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = DependabotStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            ecosystems=len(ecosystems),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> DependabotStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[DependabotInfo]:
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
        """Scaffold a hardened Dependabot config template."""
        return """\
# Generated by DevAI DependabotAnalyzer
version: 2
registries:
  npm-private:
    type: npm-registry
    url: https://registry.example.com
    # Use Dependabot secrets — never hardcode credentials here
    # token: ${{ secrets.DEPENDABOT_NPM_TOKEN }}

updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    groups:
      security-updates:
        applies-to: security-updates
        patterns:
          - "*"
    reviewers:
      - "security-team"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    groups:
      github-actions:
        patterns:
          - "*"
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Dependabot: none found"
        return (
            f"Dependabot: {stats.configs} file(s), {stats.ecosystems} ecosystem(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Dependabot config analysis:",
            f"  configs: {stats.configs}",
            f"  ecosystems: {stats.ecosystems}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            ecosystems = ", ".join(info.ecosystems[:5]) or "none"
            lines.append(f"  - {info.path}: ecosystems=[{ecosystems}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
