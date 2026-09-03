"""TravisCIAnalyzer — audit Travis CI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TRAVIS_FILENAMES = (".travis.yml", ".travis.yaml")
TRAVIS_DIRS = (".travis",)

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(r"\bsudo\b", re.IGNORECASE)
LATEST_TAG_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
API_KEY_DEPLOY_PATTERN = re.compile(
    r"^\s*api_key\s*:\s*[\"'][^\"'{}\s]",
    re.IGNORECASE,
)
PRIVILEGED_DOCKER_PATTERN = re.compile(
    r"privileged\s*:\s*true",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?\s*TRAVIS_(?:PULL_REQUEST|COMMIT|BRANCH|REPO_SLUG|BUILD_DIR)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
ALLOW_FAILURE_PATTERN = re.compile(
    r"^\s*allow_failures\s*:\s*true\s*$",
    re.IGNORECASE,
)
SKIP_CLEANUP_PATTERN = re.compile(
    r"^\s*skip_cleanup\s*:\s*true\s*$",
    re.IGNORECASE,
)
LANGUAGE_LINE_PATTERN = re.compile(r"^\s*language\s*:\s*(\S+)\s*$", re.IGNORECASE)
VERSION_KEY_PATTERN = re.compile(
    r"^\s*(python|ruby|node_js|php|go|java|scala|perl|rust)\s*:",
    re.IGNORECASE,
)
SECURITY_JOB_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)


@dataclass
class TravisCIFinding:
    """A security or best-practice issue in a Travis CI config."""

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
class TravisCIInfo:
    """Parsed metadata about a Travis CI config."""

    path: str
    language: str = ""
    jobs: int = 0
    has_matrix: bool = False
    lines: int = 0


@dataclass
class TravisCIStats:
    """Aggregate Travis CI analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_travis_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in TRAVIS_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(TRAVIS_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    return False


class TravisCIAnalyzer:
    """Audit Travis CI configs for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans for plaintext secrets, curl-pipe-to-shell, sudo usage, unpinned language
    versions, cleartext deploy api_key, privileged Docker, script injection via
    Travis env vars, and insecure HTTP URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TravisCIFinding] | None = None
        self._stats: TravisCIStats | None = None
        self._infos: list[TravisCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Travis CI config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_travis_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TravisCIFinding], TravisCIInfo]:
        findings: list[TravisCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, TravisCIInfo(path=rel)

        info = TravisCIInfo(path=rel, lines=len(raw_lines))
        language_set = False
        version_key_seen = False
        in_security_job = False
        job_count = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue

            lang_match = LANGUAGE_LINE_PATTERN.match(raw)
            if lang_match:
                info.language = lang_match.group(1)
                language_set = True

            if VERSION_KEY_PATTERN.match(raw):
                version_key_seen = True

            if re.match(r"^\s*-\s*name\s*:", raw, re.IGNORECASE):
                job_count += 1
                in_security_job = bool(SECURITY_JOB_PATTERN.search(raw))
            elif re.match(r"^\s*jobs\s*:", raw, re.IGNORECASE):
                info.has_matrix = True

            if HARDCODED_SECRET_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret in Travis CI config — use encrypted env vars",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if API_KEY_DEPLOY_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="api_key_deploy",
                        severity="high",
                        message="Cleartext deploy api_key — use Travis encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SUDO_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="sudo_usage",
                        severity="medium",
                        message="sudo in Travis CI — prefer container-based builds without root",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_DOCKER_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="privileged_docker",
                        severity="high",
                        message="Privileged Docker service enabled — avoid unless strictly required",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="Docker image uses :latest tag — pin to a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="Travis env var interpolated in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="Insecure HTTP URL — use HTTPS for remote resources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_FAILURE_PATTERN.search(raw) and in_security_job:
                findings.append(
                    TravisCIFinding(
                        kind="allow_failure_security",
                        severity="medium",
                        message="Security job allows failure — enforce security checks on every build",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_CLEANUP_PATTERN.search(raw):
                findings.append(
                    TravisCIFinding(
                        kind="skip_cleanup",
                        severity="low",
                        message="skip_cleanup is deprecated — remove and use explicit artifact handling",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        info.jobs = job_count

        if language_set and not version_key_seen and info.language in {
            "python",
            "ruby",
            "node_js",
            "php",
            "go",
            "java",
            "scala",
            "perl",
            "rust",
        }:
            findings.append(
                TravisCIFinding(
                    kind="unpinned_language",
                    severity="medium",
                    message=f"Language '{info.language}' has no pinned version — pin runtime versions",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[TravisCIFinding]:
        """Scan Travis CI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TravisCIFinding] = []
        infos: list[TravisCIInfo] = []
        paths = self.files()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = TravisCIStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TravisCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TravisCIInfo]:
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
        """Scaffold a hardened Travis CI template."""
        return """\
# Generated by DevAI TravisCIAnalyzer
language: python
python:
  - "3.12"

cache: pip

install:
  - pip install -e ".[dev]"

script:
  - python -m pytest

jobs:
  include:
    - name: Security scan
      script:
        - pip install devai
        - devai security-scan .
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Travis CI: none found"
        return (
            f"Travis CI: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Travis CI analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: language={info.language or 'unknown'}, "
                f"jobs={info.jobs}, matrix={info.has_matrix}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
