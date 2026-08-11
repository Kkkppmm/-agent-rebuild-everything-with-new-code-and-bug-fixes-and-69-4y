"""AppVeyorCIAnalyzer — audit AppVeyor CI configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

APPVEYOR_FILENAMES = ("appveyor.yml", "appveyor.yaml", ".appveyor.yml", ".appveyor.yaml")
APPVEYOR_DIRS = (".appveyor", "ci/appveyor")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget|Invoke-WebRequest)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"(?:\$\{?\s*APPVEYOR_(?:PULL_REQUEST_TITLE|PULL_REQUEST_NUMBER|REPO_NAME|BUILD_VERSION|COMMIT_MESSAGE|JOB_NAME)"
    r"|%APPVEYOR_(?:PULL_REQUEST_TITLE|PULL_REQUEST_NUMBER|REPO_NAME|BUILD_VERSION|COMMIT_MESSAGE|JOB_NAME)%)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(r":latest\b", re.IGNORECASE)
API_KEY_DEPLOY_PATTERN = re.compile(
    r"^\s*api_key\s*:\s*[\"'][^\"'{}\s]",
    re.IGNORECASE,
)
RDP_ENABLED_PATTERN = re.compile(
    r"^\s*enable_rdp\s*:\s*true\s*$",
    re.IGNORECASE,
)
SKIP_TAGS_PATTERN = re.compile(
    r"^\s*skip_tags\s*:\s*true\s*$",
    re.IGNORECASE,
)
PUBLISH_WAN_PATTERN = re.compile(
    r"^\s*publish_wan_artifacts\s*:\s*true\s*$",
    re.IGNORECASE,
)
VERSION_LINE_PATTERN = re.compile(r"^\s*version\s*:\s*(\S+)\s*$", re.IGNORECASE)
STACK_LINE_PATTERN = re.compile(r"^\s*stack\s*:\s*(\S+)\s*$", re.IGNORECASE)
IMAGE_LINE_PATTERN = re.compile(r"^\s*image\s*:\s*(\S+)\s*$", re.IGNORECASE)
SECURITY_JOB_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
MATRIX_JOB_PATTERN = re.compile(r"^\s*-\s*job_name\s*:", re.IGNORECASE)


@dataclass
class AppVeyorCIFinding:
    """A security or best-practice issue in an AppVeyor CI config."""

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
class AppVeyorCIInfo:
    """Parsed metadata about an AppVeyor CI config."""

    path: str
    stack: str = ""
    image: str = ""
    version: str = ""
    jobs: int = 0
    lines: int = 0


@dataclass
class AppVeyorCIStats:
    """Aggregate AppVeyor CI analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_appveyor_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in APPVEYOR_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(APPVEYOR_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    return False


class AppVeyorCIAnalyzer:
    """Audit AppVeyor CI configs for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans for plaintext secrets, curl-pipe-to-shell, cleartext deploy api_key,
    RDP exposure, APPVEYOR_* variable injection, unpinned stack versions, and
    insecure HTTP URLs.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[AppVeyorCIFinding] | None = None
        self._stats: AppVeyorCIStats | None = None
        self._infos: list[AppVeyorCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return AppVeyor CI config paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_appveyor_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[AppVeyorCIFinding], AppVeyorCIInfo]:
        findings: list[AppVeyorCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, AppVeyorCIInfo(path=rel)

        info = AppVeyorCIInfo(path=rel, lines=len(raw_lines))
        in_security_job = False
        job_count = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue

            stack_match = STACK_LINE_PATTERN.match(raw)
            if stack_match:
                info.stack = stack_match.group(1)

            image_match = IMAGE_LINE_PATTERN.match(raw)
            if image_match:
                info.image = image_match.group(1)

            version_match = VERSION_LINE_PATTERN.match(raw)
            if version_match:
                info.version = version_match.group(1)

            if MATRIX_JOB_PATTERN.match(raw):
                job_count += 1
                in_security_job = False
            elif re.match(r"^\s*-\s*name\s*:", raw, re.IGNORECASE):
                job_count += 1
                in_security_job = bool(SECURITY_JOB_PATTERN.search(raw))

            if HARDCODED_SECRET_PATTERN.search(raw):
                findings.append(
                    AppVeyorCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="Hardcoded secret in AppVeyor config — use encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(raw):
                findings.append(
                    AppVeyorCIFinding(
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
                    AppVeyorCIFinding(
                        kind="api_key_deploy",
                        severity="high",
                        message="Cleartext deploy api_key — use AppVeyor encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RDP_ENABLED_PATTERN.search(raw):
                findings.append(
                    AppVeyorCIFinding(
                        kind="rdp_enabled",
                        severity="high",
                        message="RDP enabled on build worker — disable unless debugging interactively",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(raw):
                findings.append(
                    AppVeyorCIFinding(
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
                    AppVeyorCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="AppVeyor env var interpolated in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(raw):
                findings.append(
                    AppVeyorCIFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="Insecure HTTP URL — use HTTPS for remote resources",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PUBLISH_WAN_PATTERN.search(raw):
                findings.append(
                    AppVeyorCIFinding(
                        kind="publish_wan",
                        severity="medium",
                        message="publish_wan_artifacts exposes artifacts publicly — restrict access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_TAGS_PATTERN.search(raw) and in_security_job:
                findings.append(
                    AppVeyorCIFinding(
                        kind="skip_tags_security",
                        severity="medium",
                        message="Security job uses skip_tags — ensure security checks run on tagged releases",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        info.jobs = job_count

        if info.version.lower() in {"latest", "stable", "current"}:
            findings.append(
                AppVeyorCIFinding(
                    kind="unpinned_version",
                    severity="medium",
                    message=f"Unpinned version '{info.version}' — pin to a specific release",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[AppVeyorCIFinding]:
        """Scan AppVeyor CI configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[AppVeyorCIFinding] = []
        infos: list[AppVeyorCIInfo] = []
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
        self._stats = AppVeyorCIStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> AppVeyorCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[AppVeyorCIInfo]:
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
        """Scaffold a hardened AppVeyor CI template."""
        return """\
# Generated by DevAI AppVeyorCIAnalyzer
version: 1.0.{build}
image: Visual Studio 2022

environment:
  matrix:
    - PYTHON: "C:\\Python312"
      PYTHON_VERSION: "3.12"

install:
  - "%PYTHON%\\python.exe -m pip install --upgrade pip"
  - "%PYTHON%\\python.exe -m pip install -e .[dev]"

build_script:
  - "%PYTHON%\\python.exe -m pytest"

deploy: off
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "AppVeyor CI: none found"
        return (
            f"AppVeyor CI: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "AppVeyor CI analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: stack={info.stack or 'unknown'}, "
                f"image={info.image or 'unknown'}, version={info.version or 'unknown'}, jobs={info.jobs}"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
