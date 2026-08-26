"""CloudBuildAnalyzer — audit Google Cloud Build configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

CLOUD_BUILD_FILENAMES = (
    "cloudbuild.yaml",
    "cloudbuild.yml",
    "cloudbuild.json",
)
CLOUD_BUILD_DIRS = ("cloudbuild", "ci/cloudbuild", ".cloudbuild")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_ENV_VALUE_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*\n"
    r"\s*value\s*:\s*[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SUBSTITUTION_PATTERN = re.compile(
    r"^\s*_[A-Z0-9_]+\s*:\s*[\"'][^\"'{}\s][^\"']+[\"']",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|name|gcr\.io|pkg\.dev)[^\n]*:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:--privileged|privileged\s*:\s*true)",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"\$\{?(?:_?[A-Z][A-Z0-9_]*|BRANCH_NAME|TAG_NAME|COMMIT_SHA|SHORT_SHA|"
    r"REVISION_ID|REPO_NAME|BUILD_ID|PROJECT_ID)\}?",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SENSITIVE_VOLUME_PATTERN = re.compile(
    r"(?:/etc/passwd|/etc/shadow|/root|/home/[^/\s]+/\.ssh)",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep)",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:--user\s+root|user:\s*root|runAsUser:\s*0)\b",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
ALLOW_FAILURE_PATTERN = re.compile(
    r"^\s*allowFailure\s*:\s*true\s*$",
    re.IGNORECASE,
)
SERVICE_ACCOUNT_KEY_PATTERN = re.compile(
    r"(?:service[_-]?account[_-]?key|credentials\.json|gcloud\s+auth\s+activate-service-account)",
    re.IGNORECASE,
)
DEFAULT_SERVICE_ACCOUNT_PATTERN = re.compile(
    r"^\s*serviceAccount\s*:\s*projects/\$\{?PROJECT_ID\}?/serviceAccounts/\$\{?PROJECT_NUMBER\}?@cloudbuild\.gserviceaccount\.com\s*$",
    re.IGNORECASE,
)
UNPINNED_IMAGE_PATTERN = re.compile(
    r"^\s*(?:name|image)\s*:\s*[\"']?(?:ubuntu|node|python|golang|alpine)[\"']?\s*$",
    re.IGNORECASE,
)
SKIP_SECURITY_PATTERN = re.compile(
    r"^\s*allowFailure\s*:\s*true\s*$",
    re.IGNORECASE,
)


@dataclass
class CloudBuildFinding:
    """A security or best-practice issue in a Google Cloud Build pipeline."""

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
class CloudBuildInfo:
    """Parsed metadata about a Cloud Build config file."""

    path: str
    steps: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class CloudBuildStats:
    """Aggregate Cloud Build analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_cloud_build_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in CLOUD_BUILD_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(CLOUD_BUILD_DIRS):
        if lower.endswith((".yml", ".yaml", ".json")):
            return True
    if lower.endswith(".cloudbuild.yaml") or lower.endswith(".cloudbuild.yml"):
        return True
    return False


class CloudBuildAnalyzer:
    """Audit Google Cloud Build pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans ``cloudbuild.yaml`` for curl-pipe-to-shell, substitution injection,
  ``allowFailure`` on security steps, and secrets in env/substitution blocks.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[CloudBuildFinding] | None = None
        self._stats: CloudBuildStats | None = None
        self._infos: list[CloudBuildInfo] | None = None

    def files(self) -> list[Path]:
        """Return Cloud Build config files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_cloud_build_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[CloudBuildFinding], CloudBuildInfo]:
        findings: list[CloudBuildFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            raw_lines = content.splitlines()
        except OSError:
            return findings, CloudBuildInfo(path=rel)

        info = CloudBuildInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        current_step = ""

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            step_match = re.match(r"^\s*-\s*name\s*:\s*(.+)$", raw)
            if step_match and "steps:" in content:
                current_step = step_match.group(1).strip().strip("\"'")
                info.steps.append(current_step)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(current_step))

            id_match = re.match(r"^\s*-\s*id\s*:\s*(.+)$", raw)
            if id_match and "steps:" in content:
                current_step = id_match.group(1).strip().strip("\"'")
                info.steps.append(current_step)
                in_security_step = bool(SECURITY_STEP_PATTERN.search(current_step))

            image_match = re.match(r"^\s*-\s*[\"']?([^\s\"']+)[\"']?\s*$", raw)
            if image_match and "images:" in "\n".join(raw_lines[max(0, lineno - 5):lineno]):
                info.images.append(image_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_SUBSTITUTION_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Secret Manager with secretEnv or availableSecrets",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if re.match(r"^\s*-\s*name\s*:\s*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD)", raw, re.I):
                value_line = raw_lines[lineno] if lineno < len(raw_lines) else ""
                if re.search(r"value\s*:\s*[\"'][^\"'{}\s]", value_line, re.I):
                    findings.append(
                        CloudBuildFinding(
                            kind="hardcoded_env",
                            severity="high",
                            message="hardcoded env value — use secretEnv with Secret Manager",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )

            if PLAIN_SECRET_VALUE_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="plain_secret_value",
                        severity="high",
                        message="sensitive-looking value in config — store in Secret Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — verify script source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a specific digest or version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if DOCKER_SOCKET_MOUNT_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line) and (
                "script:" in line
                or "args:" in line
                or "entrypoint:" in line
                or "bash" in line.lower()
                or "sh " in line.lower()
            ):
                findings.append(
                    CloudBuildFinding(
                        kind="script_injection",
                        severity="medium",
                        message="substitution variable in script — validate untrusted branch/tag inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SENSITIVE_VOLUME_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="sensitive_volume",
                        severity="high",
                        message="sensitive host path referenced — avoid mounting credentials or SSH keys",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="root_user",
                        severity="medium",
                        message="step runs as root — use a non-root user when possible",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SERVICE_ACCOUNT_KEY_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="service_account_key",
                        severity="high",
                        message="service account key in build — use Workload Identity or Secret Manager",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if UNPINNED_IMAGE_PATTERN.search(line):
                findings.append(
                    CloudBuildFinding(
                        kind="unpinned_image",
                        severity="low",
                        message="builder image not version-pinned — pin to a specific tag or digest",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_FAILURE_PATTERN.search(line) and in_security_step:
                findings.append(
                    CloudBuildFinding(
                        kind="security_step_allow_failure",
                        severity="medium",
                        message="security step allows failure — failing scans should block builds",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SKIP_SECURITY_PATTERN.search(line) and in_security_step:
                findings.append(
                    CloudBuildFinding(
                        kind="security_step_disabled",
                        severity="medium",
                        message="security build step allows failure — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if not any(f.kind == "default_service_account" for f in findings):
            for lineno, raw in enumerate(raw_lines, start=1):
                if re.match(
                    r"^\s*serviceAccount\s*:\s*projects/\$\{?PROJECT_ID\}?/serviceAccounts/\$\{?PROJECT_NUMBER\}?@cloudbuild\.gserviceaccount\.com\s*$",
                    raw,
                    re.I,
                ):
                    findings.append(
                        CloudBuildFinding(
                            kind="default_service_account",
                            severity="medium",
                            message="using default Cloud Build SA — create a dedicated service account with least privilege",
                            path=rel,
                            lineno=lineno,
                            line=raw.strip(),
                        )
                    )
                    break

        return findings, info

    def analyze(self) -> list[CloudBuildFinding]:
        """Scan Cloud Build configs and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[CloudBuildFinding] = []
        infos: list[CloudBuildInfo] = []
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
        self._stats = CloudBuildStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> CloudBuildStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[CloudBuildInfo]:
        """Return parsed config metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no pipelines)."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
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
        """Scaffold a hardened Google Cloud Build pipeline template."""
        return """\
# Generated by DevAI CloudBuildAnalyzer
steps:
  - id: test
    name: python:3.12-slim
    entrypoint: bash
    args:
      - -c
      - |
        pip install -e ".[dev]"
        python -m pytest
    secretEnv:
      - PYPI_TOKEN

  - id: security-scan
    name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    args:
      - -c
      - devai security-scan .
    waitFor:
      - test

availableSecrets:
  secretManager:
    - versionName: projects/$PROJECT_ID/secrets/pypi-token/versions/latest
      env: PYPI_TOKEN

options:
  logging: CLOUD_LOGGING_ONLY
  machineType: E2_HIGHCPU_8

serviceAccount: projects/$PROJECT_ID/serviceAccounts/cloud-build@$PROJECT_ID.iam.gserviceaccount.com

images:
  - gcr.io/$PROJECT_ID/app:$SHORT_SHA
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Cloud Build: none found"
        return (
            f"Cloud Build: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Google Cloud Build pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            steps = ", ".join(info.steps[:5]) or "none"
            lines.append(f"  - {info.path}: {len(info.steps)} step(s), steps=[{steps}]")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
