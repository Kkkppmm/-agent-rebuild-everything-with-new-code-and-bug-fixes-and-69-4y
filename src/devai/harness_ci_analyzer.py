"""HarnessCIAnalyzer — audit Harness CI pipeline configs for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

HARNESS_FILENAMES = ("harness.yaml", "harness.yml")
HARNESS_DIRS = (".harness", "harness", "ci/harness", ".harness/ci")

HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key)\s*:\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_VALUE_PATTERN = re.compile(
    r"^\s*value\s*:\s*[\"'](?:sk-|ghp_|glpat-|AKIA|xox[baprs]-)[^\"']+[\"']",
    re.IGNORECASE,
)
PLAINTEXT_SECRET_TYPE_PATTERN = re.compile(
    r"^\s*-\s*name\s*:\s*[^\n]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY)",
    re.IGNORECASE,
)
STRING_SECRET_TYPE_PATTERN = re.compile(
    r"^\s*type\s*:\s*String\s*$",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|connectorRef)\s*:\s*[^\s:]+:latest\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_MOUNT_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"^\s*privileged\s*:\s*true\s*$",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"^\s*hostNetwork\s*:\s*true\s*$",
    re.IGNORECASE,
)
RUN_AS_ROOT_PATTERN = re.compile(
    r"^\s*runAsUser\s*:\s*0\s*$",
    re.IGNORECASE,
)
ALLOW_PRIV_ESCALATION_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation\s*:\s*true\s*$",
    re.IGNORECASE,
)
AUTOMOUNT_SA_TOKEN_PATTERN = re.compile(
    r"^\s*automountServiceAccountToken\s*:\s*true\s*$",
    re.IGNORECASE,
)
SCRIPT_INJECTION_PATTERN = re.compile(
    r"<\+(?:trigger\.payload[^>]*|codebase\.pullRequest[^>]*|pipeline\.variables\.[^>]+)>",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
SECURITY_STEP_PATTERN = re.compile(
    r"(security|audit|snyk|bandit|safety|trivy|semgrep|gitleaks)",
    re.IGNORECASE,
)
HARNESS_PIPELINE_PATTERN = re.compile(
    r"^\s*pipeline\s*:",
    re.IGNORECASE,
)
STEP_NAME_PATTERN = re.compile(
    r"^\s*name\s*:\s*[\"']?([^\"'\n]+)",
    re.IGNORECASE,
)


@dataclass
class HarnessCIFinding:
    """A security or best-practice issue in a Harness CI pipeline."""

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
class HarnessCIInfo:
    """Parsed metadata about a Harness CI pipeline file."""

    path: str
    stages: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class HarnessCIStats:
    """Aggregate Harness CI analysis statistics."""

    pipelines: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _looks_like_harness_pipeline(content: str) -> bool:
    return bool(HARNESS_PIPELINE_PATTERN.search(content)) and (
        "identifier:" in content.lower() or "stages:" in content.lower()
    )


def _is_harness_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in HARNESS_FILENAMES:
        return True
    if lower.endswith(".harness.yaml") or lower.endswith(".harness.yml"):
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(HARNESS_DIRS) and lower.endswith((".yml", ".yaml")):
        return True
    return False


class HarnessCIAnalyzer:
    """Audit Harness CI pipelines for hardcoded secrets, unsafe scripts, and weak defaults.

    Scans `.harness/` pipeline YAML for curl-pipe-to-shell, privileged containers,
    plaintext secrets, Harness expression injection, and missing security gates.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[HarnessCIFinding] | None = None
        self._stats: HarnessCIStats | None = None
        self._infos: list[HarnessCIInfo] | None = None

    def files(self) -> list[Path]:
        """Return Harness CI pipeline files found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_harness_file(path):
                found.append(path)
                continue
            if path.suffix.lower() in (".yml", ".yaml"):
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _looks_like_harness_pipeline(content):
                    found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[HarnessCIFinding], HarnessCIInfo]:
        findings: list[HarnessCIFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, HarnessCIInfo(path=rel)

        info = HarnessCIInfo(path=rel, lines=len(raw_lines))
        in_security_step = False
        pending_secret_name = False
        in_stage_block = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if re.match(r"^\s*stage\s*:", raw, re.IGNORECASE):
                in_stage_block = True
            if in_stage_block:
                stage_match = STEP_NAME_PATTERN.match(raw)
                if stage_match and "type:" not in line.lower():
                    info.stages.append(stage_match.group(1).strip())

            step_match = re.match(r"^\s*-\s*step\s*:", raw, re.IGNORECASE)
            if step_match or re.match(r"^\s*step\s*:", raw, re.IGNORECASE):
                in_stage_block = False

            name_match = STEP_NAME_PATTERN.match(raw)
            if name_match and ("step" in raw.lower() or "stage" in raw.lower()):
                step_name = name_match.group(1).strip()
                if "stage" in raw.lower() or in_stage_block:
                    if step_name not in info.stages:
                        info.stages.append(step_name)
                else:
                    info.steps.append(step_name)
                    in_security_step = bool(SECURITY_STEP_PATTERN.search(step_name))

            if PLAINTEXT_SECRET_TYPE_PATTERN.match(raw):
                pending_secret_name = True
            elif pending_secret_name and STRING_SECRET_TYPE_PATTERN.match(raw):
                findings.append(
                    HarnessCIFinding(
                        kind="plaintext_secret_type",
                        severity="high",
                        message="secret stored as type: String — use Harness Secret Manager references",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )
                pending_secret_name = False
            elif pending_secret_name and not raw.strip().startswith("-"):
                pending_secret_name = False

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_VALUE_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded credential — use Harness secrets or encrypted variables",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
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
                    HarnessCIFinding(
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
                    HarnessCIFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="Docker socket mount grants host-level container access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if PRIVILEGED_PATTERN.match(line):
                findings.append(
                    HarnessCIFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container mode grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.match(line):
                findings.append(
                    HarnessCIFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork bypasses container network isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.match(line):
                findings.append(
                    HarnessCIFinding(
                        kind="run_as_root",
                        severity="high",
                        message="runAsUser: 0 runs container as root — use a non-root user",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIV_ESCALATION_PATTERN.match(line):
                findings.append(
                    HarnessCIFinding(
                        kind="privilege_escalation",
                        severity="medium",
                        message="allowPrivilegeEscalation: true weakens container isolation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if AUTOMOUNT_SA_TOKEN_PATTERN.match(line):
                findings.append(
                    HarnessCIFinding(
                        kind="automount_sa_token",
                        severity="medium",
                        message="automountServiceAccountToken: true exposes cluster credentials to pods",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SCRIPT_INJECTION_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="script_injection",
                        severity="medium",
                        message="Harness expression from trigger/payload in script — validate untrusted PR inputs",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    HarnessCIFinding(
                        kind="insecure_http",
                        severity="low",
                        message="insecure HTTP URL in pipeline — prefer HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if in_security_step and re.search(
                r"^\s*action\s*:\s*(?:Ignore|MarkAsSuccess)\b", line, re.IGNORECASE
            ):
                findings.append(
                    HarnessCIFinding(
                        kind="security_failure_ignored",
                        severity="medium",
                        message="security step ignores failures — failing scans should block merges",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        return findings, info

    def analyze(self) -> list[HarnessCIFinding]:
        """Scan Harness CI pipelines and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[HarnessCIFinding] = []
        infos: list[HarnessCIInfo] = []
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
        self._stats = HarnessCIStats(
            pipelines=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> HarnessCIStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[HarnessCIInfo]:
        """Return parsed pipeline metadata."""
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
        """Scaffold a hardened Harness CI pipeline template."""
        return """\
# Generated by DevAI HarnessCIAnalyzer
pipeline:
  name: Example Pipeline
  identifier: Example_Pipeline
  stages:
    - stage:
        name: Build
        identifier: Build
        type: CI
        spec:
          cloneCodebase: true
          infrastructure:
            type: KubernetesDirect
            spec:
              connectorRef: account.DevCluster
              namespace: harness-delegate
              automountServiceAccountToken: false
              os: Linux
          execution:
            steps:
              - step:
                  type: Run
                  name: Test
                  identifier: Test
                  spec:
                    connectorRef: account.dockerhub
                    image: python:3.12-slim
                    shell: Sh
                    command: |-
                      pip install -e ".[dev]"
                      python -m pytest

              - step:
                  type: Run
                  name: Security Scan
                  identifier: Security_Scan
                  spec:
                    connectorRef: account.dockerhub
                    image: python:3.12-slim
                    shell: Sh
                    command: |-
                      pip install devai
                      devai security-scan .
                  failureStrategies:
                    - onFailure:
                        errors:
                          - AllErrors
                        action:
                          type: Abort
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.pipelines == 0:
            return "Harness CI: none found"
        return (
            f"Harness CI: {stats.pipelines} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Harness CI pipeline analysis:",
            f"  pipelines: {stats.pipelines}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            stages = ", ".join(info.stages[:5]) or "none"
            steps = ", ".join(info.steps[:5]) or "none"
            lines.append(
                f"  - {info.path}: {len(info.stages)} stage(s), {len(info.steps)} step(s), "
                f"stages=[{stages}], steps=[{steps}]"
            )
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
