"""KubernetesAnalyzer — audit K8s manifests for security and deployment best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_MARKERS = (
    "apiVersion:",
    "kind:",
    "metadata:",
    "spec:",
)
K8S_KINDS = (
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Pod",
    "Service",
    "Ingress",
    "ConfigMap",
    "Secret",
    "Job",
    "CronJob",
)

PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b", re.IGNORECASE
)
LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*[:=]",
    re.IGNORECASE,
)
READ_ONLY_ROOT_FALSE_PATTERN = re.compile(
    r"readOnlyRootFilesystem:\s*false\b", re.IGNORECASE
)


@dataclass
class KubernetesFinding:
    """A security or best-practice issue in a Kubernetes manifest."""

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
class KubernetesInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    kinds: list[str] = field(default_factory=list)
    has_security_context: bool = False
    has_resource_limits: bool = False
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in (".yaml", ".yml"):
        return False
    lower_parts = {p.lower() for p in path.parts}
    if "kubernetes" in lower_parts or "k8s" in lower_parts:
        return True
    # Heuristic: check content markers
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2048]
    except OSError:
        return False
    if not any(marker in head for marker in K8S_MARKERS):
        return False
    return any(kind in head for kind in K8S_KINDS)


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged mode, host namespaces, root execution, secrets in env,
    :latest image tags, missing resource limits, and insecure security contexts.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[KubernetesFinding] | None = None
        self._stats: KubernetesStats | None = None
        self._infos: list[KubernetesInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_k8s_manifest(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                info.kinds.append(kind)

            if "securityContext:" in line or "runAsNonRoot:" in line:
                info.has_security_context = True

            if "limits:" in line or "resources:" in line:
                info.has_resource_limits = True

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="privileged",
                        severity="high",
                        message="privileged: true grants full host access",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork: true exposes pod to host network",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_PID_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_pid",
                        severity="high",
                        message="hostPID: true shares host process namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if HOST_IPC_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="host_ipc",
                        severity="medium",
                        message="hostIPC: true shares host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="run_as_root",
                        severity="high",
                        message="runAsUser: 0 runs container as root",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if ALLOW_PRIV_ESC_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="privilege_escalation",
                        severity="high",
                        message="allowPrivilegeEscalation: true enables privilege escalation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin a specific version",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if SECRET_ENV_PATTERN.search(line) and "value:" in line.lower():
                findings.append(
                    KubernetesFinding(
                        kind="secret_in_env",
                        severity="high",
                        message="potential secret in env value — use Secret references",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if READ_ONLY_ROOT_FALSE_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="writable_root_fs",
                        severity="medium",
                        message="readOnlyRootFilesystem: false allows writing to container root",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.kinds and not info.has_security_context:
            findings.append(
                KubernetesFinding(
                    kind="missing_security_context",
                    severity="medium",
                    message="no securityContext defined — set runAsNonRoot and drop capabilities",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        if info.kinds and not info.has_resource_limits:
            findings.append(
                KubernetesFinding(
                    kind="missing_resource_limits",
                    severity="low",
                    message="no resource limits — set CPU/memory limits to prevent resource exhaustion",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[KubernetesFinding] = []
        infos: list[KubernetesInfo] = []
        paths = self.manifests()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        self._findings = findings
        self._infos = infos
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._stats = KubernetesStats(
            manifests=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> KubernetesStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[KubernetesInfo]:
        """Return parsed manifest metadata."""
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no issues or no manifests)."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return 100.0
        if stats.findings == 0:
            return 100.0
        penalty = (
            stats.high_severity * 20.0
            + stats.medium_severity * 8.0
            + stats.low_severity * 2.0
        )
        return round(max(0.0, min(100.0, 100.0 - penalty)), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes manifests: none found"
        return (
            f"Kubernetes manifests: {stats.manifests} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Kubernetes manifest analysis:",
            f"  manifests: {stats.manifests}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            kinds = ", ".join(info.kinds) or "unknown"
            lines.append(f"  - {info.path}: kinds={kinds}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
