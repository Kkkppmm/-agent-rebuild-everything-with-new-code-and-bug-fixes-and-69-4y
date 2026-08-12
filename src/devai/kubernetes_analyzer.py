"""KubernetesAnalyzer — audit Kubernetes manifests for security misconfigurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIRS = ("k8s", "kubernetes", "manifests", "deploy", "deployment", "helm")
K8S_SUFFIXES = (".yaml", ".yml")
K8S_NAME_PATTERN = re.compile(
    r"(deployment|service|ingress|configmap|secret|statefulset|daemonset|pod|cronjob|job)",
    re.IGNORECASE,
)

PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"runAsUser:\s*0\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
LATEST_IMAGE_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_VALUE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*:\s*['\"]?[A-Za-z0-9+/=_-]{8,}",
    re.IGNORECASE,
)
NO_LIMITS_PATTERN = re.compile(r"resources:\s*$", re.IGNORECASE)


@dataclass
class KubernetesFinding:
    """A security issue in a Kubernetes manifest."""

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
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    lower = path.name.lower()
    if not lower.endswith(K8S_SUFFIXES):
        return False
    parts = {p.lower() for p in path.parts}
    if parts & set(K8S_DIRS):
        return True
    if K8S_NAME_PATTERN.search(lower):
        return True
    if lower in ("kustomization.yaml", "kustomization.yml"):
        return True
    return False


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for privileged mode, host namespaces, and secrets in env.

    Scans YAML manifests in common k8s directories for securityContext issues,
    :latest image tags, hardcoded secrets, and missing resource limits.
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
            if not path.is_file():
                continue
            if _is_k8s_manifest(path):
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
        has_resources = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("kind:"):
                kind = line.split(":", 1)[1].strip()
                info.kinds.append(kind)

            if "securityContext:" in line:
                info.has_security_context = True

            if "limits:" in line or "requests:" in line:
                has_resources = True

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
                        message="hostNetwork: true exposes pod to host network stack",
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
                        severity="medium",
                        message="allowPrivilegeEscalation: true can enable privilege escalation",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

            if LATEST_IMAGE_PATTERN.search(line):
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

            if SECRET_VALUE_PATTERN.search(line):
                findings.append(
                    KubernetesFinding(
                        kind="secret_in_manifest",
                        severity="high",
                        message="potential secret in manifest — use Kubernetes Secrets or external secret store",
                        path=rel,
                        lineno=lineno,
                        line=raw.strip(),
                    )
                )

        if info.kinds and not has_resources and not info.has_security_context:
            findings.append(
                KubernetesFinding(
                    kind="missing_security_context",
                    severity="low",
                    message="no securityContext or resource limits detected",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[KubernetesFinding]:
        """Scan Kubernetes manifests and return findings."""
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

    def generate_hardened_template(self) -> str:
        """Scaffold a hardened Kubernetes Deployment template."""
        return """\
# Generated by DevAI KubernetesAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: app
  template:
    metadata:
      labels:
        app: app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: app
          image: myregistry/app:1.0.0
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
"""

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
            "Kubernetes analysis:",
            f"  manifests: {stats.manifests}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            kinds = ", ".join(info.kinds) if info.kinds else "unknown"
            lines.append(f"  - {info.path}: kind(s)={kinds}")
        for finding in self._findings[:25]:
            lines.append(f"  - {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
