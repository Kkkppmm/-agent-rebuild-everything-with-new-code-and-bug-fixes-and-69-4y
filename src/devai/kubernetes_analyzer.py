"""KubernetesAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_EXTENSIONS = (".yaml", ".yml")

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(r"^\s*runAsUser:\s*0\b", re.IGNORECASE)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"^\s*-\s*name:\s*(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL|AWS_SECRET)[A-Z0-9_]*\b",
    re.IGNORECASE,
)
PLAIN_SECRET_VALUE_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential)\s*:\s*['\"][^'\"]{4,}",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(r"^\s*hostPath:\s*$", re.IGNORECASE)
DANGEROUS_HOST_PATH_PATTERN = re.compile(
    r"path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run/docker\.sock)['\"]?",
    re.IGNORECASE,
)
SECRET_KEY_REF_PATTERN = re.compile(r"secretKeyRef:", re.IGNORECASE)
SECURITY_CONTEXT_PATTERN = re.compile(r"^\s*securityContext:\s*$", re.IGNORECASE)
READ_ONLY_ROOT_FALSE_PATTERN = re.compile(
    r"^\s*readOnlyRootFilesystem:\s*false\b",
    re.IGNORECASE,
)


@dataclass
class KubernetesFinding:
    """A security or best-practice issue in a Kubernetes manifest."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    resource: str = ""
    line: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        res = f" ({self.resource})" if self.resource else ""
        return f"[{self.severity}] {self.path}:{self.lineno}{res} — {self.message}"


@dataclass
class KubernetesInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    resources: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class KubernetesStats:
    """Aggregate Kubernetes manifest analysis statistics."""

    manifests: int
    findings: int
    resources: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix.lower() not in K8S_EXTENSIONS:
        return False
    parts = {p.lower() for p in path.parts}
    if "kubernetes" in parts or "k8s" in parts:
        return True
    if "manifests" in parts or "deploy" in parts or "helm" in parts:
        return True
    name = path.name.lower()
    if any(token in name for token in ("deployment", "service", "ingress", "configmap", "secret", "statefulset", "daemonset", "cronjob", "job", "pod")):
        return True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"^\s*apiVersion:\s*", text, re.MULTILINE)) and bool(
        re.search(r"^\s*kind:\s*", text, re.MULTILINE)
    )


class KubernetesAnalyzer:
    """Audit Kubernetes manifests for security risks and deployment best practices.

    Scans for privileged mode, host namespaces, root containers, secrets in env,
    :latest image tags, dangerous hostPath mounts, missing securityContext, and
    other common misconfigurations.
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

    def _add_finding(
        self,
        findings: list[KubernetesFinding],
        *,
        kind: str,
        severity: str,
        message: str,
        path: str,
        lineno: int,
        resource: str = "",
        line: str = "",
    ) -> None:
        findings.append(
            KubernetesFinding(
                kind=kind,
                severity=severity,
                message=message,
                path=path,
                lineno=lineno,
                resource=resource,
                line=line.strip(),
            )
        )

    def _analyze_file(self, path: Path) -> tuple[list[KubernetesFinding], KubernetesInfo]:
        findings: list[KubernetesFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, KubernetesInfo(path=rel)

        info = KubernetesInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        current_kind = ""
        in_security_context = False
        has_security_context = False
        in_env = False
        env_indent = 0
        pending_host_path = False

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if line.startswith("kind:"):
                current_kind = line.split(":", 1)[1].strip()
                if current_kind and current_kind not in info.kinds:
                    info.kinds.append(current_kind)
                has_security_context = False
                in_security_context = False
                in_env = False
                pending_host_path = False
                continue

            if line.startswith("metadata:"):
                current_resource = ""
                continue

            if line.startswith("name:") and indent <= 6:
                current_resource = line.split(":", 1)[1].strip()
                resource_label = f"{current_kind}/{current_resource}" if current_kind else current_resource
                if resource_label and resource_label not in info.resources:
                    info.resources.append(resource_label)
                continue

            if SECURITY_CONTEXT_PATTERN.match(line):
                in_security_context = True
                has_security_context = True
                continue

            if indent <= 2 and not line.startswith("-") and ":" in line:
                in_security_context = False
                in_env = False

            if line.startswith("env:"):
                in_env = True
                env_indent = indent
                continue

            if in_env and indent <= env_indent and not line.startswith("-"):
                in_env = False

            resource_label = f"{current_kind}/{current_resource}" if current_kind else current_resource

            if LATEST_TAG_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="latest_image_tag",
                    severity="medium",
                    message="image uses :latest tag — pin to a specific digest or version",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if PRIVILEGED_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="privileged",
                    severity="high",
                    message="privileged: true grants full host capabilities",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if HOST_NETWORK_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="host_network",
                    severity="high",
                    message="hostNetwork: true shares the host network namespace",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if HOST_PID_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="host_pid",
                    severity="high",
                    message="hostPID: true shares the host process namespace",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if HOST_IPC_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="host_ipc",
                    severity="high",
                    message="hostIPC: true shares the host IPC namespace",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if RUN_AS_ROOT_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="run_as_root",
                    severity="high",
                    message="runAsUser: 0 runs container as root",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if RUN_AS_NON_ROOT_FALSE_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="run_as_non_root_false",
                    severity="medium",
                    message="runAsNonRoot: false allows root execution",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if ALLOW_PRIV_ESC_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="allow_privilege_escalation",
                    severity="medium",
                    message="allowPrivilegeEscalation: true — set to false when possible",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if CAP_ADD_ALL_PATTERN.search(line) and "capabilities" in raw.lower():
                self._add_finding(
                    findings,
                    kind="cap_add_all",
                    severity="high",
                    message="capabilities add ALL — drop unnecessary capabilities",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if READ_ONLY_ROOT_FALSE_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="writable_root_fs",
                    severity="low",
                    message="readOnlyRootFilesystem: false — prefer read-only root filesystem",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if HOST_PATH_PATTERN.match(line):
                pending_host_path = True
                continue

            if pending_host_path and DANGEROUS_HOST_PATH_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="dangerous_host_path",
                    severity="high",
                    message="dangerous hostPath mount — avoid mounting /, /etc, /proc, or docker.sock",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )
                pending_host_path = False

            if in_env and SECRET_ENV_PATTERN.search(line) and not SECRET_KEY_REF_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="secret_in_env",
                    severity="high",
                    message="sensitive value in env block — use secretKeyRef or external secrets",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

            if PLAIN_SECRET_VALUE_PATTERN.search(line) and not SECRET_KEY_REF_PATTERN.search(line):
                self._add_finding(
                    findings,
                    kind="plain_secret_value",
                    severity="high",
                    message="plaintext secret in manifest — use Kubernetes Secrets",
                    path=rel,
                    lineno=lineno,
                    resource=resource_label,
                    line=line,
                )

        if current_kind in ("Deployment", "StatefulSet", "DaemonSet", "Pod", "Job", "CronJob"):
            if not has_security_context:
                self._add_finding(
                    findings,
                    kind="missing_security_context",
                    severity="medium",
                    message="no securityContext defined — set runAsNonRoot and drop capabilities",
                    path=rel,
                    lineno=1,
                    resource=f"{current_kind}/{current_resource}" if current_resource else current_kind,
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

        total_resources = sum(len(i.resources) for i in infos)
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")

        self._findings = findings
        self._infos = infos
        self._stats = KubernetesStats(
            manifests=len(paths),
            findings=len(findings),
            resources=total_resources,
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
        runAsUser: 10001
        fsGroup: 10001
      containers:
        - name: app
          image: ghcr.io/example/app:1.0.0
          imagePullPolicy: IfNotPresent
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
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: database-url
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes: no manifests found"
        return (
            f"Kubernetes: {stats.manifests} manifest(s), {stats.resources} resource(s), "
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
            f"  resources: {stats.resources}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score():.0f}/100",
        ]
        if self._findings:
            lines.append("")
            lines.append("Findings:")
            for finding in self._findings[:20]:
                lines.append(f"  - {finding.format()}")
            if len(self._findings) > 20:
                lines.append(f"  ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
