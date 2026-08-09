"""K8sAnalyzer — audit Kubernetes manifests for security and best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

K8S_DIRS = ("k8s", "kubernetes", "deploy", "deployment", "manifests", "helm")
K8S_EXTENSIONS = (".yaml", ".yml")

LATEST_TAG_PATTERN = re.compile(r"image:\s*[^\s]+:latest\b", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(
    r"(password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
SECRET_ENV_NAME_PATTERN = re.compile(
    r"name:\s*['\"]?\w*(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|CREDENTIAL)",
    re.IGNORECASE,
)
DOCKER_SOCK_PATTERN = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
HOST_PATH_SENSITIVE_PATTERN = re.compile(
    r"hostPath:\s*$|path:\s*['\"]?(?:/|/etc|/proc|/sys|/var/run)['\"]?",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(r"^\s*privileged:\s*true\b", re.IGNORECASE)
HOST_NETWORK_PATTERN = re.compile(r"^\s*hostNetwork:\s*true\b", re.IGNORECASE)
HOST_PID_PATTERN = re.compile(r"^\s*hostPID:\s*true\b", re.IGNORECASE)
HOST_IPC_PATTERN = re.compile(r"^\s*hostIPC:\s*true\b", re.IGNORECASE)
RUN_AS_ROOT_PATTERN = re.compile(
    r"^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b",
    re.IGNORECASE,
)
ALLOW_PRIV_ESC_PATTERN = re.compile(
    r"^\s*allowPrivilegeEscalation:\s*true\b",
    re.IGNORECASE,
)
READ_ONLY_FALSE_PATTERN = re.compile(
    r"^\s*readOnlyRootFilesystem:\s*false\b",
    re.IGNORECASE,
)
CAP_ADD_ALL_PATTERN = re.compile(r"^\s*-\s*ALL\b", re.IGNORECASE)
RESOURCE_LIMIT_PATTERN = re.compile(
    r"(limits:\s*$|memory:\s*['\"]?\d|cpu:\s*['\"]?\d|resources:\s*$)",
    re.IGNORECASE,
)
RUN_AS_USER_PATTERN = re.compile(r"^\s*runAsUser:\s+", re.IGNORECASE)
RUN_AS_NON_ROOT_PATTERN = re.compile(r"^\s*runAsNonRoot:\s*true\b", re.IGNORECASE)
SECRET_REF_INLINE_PATTERN = re.compile(
    r"^\s*value:\s*(?:['\"][^'\"]{8,}['\"]|[^\s#]{8,})",
    re.IGNORECASE,
)
WILDCARD_INGRESS_PATTERN = re.compile(
    r"^\s*-\s*['\"]?\*['\"]?\s*$|host:\s*['\"]?\*['\"]?",
    re.IGNORECASE,
)


@dataclass
class K8sFinding:
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
class K8sInfo:
    """Parsed metadata about a Kubernetes manifest."""

    path: str
    resources: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class K8sStats:
    """Aggregate Kubernetes analysis statistics."""

    manifests: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_k8s_manifest(path: Path) -> bool:
    name = path.name.lower()
    if not any(name.endswith(ext) for ext in K8S_EXTENSIONS):
        return False
    if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        return False
    parts_lower = {p.lower() for p in path.parts}
    if parts_lower & set(K8S_DIRS):
        return True
    # Common manifest naming conventions
    if re.match(
        r"^(deployment|service|ingress|configmap|secret|pod|statefulset|daemonset|job|cronjob)",
        name,
    ):
        return True
    if re.search(r"(deployment|service|ingress|configmap|secret|manifest|k8s|kube)", name):
        return True
    return False


def _looks_like_k8s_content(lines: list[str]) -> bool:
    """Heuristic: file contains Kubernetes API markers."""
    markers = ("apiVersion:", "kind:", "metadata:", "spec:")
    hits = sum(1 for line in lines[:30] for m in markers if m in line)
    return hits >= 2


class K8sAnalyzer:
    """Audit Kubernetes YAML manifests for security risks and cluster best practices.

    Scans for privileged pods, host networking/PID/IPC, :latest image tags,
    secrets in environment literals, dangerous hostPath mounts, missing resource
    limits, and other common misconfigurations.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[K8sFinding] | None = None
        self._stats: K8sStats | None = None
        self._infos: list[K8sInfo] | None = None

    def manifests(self) -> list[Path]:
        """Return Kubernetes manifest paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            if _is_k8s_manifest(path):
                found.append(path)
                continue
            if any(path.name.endswith(ext) for ext in K8S_EXTENSIONS):
                try:
                    raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                if _looks_like_k8s_content(raw):
                    found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[K8sFinding], K8sInfo]:
        findings: list[K8sFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return findings, K8sInfo(path=rel)

        info = K8sInfo(path=rel, lines=len(raw_lines))
        current_resource = ""
        current_kind = ""
        in_containers = False
        container_indent = 0
        container_has_user = False
        container_has_resources = False
        in_env = False
        env_indent = 0
        in_security_context = False
        security_indent = 0
        in_host_paths = False
        host_path_indent = 0
        in_ingress_rules = False
        ingress_indent = 0

        for lineno, raw in enumerate(raw_lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            indent = len(raw) - len(raw.lstrip())

            if indent == 0 and line.startswith("kind:"):
                current_kind = line.split(":", 1)[1].strip()
                info.kinds.append(current_kind)
                continue

            if indent == 0 and line.startswith("metadata:"):
                current_resource = ""
                continue

            if line.startswith("name:") and indent <= 4:
                name_val = line.split(":", 1)[1].strip().strip("'\"")
                if current_kind:
                    current_resource = f"{current_kind}/{name_val}"
                    info.resources.append(current_resource)
                continue

            if line == "containers:" or line.startswith("containers:"):
                in_containers = True
                container_indent = indent
                container_has_user = False
                container_has_resources = False
                continue

            if in_containers and indent <= container_indent and line.endswith(":") and indent > 0:
                if not container_has_resources and current_resource:
                    findings.append(
                        K8sFinding(
                            kind="missing_resource_limits",
                            severity="medium",
                            message="Container has no resource limits defined",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                        )
                    )
                in_containers = False

            if HOST_NETWORK_PATTERN.search(raw):
                findings.append(
                    K8sFinding(
                        kind="host_network",
                        severity="high",
                        message="Pod uses host networking",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if HOST_PID_PATTERN.search(raw):
                findings.append(
                    K8sFinding(
                        kind="host_pid",
                        severity="high",
                        message="Pod uses host PID namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if HOST_IPC_PATTERN.search(raw):
                findings.append(
                    K8sFinding(
                        kind="host_ipc",
                        severity="high",
                        message="Pod uses host IPC namespace",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if in_containers:
                if RUN_AS_USER_PATTERN.search(raw) or RUN_AS_NON_ROOT_PATTERN.search(raw):
                    container_has_user = True
                if RESOURCE_LIMIT_PATTERN.search(raw):
                    container_has_resources = True

                if PRIVILEGED_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="privileged",
                            severity="high",
                            message="Container runs in privileged mode",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

                if LATEST_TAG_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="latest_tag",
                            severity="medium",
                            message="Container image uses :latest tag — pin to a specific version",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

                if DOCKER_SOCK_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="docker_sock_mount",
                            severity="high",
                            message="Docker socket mount detected — cluster escape risk",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

            if line == "securityContext:" or line.startswith("securityContext:"):
                in_security_context = True
                security_indent = indent
                continue

            if in_security_context:
                if indent <= security_indent and line.endswith(":"):
                    in_security_context = False
                elif RUN_AS_ROOT_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="run_as_root",
                            severity="high",
                            message="securityContext allows running as root",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )
                elif ALLOW_PRIV_ESC_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="privilege_escalation",
                            severity="high",
                            message="allowPrivilegeEscalation is enabled",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )
                elif READ_ONLY_FALSE_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="writable_rootfs",
                            severity="medium",
                            message="readOnlyRootFilesystem is disabled",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

            if line == "env:" or line.startswith("env:"):
                in_env = True
                env_indent = indent
                continue

            if in_env:
                if indent <= env_indent and line.endswith(":") and indent > 0:
                    in_env = False
                elif SECRET_ENV_PATTERN.search(raw) or SECRET_ENV_NAME_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="secret_in_environment",
                            severity="high",
                            message="Potential secret in environment literal",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )
                elif SECRET_REF_INLINE_PATTERN.search(raw) and "secretKeyRef" not in raw:
                    findings.append(
                        K8sFinding(
                            kind="inline_secret_value",
                            severity="high",
                            message="Inline value in env block may expose a secret",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

            if line == "hostPath:" or line.startswith("hostPath:"):
                in_host_paths = True
                host_path_indent = indent
                continue

            if in_host_paths:
                if indent <= host_path_indent and line.endswith(":") and indent > 0:
                    in_host_paths = False
                elif HOST_PATH_SENSITIVE_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="sensitive_hostpath",
                            severity="high",
                            message="hostPath mount to sensitive host directory",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

            context_block = "\n".join(raw_lines[max(0, lineno - 6):lineno])
            if (
                CAP_ADD_ALL_PATTERN.search(raw)
                and "capabilities:" in context_block
                and "add:" in context_block
                and "drop:" not in context_block.split("add:")[0]
            ):
                findings.append(
                    K8sFinding(
                        kind="cap_add_all",
                        severity="high",
                        message="capabilities add ALL grants full Linux capabilities",
                        path=rel,
                        lineno=lineno,
                        resource=current_resource,
                        line=line,
                    )
                )

            if line == "rules:" and current_kind == "Ingress":
                in_ingress_rules = True
                ingress_indent = indent
                continue

            if in_ingress_rules:
                if indent <= ingress_indent and line.endswith(":") and indent > 0:
                    in_ingress_rules = False
                elif WILDCARD_INGRESS_PATTERN.search(raw):
                    findings.append(
                        K8sFinding(
                            kind="wildcard_ingress",
                            severity="medium",
                            message="Ingress allows wildcard host — restrict to known domains",
                            path=rel,
                            lineno=lineno,
                            resource=current_resource,
                            line=line,
                        )
                    )

        return findings, info

    def analyze(self) -> list[K8sFinding]:
        """Scan Kubernetes manifests and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[K8sFinding] = []
        infos: list[K8sInfo] = []
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
        self._stats = K8sStats(
            manifests=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> K8sStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[K8sInfo]:
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
# Generated by DevAI K8sAnalyzer
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels:
    app: app
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
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: python:3.12-slim
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: 8000
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.manifests == 0:
            return "Kubernetes manifests: none found"
        lines = [
            (
                f"Kubernetes manifests: {stats.manifests} file(s), "
                f"{stats.findings} finding(s) "
                f"({stats.high_severity} high, {stats.medium_severity} medium, "
                f"{stats.low_severity} low)"
            ),
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self) -> str:
        """Export findings as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "# Kubernetes Manifest Audit",
            "",
            self.summary(),
            "",
        ]
        if stats.findings:
            lines.append("## Findings")
            lines.append("")
            for finding in self._findings or []:
                lines.append(f"- {finding.format()}")
        return "\n".join(lines)
