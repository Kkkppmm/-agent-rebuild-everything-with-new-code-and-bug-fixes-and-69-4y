"""TelepresenceAnalyzer — audit Telepresence configs for security and Kubernetes dev best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TELEPRESENCE_FILENAMES = (
    "telepresence.yaml",
    "telepresence.yml",
    "telepresence-values.yaml",
    "telepresence-values.yml",
)
TELEPRESENCE_DIRS = (
    "telepresence",
    ".telepresence",
    "deploy/telepresence",
    "k8s/telepresence",
    "manifests/telepresence",
)
TELEPRESENCE_MARKER_PATTERN = re.compile(
    r"(?:^\s*workloads\s*:|^\s*intercept\s*:|^\s*ambassador\s*:|"
    r"^\s*trafficManager\s*:|^\s*client\s*:|^\s*managerRbac\s*:|"
    r"telepresence\.io/)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#{}\s][^\s#]*)",
    re.IGNORECASE,
)
HARDCODED_ENV_PATTERN = re.compile(
    r"^\s*(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*:\s*"
    r"(?:[\"'][^\"'{}\s][^\"']*[\"']|[^\s#{}\s][^\s#]*)",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:url|repo|registry|repository|base|chart|helmRepo)\s*:\s*"
    r"[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|tag|value)\s*:\s*[\"']?[^\"'\s]*:latest[\"']?\s*$|"
    r"(?:tag|newTag)\s*:\s*[\"']?latest[\"']?\s*$",
    re.IGNORECASE,
)
SKIP_TLS_PATTERN = re.compile(
    r"(?:insecureSkipTLSVerify|skipTLSVerify|insecure_skip_tls_verify|tls\s*:\s*false)",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"privileged\s*:\s*true",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"hostNetwork\s*:\s*true",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
CLUSTER_ADMIN_PATTERN = re.compile(
    r"cluster-admin|clusterRole\s*:\s*cluster-admin|managerRbac\s*:\s*cluster-wide",
    re.IGNORECASE,
)
PROD_NAMESPACE_PATTERN = re.compile(
    r"(?:namespace|managerNamespace|defaultNamespace|targetNamespace)\s*:\s*"
    r"[\"']?(?:prod|production|live|staging)[\"']?",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:runAsUser|runAsRoot)\s*:\s*(?:0|true)",
    re.IGNORECASE,
)
RUN_AS_NON_ROOT_FALSE_PATTERN = re.compile(
    r"runAsNonRoot\s*:\s*false",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"hostPath\s*:\s*[\"']?/(?:etc|proc|sys|var/run/docker\.sock)",
    re.IGNORECASE,
)
ENV_FILE_SENSITIVE_PATTERN = re.compile(
    r"(?:envFile|env-file|env_file)\s*:\s*[\"']?(?:\.env|\.env\.[^\"'\s]+)[\"']?",
    re.IGNORECASE,
)
INLINE_KUBECONFIG_PATTERN = re.compile(
    r"(?:kubeconfig|kubeConfig)\s*:\s*[\"']?[A-Za-z0-9+/=]{20,}",
    re.IGNORECASE,
)
DOCKER_RUN_PATTERN = re.compile(
    r"(?:dockerRun|docker\s*:\s*true|client\s*:\s*docker)",
    re.IGNORECASE,
)
ALLOW_PRIVILEGED_PATTERN = re.compile(
    r"(?:allowPrivileged|allow-privileged|allowPrivilegedWorkloads)\s*:\s*true",
    re.IGNORECASE,
)
GLOBAL_INTERCEPT_PATTERN = re.compile(
    r"(?:global|defaultWorkload|interceptAll|intercept-all)\s*:\s*true",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git::)?https?://[^\s\"']+(?![^\n]*(?:ref=|commit=|tag=|@))",
    re.IGNORECASE,
)


@dataclass
class TelepresenceFinding:
    """A security or best-practice issue in a Telepresence configuration."""

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
class TelepresenceInfo:
    """Parsed metadata about a Telepresence config file."""

    path: str
    workloads: int = 0
    intercepts: int = 0
    namespaces: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class TelepresenceStats:
    """Aggregate Telepresence analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_telepresence_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in TELEPRESENCE_FILENAMES:
        return True
    if lower.endswith((".yaml", ".yml")):
        parts = {p.lower() for p in path.parts}
        if parts & set(TELEPRESENCE_DIRS):
            return True
        if "telepresence" in lower:
            return True
        try:
            head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            if TELEPRESENCE_MARKER_PATTERN.search(head):
                return True
        except OSError:
            pass
    return False


class TelepresenceAnalyzer:
    """Audit Telepresence configs for hardcoded secrets, production intercepts, and risky dev settings.

    Scans ``telepresence.yaml`` and related values files for plaintext env vars, production
    namespace targets, docker.sock mounts, privileged traffic-agent settings, sensitive envFile
    paths, and cluster-wide manager RBAC.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TelepresenceFinding] | None = None
        self._stats: TelepresenceStats | None = None
        self._infos: list[TelepresenceInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Telepresence configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_telepresence_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TelepresenceFinding], TelepresenceInfo]:
        findings: list[TelepresenceFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, TelepresenceInfo(path=rel)

        raw_lines = text.splitlines()
        info = TelepresenceInfo(path=rel, lines=len(raw_lines))

        in_env_block = False
        namespaces: list[str] = []
        workload_count = 0
        intercept_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"^\s*workloads\s*:\s*$", line, re.IGNORECASE):
                in_env_block = False
            elif re.search(r"^\s*env\s*:\s*$", line, re.IGNORECASE):
                in_env_block = True
            elif in_env_block and not line.startswith(" ") and not line.startswith("-"):
                in_env_block = False

            if re.search(r"^\s*-\s*name\s*:", line, re.IGNORECASE) and "workloads" in text.lower():
                workload_count += 1

            if re.search(r"^\s*intercept\s*:", line, re.IGNORECASE):
                intercept_count += 1

            ns_match = re.search(
                r"(?:namespace|managerNamespace|defaultNamespace|targetNamespace)\s*:\s*"
                r"[\"']?([^\"'\s#]+)[\"']?",
                line,
                re.IGNORECASE,
            )
            if ns_match:
                namespaces.append(ns_match.group(1))

            if HARDCODED_SECRET_PATTERN.search(line) or (
                in_env_block and HARDCODED_ENV_PATTERN.search(line)
            ):
                findings.append(
                    TelepresenceFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Telepresence config — use Kubernetes secrets or envFrom references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Telepresence config — use IAM roles or secret references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="insecure HTTP source — use HTTPS for registries and remote configs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a digest or version tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_TLS_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="skip_tls_verify",
                        severity="high",
                        message="TLS verification disabled — enable TLS verification for cluster and registry traffic",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container enabled — avoid privileged mode in traffic-agent workloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork enabled — isolate traffic-agent pod networking",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock mount exposes host Docker daemon — use container-mode intercepts instead",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in lifecycle hook — use pinned artifacts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="cluster_admin",
                        severity="high",
                        message="cluster-admin or cluster-wide manager RBAC — restrict to namespace-scoped roles",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PROD_NAMESPACE_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="production_namespace",
                        severity="medium",
                        message="namespace targets production-like environment — isolate dev intercepts from prod",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ROOT_USER_PATTERN.search(line) or RUN_AS_NON_ROOT_FALSE_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="root_container",
                        severity="medium",
                        message="container runs as root — set runAsNonRoot and non-zero runAsUser",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_PATH_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="host_path_mount",
                        severity="high",
                        message="hostPath mount to sensitive host directory — use PVCs or emptyDir",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ENV_FILE_SENSITIVE_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="sensitive_env_file",
                        severity="high",
                        message="envFile references .env — use Kubernetes secrets instead of syncing local secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INLINE_KUBECONFIG_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="inline_kubeconfig",
                        severity="high",
                        message="inline kubeconfig in Telepresence config — use context references or secret files",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_RUN_PATTERN.search(line) and DOCKER_SOCKET_PATTERN.search(text):
                findings.append(
                    TelepresenceFinding(
                        kind="docker_run_mode",
                        severity="medium",
                        message="dockerRun/client docker mode with docker.sock access — prefer container-mode intercepts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ALLOW_PRIVILEGED_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="allow_privileged",
                        severity="high",
                        message="allowPrivileged enabled — disable privileged workload intercepts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if GLOBAL_INTERCEPT_PATTERN.search(line):
                findings.append(
                    TelepresenceFinding(
                        kind="global_intercept",
                        severity="medium",
                        message="global/default intercept enabled — scope intercepts to explicit workloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git::" in line.lower() or "repository" in line.lower()
            ):
                if "ref=" not in line and "commit=" not in line and "tag=" not in line:
                    findings.append(
                        TelepresenceFinding(
                            kind="unpinned_git_source",
                            severity="medium",
                            message="git remote source without ref/commit pin — pin to immutable revision",
                            path=rel,
                            lineno=lineno,
                            line=line,
                        )
                    )

        info.workloads = workload_count
        info.intercepts = intercept_count
        info.namespaces = namespaces
        return findings, info

    def analyze(self) -> list[TelepresenceFinding]:
        """Scan Telepresence configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TelepresenceFinding] = []
        infos: list[TelepresenceInfo] = []
        paths = self.configs()

        for path in paths:
            file_findings, info = self._analyze_file(path)
            findings.extend(file_findings)
            infos.append(info)

        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")
        low = sum(1 for f in findings if f.severity == "low")
        self._findings = findings
        self._infos = infos
        self._stats = TelepresenceStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TelepresenceStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TelepresenceInfo]:
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

    def generate_hardened_config(self) -> str:
        """Scaffold a hardened Telepresence configuration."""
        return """\
---
workloads:
  - name: api
    namespace: app-dev
    intercept:
      port: 8080
      default: false
      env:
        LOG_LEVEL: debug
      envFile: ./config/dev.env.example

client:
  docker:
    enabled: false

trafficManager:
  managerNamespace: telepresence-dev
  agent:
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      privileged: false
      allowPrivilegeEscalation: false

managerRbac:
  create: true
  namespaced: true
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Telepresence configs: none found"
        return (
            f"Telepresence configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Telepresence analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            ns_list = ", ".join(info.namespaces) if info.namespaces else "none"
            lines.append(
                f"  - {info.path}: {info.workloads} workload(s), "
                f"{info.intercepts} intercept(s), namespaces: {ns_list}"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
