"""TiltAnalyzer — audit Tiltfiles for security and Kubernetes dev best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TILT_FILENAMES = ("Tiltfile",)
TILT_EXTENSIONS = (".tilt",)
TILT_DIRS = ("tilt", "deploy/tilt", "k8s/tilt", "manifests/tilt")
TILT_MARKER_PATTERN = re.compile(
    r"(?:docker_build|k8s_yaml|k8s_resource|local_resource|helm|custom_build|"
    r"allow_k8s_contexts|load\s*\(\s*['\"]ext://)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:['\"]?(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)['\"]?)\s*[=:]\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
HARDCODED_SECRET_KWARG_PATTERN = HARDCODED_SECRET_PATTERN
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:registry|repo|url|repository|default_registry)\s*[\(=]\s*[\"']?http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:image|ref|tag)\s*=\s*[\"']?[^\"'\s]*:latest[\"']?",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"privileged\s*=\s*True|security_context\s*=\s*\{[^}]*privileged\s*:\s*True",
    re.IGNORECASE,
)
HOST_NETWORK_PATTERN = re.compile(
    r"host_network\s*=\s*True|hostNetwork\s*:\s*true",
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
    r"cluster-admin|cluster_admin",
    re.IGNORECASE,
)
PROD_CONTEXT_PATTERN = re.compile(
    r"allow_k8s_contexts\s*\(\s*[\"'](?:prod|production|live|staging)[\"']",
    re.IGNORECASE,
)
SYNC_SENSITIVE_PATTERN = re.compile(
    r"sync\s*\(\s*['\"](?:\.env|\.git|/etc|/proc|/sys)",
    re.IGNORECASE,
)
PORT_FORWARD_ALL_PATTERN = re.compile(
    r"port_forwards\s*=\s*\[[^\]]*0\s*:\s*0|port_forwards\s*=\s*['\"]0['\"]",
    re.IGNORECASE,
)
INSECURE_REGISTRY_PATTERN = re.compile(
    r"insecure_registry\s*=\s*True|default_registry\s*\(\s*[\"']http://",
    re.IGNORECASE,
)
SKIP_TLS_PATTERN = re.compile(
    r"(?:insecure_skip_tls_verify|skip_tls_verify)\s*=\s*True",
    re.IGNORECASE,
)
DISABLED_SECRET_SCAN_PATTERN = re.compile(
    r"secret_settings\s*\([^)]*disable_scrub\s*=\s*True",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"git\s+clone\s+https?://[^\s\"']+(?![^\n]*(?:--branch|--depth|@))",
    re.IGNORECASE,
)
ROOT_USER_PATTERN = re.compile(
    r"(?:run_as_user|runAsUser)\s*=\s*0|runAsNonRoot\s*:\s*false",
    re.IGNORECASE,
)
DISABLED_UPDATE_PATTERN = re.compile(
    r"update_settings\s*=\s*update_settings\s*\(\s*max_parallel_updates\s*=\s*0",
    re.IGNORECASE,
)


@dataclass
class TiltFinding:
    """A security or best-practice issue in a Tilt configuration."""

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
class TiltInfo:
    """Parsed metadata about a Tiltfile."""

    path: str
    resources: int = 0
    docker_builds: int = 0
    local_resources: int = 0
    lines: int = 0


@dataclass
class TiltStats:
    """Aggregate Tilt analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_tilt_file(path: Path) -> bool:
    name = path.name
    if name in TILT_FILENAMES:
        return True
    if name.startswith("Tiltfile."):
        return True
    if name.endswith(TILT_EXTENSIONS):
        return True
    if name.lower().endswith((".yaml", ".yml")):
        parts = {p.lower() for p in path.parts}
        if parts & set(TILT_DIRS):
            return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if TILT_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


class TiltAnalyzer:
    """Audit Tiltfiles for hardcoded secrets, insecure registries, and risky dev settings.

    Scans ``Tiltfile`` for plaintext env vars, insecure HTTP registries, :latest tags,
    docker.sock mounts, production kube contexts, disabled secret scrubbing, and privileged patches.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[TiltFinding] | None = None
        self._stats: TiltStats | None = None
        self._infos: list[TiltInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Tilt configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_tilt_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[TiltFinding], TiltInfo]:
        findings: list[TiltFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, TiltInfo(path=rel)

        raw_lines = text.splitlines()
        info = TiltInfo(path=rel, lines=len(raw_lines))

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"\bk8s_resource\s*\(", line):
                info.resources += 1
            if re.search(r"\bdocker_build\s*\(", line):
                info.docker_builds += 1
            if re.search(r"\blocal_resource\s*\(", line):
                info.local_resources += 1

            if HARDCODED_SECRET_PATTERN.search(line) or HARDCODED_SECRET_KWARG_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in Tiltfile — use secret_settings or Kubernetes secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Tiltfile — use IAM roles or secret references",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="insecure_http_source",
                        severity="high",
                        message="insecure HTTP registry or repo — use HTTPS",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="latest_image_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to a digest or version tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_REGISTRY_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="insecure_registry",
                        severity="high",
                        message="insecure registry configured — use TLS-enabled registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SKIP_TLS_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="tls_verification_disabled",
                        severity="high",
                        message="TLS verification disabled for registry or Helm chart fetch",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="privileged_container",
                        severity="high",
                        message="privileged container enabled — restrict to required workloads",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_NETWORK_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="host_network",
                        severity="high",
                        message="hostNetwork enabled — exposes workload to host network stack",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock mount grants container root on host — avoid in Tilt builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell in local_resource — verify source and pin checksums",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CLUSTER_ADMIN_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="cluster_admin",
                        severity="high",
                        message="cluster-admin grants excessive cluster permissions",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PROD_CONTEXT_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="production_kube_context",
                        severity="medium",
                        message="allow_k8s_contexts targets production-like cluster — isolate dev from prod",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if SYNC_SENSITIVE_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="sensitive_sync_path",
                        severity="medium",
                        message="live_update sync may expose secrets or host paths — restrict sync paths",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PORT_FORWARD_ALL_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="broad_port_forward",
                        severity="medium",
                        message="port_forwards exposes all ports — restrict to required ports",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLED_SECRET_SCAN_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="secret_scrub_disabled",
                        severity="high",
                        message="secret_settings disable_scrub=True prevents redacting secrets in logs",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if ROOT_USER_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="root_container",
                        severity="medium",
                        message="container runs as root — set runAsNonRoot and non-zero runAsUser",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="git clone without branch/commit pin — pin to immutable revision",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DISABLED_UPDATE_PATTERN.search(line):
                findings.append(
                    TiltFinding(
                        kind="updates_disabled",
                        severity="low",
                        message="max_parallel_updates=0 disables live updates — verify intentional for production",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        return findings, info

    def analyze(self) -> list[TiltFinding]:
        """Scan Tilt configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[TiltFinding] = []
        infos: list[TiltInfo] = []
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
        self._stats = TiltStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> TiltStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[TiltInfo]:
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
        """Scaffold a hardened Tiltfile."""
        return """\
# Hardened Tiltfile template
allow_k8s_contexts('docker-desktop', 'kind-kind', 'minikube')

default_registry('ghcr.io/org')

docker_build(
    'app',
    '.',
    dockerfile='Dockerfile',
    live_update=[
        sync('./src', '/app/src'),
        run('pip install -r requirements.txt', trigger=['requirements.txt']),
    ],
)

k8s_yaml('k8s/')

k8s_resource(
    'app',
    port_forwards='8080:8080',
    labels=['app'],
)
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Tilt configs: none found"
        return (
            f"Tilt configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Tilt analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path}: {info.resources} k8s_resource(s), "
                f"{info.docker_builds} docker_build(s), {info.local_resources} local_resource(s)"
            )
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more")
        return "\n".join(lines)
