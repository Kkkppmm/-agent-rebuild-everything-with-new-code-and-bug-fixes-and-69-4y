"""EarthlyAnalyzer — audit Earthfiles for security and reproducible build best practices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

EARTHLY_FILENAMES = ("Earthfile", "earthfile", "Earthfile.dockerfile")
EARTHLY_EXTENSIONS = (".earth",)
EARTHLY_DIRS = ("earthly", ".earthly", "build/earthly", "ci/earthly")
EARTHLY_MARKER_PATTERN = re.compile(
    r"(?:^\s*VERSION\s|^\s*FROM\s|^\s*BUILD\s|^\s*SAVE\s|^\s*WITH\s+DOCKER)",
    re.IGNORECASE | re.MULTILINE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:ARG|ENV)\s+(?:--\w+\s+)*(?:password|passwd|secret|api[_-]?key|token|credential|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)\s*=\s*"
    r"[\"']?[^\"'\s${}][^\s\"']*[\"']?",
    re.IGNORECASE,
)
HARDCODED_ENV_PATTERN = re.compile(
    r"^\s*(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*=\s*"
    r"[\"']?[^\"'\s${}][^\s\"']*[\"']?",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:FROM|BUILD|SAVE\s+IMAGE|--push|--load)\s+[^\n]*http://(?!localhost|127\.0\.0\.1)[^\s\"']+",
    re.IGNORECASE,
)
LATEST_TAG_PATTERN = re.compile(
    r"(?:FROM|SAVE\s+IMAGE|BUILD|--tag)\s+[^\n]*:latest\b",
    re.IGNORECASE,
)
CURL_PIPE_SHELL_PATTERN = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
DOCKER_SOCKET_PATTERN = re.compile(
    r"/var/run/docker\.sock",
    re.IGNORECASE,
)
PRIVILEGED_PATTERN = re.compile(
    r"(?:--privileged|privileged\s*=\s*true)",
    re.IGNORECASE,
)
INSECURE_FLAG_PATTERN = re.compile(
    r"(?:--insecure|--allow-privileged|insecure\s*=\s*true)",
    re.IGNORECASE,
)
PLAIN_ARG_SECRET_PATTERN = re.compile(
    r"^\s*ARG\s+(?!--secret\b)(?:password|passwd|secret|api[_-]?key|token|credential|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)\b",
    re.IGNORECASE,
)
RUN_SECRET_PATTERN = re.compile(
    r"^\s*RUN\s+.*(?:password|passwd|secret|api[_-]?key|token|credential)\s*=\s*"
    r"[\"'][^\"'{}\s][^\"']*[\"']",
    re.IGNORECASE,
)
PROD_TARGET_PATTERN = re.compile(
    r"(?:BUILD|SAVE\s+IMAGE)\s+[^\n]*(?:\+prod|\+production|\+live|\+staging)\b",
    re.IGNORECASE,
)
UNPINNED_GIT_PATTERN = re.compile(
    r"(?:git\+https?://|git@)[^\s\"']+(?![^\n]*(?:@|#|ref=))",
    re.IGNORECASE,
)
CACHE_SECRET_PATTERN = re.compile(
    r"^\s*CACHE\s+.*(?:password|passwd|secret|api[_-]?key|token|credential)",
    re.IGNORECASE,
)
HOST_PATH_PATTERN = re.compile(
    r"(?:COPY|SAVE\s+ARTIFACT)\s+[^\n]*(?:/etc/passwd|/etc/shadow|\.ssh/|\.aws/)",
    re.IGNORECASE,
)


@dataclass
class EarthlyFinding:
    """A security or best-practice issue in an Earthfile."""

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
class EarthlyInfo:
    """Parsed metadata about an Earthfile."""

    path: str
    version: str = ""
    targets: list[str] = field(default_factory=list)
    base_images: list[str] = field(default_factory=list)
    lines: int = 0


@dataclass
class EarthlyStats:
    """Aggregate Earthly analysis statistics."""

    configs: int
    files: int
    findings: int
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _is_earthly_file(path: Path) -> bool:
    lower = path.name.lower()
    if lower in {name.lower() for name in EARTHLY_FILENAMES}:
        return True
    if lower.endswith(EARTHLY_EXTENSIONS):
        return True
    if lower.endswith((".dockerfile", ".earth")):
        parts = {p.lower() for p in path.parts}
        if parts & set(EARTHLY_DIRS):
            return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4096]
        if EARTHLY_MARKER_PATTERN.search(head):
            return True
    except OSError:
        pass
    return False


class EarthlyAnalyzer:
    """Audit Earthfiles for hardcoded secrets, insecure registries, and risky build settings.

    Scans ``Earthfile`` and ``*.earth`` targets for plaintext ARG/ENV secrets, :latest tags,
    curl-pipe-to-shell, docker.sock mounts, privileged WITH DOCKER, insecure registries,
    and sensitive host path copies.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[EarthlyFinding] | None = None
        self._stats: EarthlyStats | None = None
        self._infos: list[EarthlyInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Earthly configuration paths found in the project."""
        found: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and _is_earthly_file(path):
                found.append(path)
        return found

    def _analyze_file(self, path: Path) -> tuple[list[EarthlyFinding], EarthlyInfo]:
        findings: list[EarthlyFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, EarthlyInfo(path=rel)

        raw_lines = text.splitlines()
        info = EarthlyInfo(path=rel, lines=len(raw_lines))
        has_user = False
        from_count = 0

        for lineno, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^\s*VERSION\s+", line, re.IGNORECASE):
                match = re.search(r"VERSION\s+([\w.]+)", line, re.IGNORECASE)
                if match:
                    info.version = match.group(1)

            if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
                from_count += 1
                match = re.search(r"FROM\s+([^\s]+)", line, re.IGNORECASE)
                if match:
                    info.base_images.append(match.group(1))

            target_match = re.match(r"^([a-zA-Z0-9_.+-]+)\s*:", stripped)
            if target_match and not stripped.startswith(("ARG ", "ENV ", "RUN ", "COPY ", "SAVE ")):
                info.targets.append(target_match.group(1))

            if re.match(r"^\s*USER\s+", line, re.IGNORECASE):
                has_user = True

            if HARDCODED_SECRET_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="hardcoded_secret",
                        severity="high",
                        message="hardcoded secret in ARG/ENV — use Earthly secrets (--secret) or CI secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HARDCODED_ENV_PATTERN.search(line) and re.match(r"^\s*ENV\s+", line, re.IGNORECASE):
                findings.append(
                    EarthlyFinding(
                        kind="hardcoded_env",
                        severity="high",
                        message="hardcoded sensitive ENV value — use --secret or runtime env injection",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if AWS_ACCESS_KEY_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="aws_access_key",
                        severity="high",
                        message="AWS access key in Earthfile — use secret mounts or CI credentials",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_HTTP_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="insecure_http",
                        severity="medium",
                        message="insecure HTTP registry or image reference — use HTTPS registries",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if LATEST_TAG_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="latest_tag",
                        severity="medium",
                        message="image uses :latest tag — pin to immutable digest or version tag",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CURL_PIPE_SHELL_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="curl_pipe_shell",
                        severity="high",
                        message="curl/wget piped to shell — vendor scripts or verify checksums",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if DOCKER_SOCKET_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="docker_socket_mount",
                        severity="high",
                        message="docker.sock mount — avoid host Docker socket in Earthly builds",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PRIVILEGED_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="privileged_mode",
                        severity="high",
                        message="privileged container mode — disable privileged WITH DOCKER targets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if INSECURE_FLAG_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="insecure_flag",
                        severity="medium",
                        message="insecure or allow-privileged flag — remove --insecure and privileged allowances",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PLAIN_ARG_SECRET_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="plain_arg_secret",
                        severity="high",
                        message="sensitive ARG without --secret — use ARG --secret for credentials",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if RUN_SECRET_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="run_secret",
                        severity="high",
                        message="secret value embedded in RUN command — use ARG --secret and mount at runtime",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if PROD_TARGET_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="prod_target",
                        severity="low",
                        message="production-like target name — ensure prod builds use pinned tags and secret stores",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if CACHE_SECRET_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="cache_secret",
                        severity="medium",
                        message="sensitive value in CACHE directive — avoid caching paths with secrets",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if HOST_PATH_PATTERN.search(line):
                findings.append(
                    EarthlyFinding(
                        kind="sensitive_host_path",
                        severity="high",
                        message="copying sensitive host paths — avoid bundling credentials or SSH keys into artifacts",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

            if UNPINNED_GIT_PATTERN.search(line) and (
                "git+" in line.lower() or "git@" in line.lower()
            ):
                findings.append(
                    EarthlyFinding(
                        kind="unpinned_git_source",
                        severity="medium",
                        message="git source without commit/ref pin — pin to immutable revision",
                        path=rel,
                        lineno=lineno,
                        line=line,
                    )
                )

        if from_count > 0 and not has_user:
            findings.append(
                EarthlyFinding(
                    kind="missing_user",
                    severity="low",
                    message="no USER directive — run final stages as non-root when possible",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        return findings, info

    def analyze(self) -> list[EarthlyFinding]:
        """Scan Earthly configurations and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[EarthlyFinding] = []
        infos: list[EarthlyInfo] = []
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
        self._stats = EarthlyStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> EarthlyStats:
        """Return aggregate statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[EarthlyInfo]:
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
        """Scaffold a hardened Earthfile."""
        return """\
VERSION 0.8

base:
    FROM alpine:3.20.3
    RUN apk add --no-cache ca-certificates
    USER nonroot:nonroot
    WORKDIR /app

build:
    FROM +base
    ARG --secret API_TOKEN
    COPY --chown=nonroot:nonroot . .
    RUN --mount=type=secret,id=API_TOKEN \\
        test -n "$API_TOKEN" && echo "build with secret mount"
    SAVE ARTIFACT dist /dist

docker:
    FROM +build
    COPY +build/dist /app/dist
    ENTRYPOINT ["/app/dist/entrypoint"]
    SAVE IMAGE myapp:1.0.0 --push
"""

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Earthly configs: none found"
        return (
            f"Earthly configs: {stats.configs} config(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, {stats.low_severity} low)"
        )

    def to_context(self) -> str:
        """Format analysis as LLM-ready context."""
        self.analyze()
        stats = self.stats
        lines = [
            "Earthly analysis:",
            f"  configs: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            targets = ", ".join(info.targets[:8]) if info.targets else "none"
            lines.append(
                f"  - {info.path}: version={info.version or 'unknown'}, "
                f"{len(info.targets)} target(s), bases: {len(info.base_images)}"
            )
            lines.append(f"    targets: {targets}")
        for finding in (self._findings or [])[:25]:
            lines.append(f"  {finding.format()}")
        if self._findings and len(self._findings) > 25:
            lines.append(f"  ... and {len(self._findings) - 25} more finding(s)")
        return "\n".join(lines)
