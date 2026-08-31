"""GradioAnalyzer — audit Gradio apps for secrets, share links, auth, and SSRF risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

GRADIO_ENTRY_NAMES = (
    "app.py",
    "main.py",
    "gradio_app.py",
    "demo.py",
    "src/app.py",
    "src/main.py",
)
GRADIO_IMPORT_PATTERN = re.compile(
    r"(?:from\s+gradio|import\s+gradio|\bgr\.)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|hf[_-]?token|"
    r"openai[_-]?api[_-]?key)\s*=\s*"
    r"(?!\s*(?:os\.environ|getenv|SecretStr))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
SHARE_ENABLED_PATTERN = re.compile(
    r"\.launch\s*\([^)]*share\s*=\s*True",
    re.IGNORECASE | re.DOTALL,
)
AUTH_NONE_PATTERN = re.compile(
    r"\.launch\s*\([^)]*auth\s*=\s*None",
    re.IGNORECASE | re.DOTALL,
)
NO_AUTH_PATTERN = re.compile(
    r"\.launch\s*\(\s*\)(?!.*auth\s*=)",
    re.IGNORECASE,
)
ALLOWED_PATHS_ROOT_PATTERN = re.compile(
    r"allowed_paths\s*=\s*\[[^\]]*['\"](/|/tmp|\.\.)['\"]",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination|endpoint)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:httpx|requests|aiohttp)\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SERVER_NAME_EXPOSED_PATTERN = re.compile(
    r"\.launch\s*\([^)]*server_name\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE | re.DOTALL,
)
API_OPEN_PATTERN = re.compile(
    r"api_open\s*=\s*True|show_api\s*=\s*True",
    re.IGNORECASE,
)


@dataclass
class GradioFinding:
    """A security or best-practice issue in a Gradio application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class GradioInfo:
    """Parsed metadata about a Gradio application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_auth: bool = False
    has_share: bool = False
    components: list[str] = field(default_factory=list)


@dataclass
class GradioStats:
    """Aggregate Gradio analysis statistics."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _file_kind(path: Path) -> str:
    if path.suffix == ".py":
        return "python"
    if path.suffix in (".toml", ".json", ".yaml", ".yml"):
        return path.suffix.lstrip(".")
    return "unknown"


def _contains_gradio(text: str) -> bool:
    return bool(GRADIO_IMPORT_PATTERN.search(text))


def _looks_like_gradio_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "gradio" in text:
                return True
        except OSError:
            continue

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
            deps = data.get("project", {}).get("dependencies", [])
            optional = data.get("project", {}).get("optional-dependencies", {})
            all_deps = list(deps) + [item for group in optional.values() for item in group]
            if any("gradio" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in GRADIO_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_gradio(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class GradioAnalyzer:
    """Audit Gradio applications for security and production risks.

    Scans Gradio entry files for hardcoded secrets, public share links,
    missing authentication, unsafe allowed_paths, and SSRF targets.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GradioFinding] | None = None
        self._stats: GradioStats | None = None
        self._infos: list[GradioInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Gradio application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in GRADIO_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_gradio(text):
                    found.append(path)
                    seen.add(path)

        if _looks_like_gradio_project(self.root):
            for path in sorted(self.root.rglob("*.py")):
                if path in seen:
                    continue
                if any(part.startswith(".") for part in path.parts):
                    continue
                if any(
                    part in {"venv", ".venv", "node_modules", "__pycache__", ".tox", ".mypy_cache"}
                    for part in path.parts
                ):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_gradio(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[GradioFinding],
        info: GradioInfo,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for component in ("gr.Interface", "gr.Blocks", "gr.ChatInterface", "gr.TabbedInterface"):
            if component in stripped and component not in info.components:
                info.components.append(component)

        if "auth=" in stripped and "auth=None" not in stripped:
            info.has_auth = True
        if "share=True" in stripped:
            info.has_share = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Gradio app — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Gradio app — rotate and use secret stores"),
            (SHARE_ENABLED_PATTERN, "share_enabled", "high",
             "Gradio share=True exposes app via public tunnel — disable in production"),
            (AUTH_NONE_PATTERN, "auth_disabled", "high",
             "Gradio auth=None — add authentication before deploying"),
            (ALLOWED_PATHS_ROOT_PATTERN, "allowed_paths_unsafe", "high",
             "allowed_paths includes root or parent — path traversal risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Gradio app — avoid dynamic code execution"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Gradio app — use HTTPS"),
            (SERVER_NAME_EXPOSED_PATTERN, "server_exposed", "medium",
             "Gradio bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (API_OPEN_PATTERN, "api_exposed", "medium",
             "Gradio API docs exposed — restrict in production"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    GradioFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

    def _analyze_file(self, path: Path) -> tuple[list[GradioFinding], GradioInfo]:
        findings: list[GradioFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GradioInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = GradioInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if NO_AUTH_PATTERN.search(raw_text) and ".launch(" in raw_text:
            if not info.has_auth and not any(f.kind == "auth_disabled" for f in findings):
                findings.append(
                    GradioFinding(
                        kind="no_auth",
                        severity="medium",
                        message="Gradio launched without authentication — add auth= for production",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[GradioFinding]:
        """Scan Gradio application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[GradioFinding] = []
        infos: list[GradioInfo] = []
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
        self._stats = GradioStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> GradioStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[GradioInfo]:
        if self._infos is None:
            self.analyze()
        return self._infos  # type: ignore[return-value]

    def health_score(self) -> float:
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
        """Scaffold a hardened Gradio app.py entry template."""
        return """\
# Generated by DevAI GradioAnalyzer
import os

import gradio as gr


def greet(name: str) -> str:
    return f"Hello, {name}!"


demo = gr.Interface(fn=greet, inputs="text", outputs="text")

if __name__ == "__main__":
    demo.launch(
        auth=(os.environ["GRADIO_USER"], os.environ["GRADIO_PASSWORD"]),
        share=False,
        server_name="127.0.0.1",
        show_api=False,
    )
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Gradio: no application files found"
        return (
            f"Gradio: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Gradio application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"components={','.join(info.components[:5]) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
