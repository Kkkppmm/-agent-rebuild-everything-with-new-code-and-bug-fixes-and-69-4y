"""StreamlitAnalyzer — audit Streamlit apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

STREAMLIT_ENTRY_NAMES = (
    "app.py",
    "Home.py",
    "main.py",
    "streamlit_app.py",
    "src/app.py",
    "src/main.py",
    "pages/Home.py",
)
STREAMLIT_IMPORT_PATTERN = re.compile(
    r"(?:import\s+streamlit|from\s+streamlit|\bst\.)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|openai[_-]?api[_-]?key|"
    r"jwt[_-]?secret|secret_key)\s*=\s*"
    r"(?!\s*(?:os\.environ|st\.secrets|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
UNSAFE_ALLOW_HTML_PATTERN = re.compile(
    r"unsafe_allow_html\s*=\s*True",
    re.IGNORECASE,
)
XSRF_DISABLED_PATTERN = re.compile(
    r"enableXsrfProtection\s*=\s*false|enable_xsrf_protection\s*=\s*False",
    re.IGNORECASE,
)
ENV_EXPOSED_PATTERN = re.compile(
    r"st\.(?:write|markdown|code|json|dataframe|table)\s*\([^)]*(?:os\.environ|environ\[)",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|httpx|urllib)\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
HOST_EXPOSED_PATTERN = re.compile(
    r"(?:address|serverAddress|server\.address)\s*=\s*['\"]0\.0\.0\.0['\"]|"
    r"server\.address\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
FILE_UPLOADER_UNRESTRICTED_PATTERN = re.compile(
    r"st\.file_uploader\s*\([^)]*\)",
    re.IGNORECASE,
)
COMMITTED_SECRET_PATTERN = re.compile(
    r"(?:password|api[_-]?key|secret|token|credential)\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(",
    re.IGNORECASE,
)


@dataclass
class StreamlitFinding:
    """A security or best-practice issue in a Streamlit application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class StreamlitInfo:
    """Parsed metadata about a Streamlit application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_secrets: bool = False
    has_auth: bool = False
    widgets: list[str] = field(default_factory=list)


@dataclass
class StreamlitStats:
    """Aggregate Streamlit analysis statistics."""

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


def _contains_streamlit(text: str) -> bool:
    return bool(STREAMLIT_IMPORT_PATTERN.search(text))


def _looks_like_streamlit_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "streamlit" in text:
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
            if any("streamlit" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in STREAMLIT_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_streamlit(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass

    config_dir = root / ".streamlit"
    if config_dir.is_dir():
        return True

    return False


class StreamlitAnalyzer:
    """Audit Streamlit applications for security and production risks.

    Scans Streamlit entry files and configs for hardcoded secrets, unsafe HTML,
    disabled XSRF protection, environment variable exposure, SSRF targets,
    and unrestricted file uploads.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[StreamlitFinding] | None = None
        self._stats: StreamlitStats | None = None
        self._infos: list[StreamlitInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Streamlit application paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in STREAMLIT_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_streamlit(text):
                    found.append(path)
                    seen.add(path)

        config_dir = self.root / ".streamlit"
        if config_dir.is_dir():
            for path in sorted(config_dir.glob("*.toml")):
                if path not in seen:
                    found.append(path)
                    seen.add(path)

        pages_dir = self.root / "pages"
        if pages_dir.is_dir():
            for path in sorted(pages_dir.glob("*.py")):
                if path not in seen:
                    try:
                        text = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    if _contains_streamlit(text):
                        found.append(path)
                        seen.add(path)

        if _looks_like_streamlit_project(self.root):
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
                if _contains_streamlit(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[StreamlitFinding],
        info: StreamlitInfo,
        *,
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        widget_match = re.search(r"st\.(\w+)\s*\(", stripped)
        if widget_match and widget_match.group(1) not in info.widgets:
            info.widgets.append(widget_match.group(1))

        if "st.secrets" in stripped:
            info.has_secrets = True
        if any(k in stripped for k in ("st.experimental_user", "st.user", "login", "authenticate")):
            info.has_auth = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Streamlit app — use st.secrets or environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Streamlit app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Streamlit app — use HTTPS"),
            (UNSAFE_ALLOW_HTML_PATTERN, "unsafe_allow_html", "high",
             "unsafe_allow_html=True — XSS risk when rendering user content"),
            (XSRF_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF protection disabled — enable enableXsrfProtection in Streamlit config"),
            (ENV_EXPOSED_PATTERN, "env_exposed", "high",
             "environment variables displayed in UI — remove sensitive values from output"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Streamlit app — avoid dynamic code execution"),
            (HOST_EXPOSED_PATTERN, "host_exposed", "medium",
             "Streamlit bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
        ]

        if is_config:
            checks.append(
                (COMMITTED_SECRET_PATTERN, "committed_secret", "high",
                 "secret committed in Streamlit config — use environment variables or secret stores"),
            )

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    StreamlitFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

        if FILE_UPLOADER_UNRESTRICTED_PATTERN.search(stripped) and "type=" not in stripped:
            findings.append(
                StreamlitFinding(
                    kind="file_uploader_unrestricted",
                    severity="medium",
                    message="file_uploader without type restriction — validate uploaded file types",
                    path=rel,
                    lineno=lineno,
                    line=stripped[:120],
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[StreamlitFinding], StreamlitInfo]:
        findings: list[StreamlitFinding] = []
        rel = str(path.relative_to(self.root))
        is_config = path.suffix == ".toml"
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, StreamlitInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = StreamlitInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(
                raw.rstrip(),
                lineno,
                rel,
                findings,
                info,
                is_config=is_config,
            )

        return findings, info

    def analyze(self) -> list[StreamlitFinding]:
        """Scan Streamlit application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[StreamlitFinding] = []
        infos: list[StreamlitInfo] = []
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
        self._stats = StreamlitStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> StreamlitStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[StreamlitInfo]:
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
        """Scaffold a hardened Streamlit app.py entry template."""
        return """\
# Generated by DevAI StreamlitAnalyzer
import os

import streamlit as st


st.set_page_config(page_title="Secure App", layout="wide")


def main() -> None:
    st.title("Secure Streamlit App")
    st.write("Configure secrets via st.secrets or environment variables.")
    api_key = os.environ.get("API_KEY")
    if not api_key:
        st.error("API_KEY environment variable is required")
        st.stop()
    st.success("Application configured securely")


if __name__ == "__main__":
    main()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Streamlit: no application files found"
        return (
            f"Streamlit: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Streamlit application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"widgets={','.join(info.widgets[:5]) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
