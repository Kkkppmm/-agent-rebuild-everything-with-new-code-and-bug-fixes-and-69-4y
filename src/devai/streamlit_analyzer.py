"""StreamlitAnalyzer — audit Streamlit apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

STREAMLIT_ENTRY_NAMES = (
    "app.py",
    "streamlit_app.py",
    "main.py",
    "Home.py",
    "pages/Home.py",
    "src/app.py",
    "src/streamlit_app.py",
)
STREAMLIT_IMPORT_PATTERN = re.compile(
    r"(?:from\s+streamlit|import\s+streamlit|\bst\.)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|openai[_-]?api[_-]?key|"
    r"anthropic[_-]?api[_-]?key)\s*=\s*"
    r"(?!\s*(?:os\.environ|st\.secrets|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
UNSAFE_HTML_PATTERN = re.compile(
    r"(?:st\.markdown|st\.write|st\.html)\s*\([^)]*unsafe_allow_html\s*=\s*True",
    re.IGNORECASE,
)
XSRF_DISABLED_PATTERN = re.compile(
    r"enableXsrfProtection\s*=\s*false|enable_xsrf_protection\s*=\s*false",
    re.IGNORECASE,
)
CORS_DISABLED_PATTERN = re.compile(
    r"enableCORS\s*=\s*false|enable_cors\s*=\s*false",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"(?:allowedOrigins|allowed_origins)\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|httpx)\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(",
    re.IGNORECASE,
)
COMMITTED_SECRET_PATTERN = re.compile(
    r"^(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|password|secret)\s*=\s*"
    r"[^\s#]+",
    re.IGNORECASE | re.MULTILINE,
)
SESSION_STATE_SECRET_PATTERN = re.compile(
    r"st\.session_state\[[^\]]+\]\s*=\s*['\"][^'\"]+['\"]",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
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
    uses_unsafe_html: bool = False
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
            all_deps = list(deps) + [
                item for group in optional.values() for item in group
            ]
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

    config = root / ".streamlit" / "config.toml"
    return config.is_file()


class StreamlitAnalyzer:
    """Audit Streamlit applications for security and production risks.

    Scans Streamlit apps and config for hardcoded secrets, unsafe HTML rendering,
    disabled XSRF protection, committed secrets files, SSRF targets, and shell commands.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[StreamlitFinding] | None = None
        self._stats: StreamlitStats | None = None
        self._infos: list[StreamlitInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Streamlit application and config paths found in the project."""
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

        for config_name in (".streamlit/config.toml", ".streamlit/secrets.toml"):
            path = self.root / config_name
            if path.is_file() and path not in seen:
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
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        widget_match = re.search(r"\bst\.(\w+)\s*\(", stripped)
        if widget_match:
            widget = widget_match.group(1)
            if widget not in info.widgets:
                info.widgets.append(widget)

        if "st.secrets" in stripped:
            info.has_secrets = True
        if any(k in stripped for k in ("st.user", "st.experimental_user", "login", "authenticate")):
            info.has_auth = True
        if "unsafe_allow_html=True" in stripped.replace(" ", ""):
            info.uses_unsafe_html = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Streamlit app — use st.secrets or environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Streamlit app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Streamlit app — use HTTPS"),
            (UNSAFE_HTML_PATTERN, "unsafe_html", "high",
             "unsafe_allow_html=True — XSS risk when rendering user-controlled content"),
            (XSRF_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF protection disabled in Streamlit config — enable enableXsrfProtection"),
            (CORS_DISABLED_PATTERN, "cors_disabled", "medium",
             "CORS disabled in Streamlit config — verify this is intentional"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allowedOrigins includes '*' — restrict to trusted origins"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Streamlit app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (SESSION_STATE_SECRET_PATTERN, "session_state_secret", "medium",
             "secret stored in st.session_state — use st.secrets instead"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
        ]

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

    def _analyze_file(self, path: Path) -> tuple[list[StreamlitFinding], StreamlitInfo]:
        findings: list[StreamlitFinding] = []
        rel = str(path.relative_to(self.root))
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
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if path.name == "secrets.toml" and COMMITTED_SECRET_PATTERN.search(raw_text):
            if not any(f.kind == "committed_secret" for f in findings):
                findings.append(
                    StreamlitFinding(
                        kind="committed_secret",
                        severity="high",
                        message="secrets.toml contains plaintext credentials — never commit secrets files",
                        path=rel,
                        lineno=1,
                        line="",
                    )
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
    api_key = st.secrets.get("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        st.error("Configure OPENAI_API_KEY via st.secrets or environment variables.")
        st.stop()
    st.success("Ready")


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
