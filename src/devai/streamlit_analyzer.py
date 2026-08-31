"""StreamlitAnalyzer — audit Streamlit apps for secrets, unsafe HTML, XSRF, and SSRF risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

STREAMLIT_ENTRY_NAMES = (
    "app.py",
    "main.py",
    "streamlit_app.py",
    "pages/home.py",
    "src/app.py",
    "src/main.py",
)
STREAMLIT_IMPORT_PATTERN = re.compile(
    r"(?:from\s+streamlit|import\s+streamlit|\bst\.)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|openai[_-]?api[_-]?key|"
    r"anthropic[_-]?api[_-]?key)\s*=\s*"
    r"(?!\s*(?:os\.environ|st\.secrets|getenv|SecretStr))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
UNSAFE_HTML_PATTERN = re.compile(
    r"st\.markdown\s*\([^)]*unsafe_allow_html\s*=\s*True",
    re.IGNORECASE,
)
XSRF_DISABLED_PATTERN = re.compile(
    r"enableXsrfProtection\s*=\s*false|enable_xsrf_protection\s*=\s*false",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"enableCORS\s*=\s*true[\s\S]{0,80}(?:\[\s*['\"]\*['\"]|origins\s*=\s*\[[^\]]*['\"]\*['\"])|"
    r"server\.enableCORS\s*=\s*true",
    re.IGNORECASE,
)
COMMITTED_SECRET_PATTERN = re.compile(
    r"(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET|password|secret)\s*=\s*[\"'][^\"'\s${}]+[\"']",
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
UNRESTRICTED_UPLOAD_PATTERN = re.compile(
    r"st\.file_uploader\s*\([^)]*\)(?!.*type\s*=)",
    re.IGNORECASE,
)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
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
    has_auth: bool = False
    has_secrets: bool = False
    has_xsrf: bool = False
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
    return False


class StreamlitAnalyzer:
    """Audit Streamlit applications for security and production risks.

    Scans Streamlit entry files and config for hardcoded secrets, unsafe HTML,
    disabled XSRF protection, open CORS, unrestricted file uploads, and SSRF targets.
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

        config_path = self.root / ".streamlit" / "config.toml"
        if config_path.is_file() and config_path not in seen:
            found.append(config_path)
            seen.add(config_path)

        secrets_path = self.root / ".streamlit" / "secrets.toml"
        if secrets_path.is_file() and secrets_path not in seen:
            found.append(secrets_path)
            seen.add(secrets_path)

        if _looks_like_streamlit_project(self.root):
            for path in sorted(self.root.rglob("*.py")):
                if path in seen:
                    continue
                if any(part.startswith(".") and part != ".streamlit" for part in path.parts):
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

        for widget in ("st.text_input", "st.file_uploader", "st.chat_input", "st.button"):
            if widget in stripped and widget not in info.widgets:
                info.widgets.append(widget)

        if any(k in stripped for k in ("st.secrets", "authenticate", "stauth", "login")):
            info.has_auth = True
        if "st.secrets" in stripped:
            info.has_secrets = True
        if "enableXsrfProtection" in stripped or "enable_xsrf_protection" in stripped:
            info.has_xsrf = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Streamlit app — use st.secrets or environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Streamlit app — rotate and use secret stores"),
            (UNSAFE_HTML_PATTERN, "unsafe_html", "high",
             "st.markdown with unsafe_allow_html=True — XSS risk"),
            (XSRF_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF protection disabled in Streamlit config — CSRF risk"),
            (CORS_WILDCARD_PATTERN, "cors_enabled", "medium",
             "CORS enabled in Streamlit — ensure origins are restricted"),
            (COMMITTED_SECRET_PATTERN, "committed_secret", "high",
             "secret value in config file — use environment variables or st.secrets"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Streamlit app — avoid dynamic code execution"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Streamlit app — use HTTPS"),
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

        if UNRESTRICTED_UPLOAD_PATTERN.search(raw_text):
            findings.append(
                StreamlitFinding(
                    kind="unrestricted_upload",
                    severity="medium",
                    message="st.file_uploader without type restriction — validate uploaded files",
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

# Load secrets from st.secrets or environment variables
api_key = st.secrets.get("OPENAI_API_KEY", os.environ.get("OPENAI_API_KEY", ""))

st.title("Secure Streamlit App")

uploaded = st.file_uploader("Upload a file", type=["csv", "txt", "pdf"])
if uploaded is not None:
    st.write(f"Received: {uploaded.name}")

# Never use unsafe_allow_html=True with untrusted input
st.markdown("Welcome to the secure app.")
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
