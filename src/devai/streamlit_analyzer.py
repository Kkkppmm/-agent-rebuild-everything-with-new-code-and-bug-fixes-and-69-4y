"""StreamlitAnalyzer — audit Streamlit apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

STREAMLIT_ENTRY_NAMES = (
    "streamlit_app.py",
    "app.py",
    "main.py",
    "Home.py",
    "home.py",
    "src/streamlit_app.py",
    "src/app.py",
    "src/main.py",
    "pages/Home.py",
)
STREAMLIT_IMPORT_PATTERN = re.compile(
    r"(?:from\s+streamlit|import\s+streamlit|^\s*st\s*=)",
    re.IGNORECASE | re.MULTILINE,
)
STREAMLIT_USAGE_PATTERN = re.compile(
    r"\bst\.(?:write|markdown|title|header|subheader|button|text_input|sidebar|set_page_config)\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|openai[_-]?api[_-]?key|"
    r"anthropic[_-]?api[_-]?key)\s*=\s*"
    r"(?!\s*(?:os\.environ|st\.secrets|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
ST_SECRETS_HARDCODED_PATTERN = re.compile(
    r"st\.secrets\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*=\s*['\"][^'\"${}]+['\"]",
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
IFRAME_USER_INPUT_PATTERN = re.compile(
    r"components\.v1\.iframe\s*\([^)]*(?:query_params|text_input|session_state|request)",
    re.IGNORECASE,
)
HTML_COMPONENT_PATTERN = re.compile(
    r"components\.v1\.html\s*\([^)]*(?:query_params|text_input|session_state|request)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|urllib|httpx)\.(?:get|post|request|urlopen)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)
FILE_UPLOADER_UNRESTRICTED_PATTERN = re.compile(
    r"st\.file_uploader\s*\([^)]*\)(?!.*type\s*=)",
    re.IGNORECASE,
)
DOWNLOAD_BUTTON_PATH_PATTERN = re.compile(
    r"st\.download_button\s*\([^)]*(?:text_input|query_params|session_state|request)",
    re.IGNORECASE,
)
CONNECTION_HARDCODED_PATTERN = re.compile(
    r"st\.connection\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:type\s*=\s*['\"][^'\"]+['\"]\s*,\s*)?"
    r"(?:url|host|password|token)\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
AUTH_DISABLED_PATTERN = re.compile(
    r"(?:enableXsrfProtection|server\.enableXsrfProtection)\s*=\s*false",
    re.IGNORECASE,
)
CORS_DISABLED_PATTERN = re.compile(
    r"(?:enableCORS|server\.enableCORS)\s*=\s*false",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:server\.address|address)\s*=\s*['\"]0\.0\.0\.0['\"]|"
    r"serverAddress\s*=\s*['\"]0\.0\.0\.0['\"]",
    re.IGNORECASE,
)
SECRETS_TOML_VALUE_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+\s*=\s*['\"][^'\"${}][^'\"]{3,}['\"]",
    re.MULTILINE,
)
COMMITTED_SECRET_KEYWORDS = re.compile(
    r"(?:password|secret|api[_-]?key|token|credential|private[_-]?key)\s*=",
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
    has_page_config: bool = False
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
    return bool(
        STREAMLIT_IMPORT_PATTERN.search(text)
        or STREAMLIT_USAGE_PATTERN.search(text)
        or "import streamlit" in text.lower()
    )


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

    pages_dir = root / "pages"
    if pages_dir.is_dir():
        for path in pages_dir.glob("*.py"):
            try:
                if _contains_streamlit(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class StreamlitAnalyzer:
    """Audit Streamlit applications for security and production risks.

    Scans Streamlit entry files, pages, and .streamlit config for hardcoded secrets,
    unsafe HTML rendering, disabled XSRF protection, committed secrets.toml, SSRF
    targets, and shell command execution.
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

            pages_dir = self.root / "pages"
            if pages_dir.is_dir():
                for path in sorted(pages_dir.glob("*.py")):
                    if path in seen:
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

        for widget in ("text_input", "file_uploader", "download_button", "button", "selectbox"):
            if f"st.{widget}" in stripped:
                if widget not in info.widgets:
                    info.widgets.append(widget)

        if "st.secrets" in stripped:
            info.has_secrets = True
        if "st.set_page_config" in stripped:
            info.has_page_config = True
        if any(k in stripped for k in ("stauth", "authenticate", "login", "logout")):
            info.has_auth = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Streamlit app — use st.secrets or environment variables"),
            (ST_SECRETS_HARDCODED_PATTERN, "st_secrets_assignment", "high",
             "assigning to st.secrets in code — load secrets from .streamlit/secrets.toml or env"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Streamlit app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Streamlit app — use HTTPS"),
            (UNSAFE_HTML_PATTERN, "unsafe_html", "high",
             "unsafe_allow_html=True — XSS risk; sanitize user content before rendering"),
            (IFRAME_USER_INPUT_PATTERN, "iframe_user_input", "high",
             "iframe with user-controlled input — SSRF/XSS risk"),
            (HTML_COMPONENT_PATTERN, "html_component_user_input", "high",
             "HTML component with user-controlled input — XSS risk"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Streamlit app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (FILE_UPLOADER_UNRESTRICTED_PATTERN, "file_uploader_unrestricted", "medium",
             "file_uploader without type restriction — limit accepted file types"),
            (DOWNLOAD_BUTTON_PATH_PATTERN, "download_button_user_path", "high",
             "download_button with user-controlled path — validate file paths"),
            (CONNECTION_HARDCODED_PATTERN, "connection_hardcoded", "high",
             "st.connection with hardcoded credentials — use st.secrets"),
            (AUTH_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF protection disabled in Streamlit config — enable enableXsrfProtection"),
            (CORS_DISABLED_PATTERN, "cors_disabled", "medium",
             "CORS disabled in Streamlit config — review server.enableCORS setting"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "Streamlit bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
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

    def _analyze_config_toml(self, path: Path) -> list[StreamlitFinding]:
        findings: list[StreamlitFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        if path.name == "secrets.toml":
            for lineno, raw in enumerate(text.splitlines(), start=1):
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if SECRETS_TOML_VALUE_PATTERN.match(stripped) and COMMITTED_SECRET_KEYWORDS.search(stripped):
                    findings.append(
                        StreamlitFinding(
                            kind="committed_secrets",
                            severity="high",
                            message="secrets.toml contains credential values — never commit secrets to VCS",
                            path=rel,
                            lineno=lineno,
                            line=stripped[:120],
                        )
                    )
            return findings

        for lineno, raw in enumerate(text.splitlines(), start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, StreamlitInfo(path=rel))
        return findings

    def _analyze_file(self, path: Path) -> tuple[list[StreamlitFinding], StreamlitInfo]:
        if path.suffix == ".toml" and ".streamlit" in path.parts:
            findings = self._analyze_config_toml(path)
            return findings, StreamlitInfo(path=str(path.relative_to(self.root)), file_kind="toml")

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
        """Scaffold a hardened Streamlit app entry template."""
        return """\
# Generated by DevAI StreamlitAnalyzer
import os

import streamlit as st


def main() -> None:
    st.set_page_config(page_title="Secure App", layout="wide")

    # Load secrets from .streamlit/secrets.toml or environment variables
    api_key = st.secrets.get("API_KEY", os.environ.get("API_KEY"))

    st.title("Secure Streamlit App")
    user_input = st.text_input("Enter text")
    if user_input:
        # Never use unsafe_allow_html with user content
        st.markdown(user_input)


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
