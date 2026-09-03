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
    "src/app.py",
    "src/streamlit_app.py",
    "src/main.py",
)
STREAMLIT_IMPORT_PATTERN = re.compile(
    r"(?:from\s+streamlit|import\s+streamlit|\bst\.(?:set_page_config|title|write|markdown|sidebar|"
    r"button|text_input|file_uploader|cache_data|cache_resource|secrets|session_state|components))",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|openai[_-]?api[_-]?key|anthropic[_-]?api[_-]?key)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|st\.secrets|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
UNSAFE_HTML_PATTERN = re.compile(
    r"unsafe_allow_html\s*=\s*True|st\.markdown\s*\([^)]*unsafe_allow_html\s*=\s*True",
    re.IGNORECASE,
)
COMPONENTS_HTML_PATTERN = re.compile(
    r"st\.components\.v1\.html\s*\([^)]*(?:st\.|user_|input_|query|session_state)",
    re.IGNORECASE,
)
CORS_ENABLED_PATTERN = re.compile(
    r"enableCORS\s*=\s*true|enable_cors\s*=\s*true",
    re.IGNORECASE,
)
XSRF_DISABLED_PATTERN = re.compile(
    r"enableXsrfProtection\s*=\s*false|enable_xsrf_protection\s*=\s*false",
    re.IGNORECASE,
)
ERROR_DETAILS_PATTERN = re.compile(
    r"showErrorDetails\s*=\s*true|show_error_details\s*=\s*true",
    re.IGNORECASE,
)
STATIC_SERVING_PATTERN = re.compile(
    r"enableStaticServing\s*=\s*true|enable_static_serving\s*=\s*true",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:address|serverAddress)\s*=\s*[\"']0\.0\.0\.0[\"']|"
    r"--server\.address\s*0\.0\.0\.0",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\.verify_mode\s*=\s*ssl\.CERT_NONE|verify_ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*[=:]\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:urllib|requests|httpx|aiohttp)\.(?:urlopen|get|post|request)\s*\([^)]*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output)|asyncio\.create_subprocess_shell)\s*\(",
    re.IGNORECASE,
)
RUN_ON_SAVE_PATTERN = re.compile(
    r"runOnSave\s*=\s*true|run_on_save\s*=\s*true",
    re.IGNORECASE,
)
TOOLBAR_DEVELOPER_PATTERN = re.compile(
    r"toolbarMode\s*=\s*[\"']developer[\"']|toolbar_mode\s*=\s*[\"']developer[\"']",
    re.IGNORECASE,
)
REFLECTED_INPUT_PATTERN = re.compile(
    r"st\.(?:write|markdown|text|code|json)\s*\([^)]*(?:st\.text_input|st\.text_area|"
    r"st\.query_params|session_state|user_input)",
    re.IGNORECASE,
)
SECRETS_FILE_PATTERN = re.compile(
    r"(?:OPENAI|ANTHROPIC|AWS|API|SECRET|TOKEN|PASSWORD|KEY)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
FILE_UPLOADER_NO_VALIDATION_PATTERN = re.compile(
    r"st\.file_uploader\s*\([^)]*\)(?![\s\S]{0,200}(?:type=|accept_multiple_files|validate))",
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
    has_cache: bool = False
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
    if path.suffix in (".toml", ".json", ".yaml", ".yml", ".conf", ".ini"):
        return path.suffix.lstrip(".")
    return "unknown"


def _contains_streamlit(text: str) -> bool:
    return bool(
        STREAMLIT_IMPORT_PATTERN.search(text)
        or "import streamlit" in text.lower()
        or "from streamlit" in text.lower()
    )


def _looks_like_streamlit_project(root: Path) -> bool:
    streamlit_dir = root / ".streamlit"
    if streamlit_dir.is_dir():
        return True

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
        for page in pages_dir.glob("*.py"):
            try:
                if _contains_streamlit(page.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass

    return False


class StreamlitAnalyzer:
    """Audit Streamlit applications for security and production risks.

    Scans Streamlit entry files, pages, and .streamlit/config.toml for hardcoded
    secrets, unsafe HTML rendering, disabled XSRF protection, open CORS, shell
    command execution, SSRF targets, and committed secrets files.
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

        pages_dir = self.root / "pages"
        if pages_dir.is_dir():
            for page in sorted(pages_dir.glob("*.py")):
                if page in seen:
                    continue
                try:
                    text = page.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_streamlit(text):
                    found.append(page)
                    seen.add(page)

        streamlit_dir = self.root / ".streamlit"
        if streamlit_dir.is_dir():
            for config_name in ("config.toml", "secrets.toml", "credentials.toml"):
                config_path = streamlit_dir / config_name
                if config_path.is_file() and config_path not in seen:
                    found.append(config_path)
                    seen.add(config_path)

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
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        widget_match = re.search(
            r"st\.(text_input|text_area|file_uploader|selectbox|number_input|button)\s*\(",
            stripped,
            re.IGNORECASE,
        )
        if widget_match and widget_match.group(1) not in info.widgets:
            info.widgets.append(widget_match.group(1))

        if "st.secrets" in stripped or "secrets.toml" in stripped:
            info.has_secrets = True
        if "st.cache_data" in stripped or "st.cache_resource" in stripped:
            info.has_cache = True

        if is_config and rel.endswith("secrets.toml"):
            if SECRETS_FILE_PATTERN.search(stripped):
                findings.append(
                    StreamlitFinding(
                        kind="committed_secrets",
                        severity="high",
                        message="secrets.toml contains hardcoded credentials — use environment variables or a secret manager",
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )
            return

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Streamlit app — use st.secrets or environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Streamlit app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Streamlit app — use HTTPS"),
            (UNSAFE_HTML_PATTERN, "unsafe_html", "high",
             "unsafe_allow_html=True — XSS risk when rendering user content"),
            (COMPONENTS_HTML_PATTERN, "components_html", "high",
             "st.components.v1.html with user input — validate and sanitize HTML"),
            (CORS_ENABLED_PATTERN, "cors_enabled", "medium",
             "CORS enabled in Streamlit config — restrict in production"),
            (XSRF_DISABLED_PATTERN, "xsrf_disabled", "high",
             "XSRF protection disabled — enable enableXsrfProtection in config"),
            (ERROR_DETAILS_PATTERN, "error_details_exposed", "medium",
             "showErrorDetails enabled — may leak stack traces to users"),
            (STATIC_SERVING_PATTERN, "static_serving", "medium",
             "static file serving enabled — ensure no sensitive files are exposed"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "Streamlit bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Streamlit app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (RUN_ON_SAVE_PATTERN, "run_on_save", "low",
             "runOnSave enabled — disable in production"),
            (TOOLBAR_DEVELOPER_PATTERN, "developer_toolbar", "low",
             "developer toolbar mode enabled — disable in production"),
            (REFLECTED_INPUT_PATTERN, "reflected_input", "high",
             "user input reflected in output — validate or encode to prevent XSS"),
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
        is_config = path.suffix == ".toml"
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, StreamlitInfo(path=rel)

        if rel.endswith("secrets.toml"):
            findings.append(
                StreamlitFinding(
                    kind="secrets_file_committed",
                    severity="high",
                    message=".streamlit/secrets.toml found in project — never commit secrets to version control",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        raw_lines = raw_text.splitlines()
        info = StreamlitInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info, is_config=is_config)

        if not is_config and FILE_UPLOADER_NO_VALIDATION_PATTERN.search(raw_text):
            if not any(f.kind == "file_uploader_no_validation" for f in findings):
                findings.append(
                    StreamlitFinding(
                        kind="file_uploader_no_validation",
                        severity="medium",
                        message="file_uploader without type restriction — validate uploaded file types",
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


def main() -> None:
    st.set_page_config(page_title="App", layout="wide")
    st.title("Secure Streamlit App")

    # Load secrets from st.secrets or environment — never hardcode
    api_key = os.environ.get("API_KEY") or st.secrets.get("API_KEY", "")

    if not api_key:
        st.error("API_KEY not configured")
        st.stop()

    st.success("App configured securely")


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
