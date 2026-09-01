"""GradioAnalyzer — audit Gradio apps and configs for security and production risks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

GRADIO_ENTRY_NAMES = (
    "app.py",
    "main.py",
    "gradio_app.py",
    "demo.py",
    "src/app.py",
    "src/main.py",
    "src/gradio_app.py",
)
GRADIO_IMPORT_PATTERN = re.compile(
    r"(?:from\s+gradio|import\s+gradio|\bgr\.(?:Interface|Blocks|ChatInterface|TabbedInterface|"
    r"Textbox|Button|File|Image|Audio|Video|JSON|HTML|Markdown|launch|load))",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|openai[_-]?api[_-]?key|anthropic[_-]?api[_-]?key|"
    r"huggingface[_-]?token|hf[_-]?token)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|os\.getenv|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
SHARE_ENABLED_PATTERN = re.compile(
    r"(?:share|share_server)\s*=\s*True|\.launch\s*\([^)]*share\s*=\s*True",
    re.IGNORECASE,
)
AUTH_DISABLED_PATTERN = re.compile(
    r"\.launch\s*\([^)]*auth\s*=\s*(?:None|False)|auth\s*=\s*(?:None|False)",
    re.IGNORECASE,
)
DEBUG_ENABLED_PATTERN = re.compile(
    r"(?:debug|show_error|show_api)\s*=\s*True|\.launch\s*\([^)]*(?:debug|show_error)\s*=\s*True",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:server_name|server\.name)\s*=\s*[\"']0\.0\.0\.0[\"']|"
    r"\.launch\s*\([^)]*server_name\s*=\s*[\"']0\.0\.0\.0[\"']",
    re.IGNORECASE,
)
SSL_VERIFY_DISABLED_PATTERN = re.compile(
    r"ssl_verify\s*=\s*False|verify\s*=\s*False|ssl\.verify_mode\s*=\s*ssl\.CERT_NONE",
    re.IGNORECASE,
)
ALLOWED_PATHS_PATTERN = re.compile(
    r"allowed_paths\s*=\s*\[[^\]]*(?:/|\.\.)",
    re.IGNORECASE,
)
UNSAFE_HTML_PATTERN = re.compile(
    r"gr\.HTML\s*\([^)]*(?:user_input|user_text|session_state|query_params|request\.)",
    re.IGNORECASE,
)
REFLECTED_OUTPUT_PATTERN = re.compile(
    r"gr\.(?:Markdown|JSON|Textbox|Code)\s*\([^)]*(?:user_input|user_text|session_state|query_params|request\.)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\.verify_mode\s*=\s*ssl\.CERT_NONE|verify_ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination|endpoint)\s*[=:]\s*['\"]https?://(?:10\.|192\.168\.|"
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
FILE_UPLOAD_NO_TYPE_PATTERN = re.compile(
    r"gr\.File\s*\([^)]*\)(?![\s\S]{0,200}(?:file_types|file_count|type=))",
    re.IGNORECASE,
)
API_OPEN_PATTERN = re.compile(
    r"api_open\s*=\s*True|show_api\s*=\s*True",
    re.IGNORECASE,
)
QUEUE_DISABLED_PATTERN = re.compile(
    r"\.launch\s*\([^)]*enable_queue\s*=\s*False|enable_queue\s*=\s*False",
    re.IGNORECASE,
)
SECRETS_FILE_PATTERN = re.compile(
    r"(?:OPENAI|ANTHROPIC|AWS|API|SECRET|TOKEN|PASSWORD|KEY|HF_TOKEN)\s*=\s*[\"'][^\"']+[\"']",
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
    """Metadata about a scanned Gradio application file."""

    path: str
    lines: int = 0
    file_kind: str = "app"
    components: list[str] = field(default_factory=list)
    has_auth: bool = False
    has_queue: bool = False


@dataclass
class GradioStats:
    """Aggregate statistics from a Gradio application scan."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _contains_gradio(text: str) -> bool:
    return bool(GRADIO_IMPORT_PATTERN.search(text))


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name in ("config.toml", "credentials.toml", "secrets.toml"):
        return "config"
    if path.suffix == ".env":
        return "env"
    return "app"


def _looks_like_gradio_project(root: Path) -> bool:
    for manifest in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"):
        path = root / manifest
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "gradio" in text:
            return True

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

    Scans Gradio entry files and configs for hardcoded secrets, public share links,
    disabled authentication, unsafe HTML rendering, shell command execution, SSRF
    targets, and overly permissive file access.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[GradioFinding] | None = None
        self._stats: GradioStats | None = None
        self._infos: list[GradioInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Gradio application and config paths found in the project."""
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

        gradio_dir = self.root / ".gradio"
        if gradio_dir.is_dir():
            for config_name in ("config.toml", "secrets.toml", "credentials.toml"):
                config_path = gradio_dir / config_name
                if config_path.is_file() and config_path not in seen:
                    found.append(config_path)
                    seen.add(config_path)

        for env_name in (".env", ".env.local", ".env.production"):
            env_path = self.root / env_name
            if env_path.is_file() and env_path not in seen:
                try:
                    text = env_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "gradio" in text.lower() or SECRETS_FILE_PATTERN.search(text):
                    found.append(env_path)
                    seen.add(env_path)

        if _looks_like_gradio_project(self.root):
            for path in sorted(self.root.rglob("*.py")):
                if path in seen:
                    continue
                if any(part.startswith(".") and part != ".gradio" for part in path.parts):
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
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        component_match = re.search(
            r"gr\.(Textbox|Button|File|Image|Audio|Video|JSON|HTML|Markdown|Chatbot|Dropdown)\s*\(",
            stripped,
            re.IGNORECASE,
        )
        if component_match and component_match.group(1) not in info.components:
            info.components.append(component_match.group(1))

        if re.search(r"auth\s*=\s*\[|auth\s*=\s*\(|gr\.auth", stripped, re.IGNORECASE):
            info.has_auth = True
        if "enable_queue" in stripped or "queue(" in stripped:
            info.has_queue = True

        if is_config and rel.endswith(("secrets.toml", "credentials.toml", ".env")):
            if SECRETS_FILE_PATTERN.search(stripped):
                findings.append(
                    GradioFinding(
                        kind="committed_secrets",
                        severity="high",
                        message="config file contains hardcoded credentials — use environment variables or a secret manager",
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )
            return

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Gradio app — use environment variables or a secret manager"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Gradio app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Gradio app — use HTTPS"),
            (SHARE_ENABLED_PATTERN, "share_enabled", "high",
             "share=True creates a public Gradio link — disable in production"),
            (AUTH_DISABLED_PATTERN, "auth_disabled", "medium",
             "authentication disabled — protect sensitive Gradio interfaces with auth"),
            (DEBUG_ENABLED_PATTERN, "debug_enabled", "medium",
             "debug/show_error enabled — may leak stack traces to users"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "Gradio bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
            (SSL_VERIFY_DISABLED_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (ALLOWED_PATHS_PATTERN, "allowed_paths", "medium",
             "allowed_paths may expose filesystem paths — restrict to required directories"),
            (UNSAFE_HTML_PATTERN, "unsafe_html", "high",
             "gr.HTML with user input — validate and sanitize HTML to prevent XSS"),
            (REFLECTED_OUTPUT_PATTERN, "reflected_input", "high",
             "user input reflected in output — validate or encode to prevent XSS"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Gradio app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (API_OPEN_PATTERN, "api_exposed", "medium",
             "API docs exposed — restrict api_open/show_api in production"),
            (QUEUE_DISABLED_PATTERN, "queue_disabled", "low",
             "queue disabled — enable queuing for production workloads"),
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
        is_config = path.suffix in {".toml", ".env"}
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, GradioInfo(path=rel)

        if rel.endswith("secrets.toml"):
            findings.append(
                GradioFinding(
                    kind="secrets_file_committed",
                    severity="high",
                    message=".gradio/secrets.toml found in project — never commit secrets to version control",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        raw_lines = raw_text.splitlines()
        info = GradioInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info, is_config=is_config)

        if not is_config and FILE_UPLOAD_NO_TYPE_PATTERN.search(raw_text):
            if not any(f.kind == "file_upload_no_validation" for f in findings):
                findings.append(
                    GradioFinding(
                        kind="file_upload_no_validation",
                        severity="medium",
                        message="gr.File without file_types restriction — validate uploaded file types",
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


def process_input(text: str) -> str:
    if not text or len(text) > 10_000:
        return "Invalid input"
    return f"Processed: {text[:500]}"


def main() -> None:
    api_key = os.environ.get("API_KEY", "")
    if not api_key:
        raise RuntimeError("API_KEY environment variable is required")

    with gr.Blocks(title="Secure Gradio App") as demo:
        gr.Markdown("# Secure Gradio App")
        input_box = gr.Textbox(label="Input", max_lines=10)
        output_box = gr.Textbox(label="Output", interactive=False)
        submit = gr.Button("Submit")
        submit.click(process_input, inputs=input_box, outputs=output_box)

    demo.launch(
        server_name="127.0.0.1",
        share=False,
        debug=False,
        show_error=False,
        api_open=False,
    )


if __name__ == "__main__":
    main()
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
                f"components={','.join(info.components[:5]) or 'none'}, "
                f"auth={'yes' if info.has_auth else 'no'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
