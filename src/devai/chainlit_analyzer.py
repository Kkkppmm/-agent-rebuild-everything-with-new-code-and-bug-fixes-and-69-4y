"""ChainlitAnalyzer — audit Chainlit apps and configs for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CHAINLIT_ENTRY_NAMES = (
    "app.py",
    "main.py",
    "chainlit_app.py",
    "src/app.py",
    "src/main.py",
    "src/chainlit_app.py",
)
CHAINLIT_IMPORT_PATTERN = re.compile(
    r"(?:from\s+chainlit|import\s+chainlit|\bcl\.(?:on_message|on_chat_start|"
    r"on_settings_update|password_auth|oauth_callback|header_auth|action_callback|"
    r"Message|AskFileMessage|AskUserMessage|Step|set_chat_profiles|run))",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|chainlit[_-]?auth[_-]?secret|openai[_-]?api[_-]?key|"
    r"anthropic[_-]?api[_-]?key|huggingface[_-]?token|hf[_-]?token)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|os\.getenv|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"allow_origins\s*=\s*\[[^\]]*[\"']\*[\"']|allow_origins\s*=\s*[\"']\*[\"']",
    re.IGNORECASE,
)
USER_ENV_EXPOSED_PATTERN = re.compile(
    r"user_env\s*=\s*\[[^\]]*(?:API|SECRET|TOKEN|KEY|PASSWORD|OPENAI|ANTHROPIC)",
    re.IGNORECASE,
)
SPONTANEOUS_UPLOAD_PATTERN = re.compile(
    r"spontaneous_file_upload\s*=\s*\{[^}]*enabled\s*=\s*true",
    re.IGNORECASE,
)
TELEMETRY_DISABLED_PATTERN = re.compile(
    r"enable_telemetry\s*=\s*false",
    re.IGNORECASE,
)
AUTH_SECRET_IN_CONFIG_PATTERN = re.compile(
    r"(?:CHAINLIT_AUTH_SECRET|auth_secret)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
UNSAFE_HTML_PATTERN = re.compile(
    r"cl\.Markdown\s*\([^)]*(?:message\.content|user_input|session|query_params)",
    re.IGNORECASE,
)
REFLECTED_OUTPUT_PATTERN = re.compile(
    r"cl\.(?:Message|Text|Code|Json)\s*\([^)]*(?:message\.content|user_input|session)",
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
FILE_UPLOAD_NO_VALIDATION_PATTERN = re.compile(
    r"cl\.AskFileMessage\s*\([^)]*\)(?![\s\S]{0,200}(?:accept|max_size|max_files))",
    re.IGNORECASE,
)
SECRETS_FILE_PATTERN = re.compile(
    r"(?:OPENAI|ANTHROPIC|AWS|API|SECRET|TOKEN|PASSWORD|KEY|HF_TOKEN|CHAINLIT_AUTH_SECRET)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:debug|show_error|dev_mode)\s*=\s*true|CHAINLIT_DEV\s*=\s*[\"']?1[\"']?",
    re.IGNORECASE,
)
BIND_ALL_PATTERN = re.compile(
    r"(?:host|bind)\s*[=:]\s*[\"']0\.0\.0\.0[\"']|--host\s+0\.0\.0\.0",
    re.IGNORECASE,
)
AUTH_DECORATOR_PATTERN = re.compile(
    r"@cl\.(?:password_auth_callback|oauth_callback|header_auth_callback)",
    re.IGNORECASE,
)


@dataclass
class ChainlitFinding:
    """A security or best-practice issue in a Chainlit application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class ChainlitInfo:
    """Metadata about a scanned Chainlit application file."""

    path: str
    lines: int = 0
    file_kind: str = "app"
    handlers: list[str] = field(default_factory=list)
    has_auth: bool = False
    has_file_upload: bool = False


@dataclass
class ChainlitStats:
    """Aggregate statistics from a Chainlit application scan."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _contains_chainlit(text: str) -> bool:
    return bool(CHAINLIT_IMPORT_PATTERN.search(text))


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name in ("config.toml", "credentials.toml", "secrets.toml"):
        return "config"
    if path.suffix == ".env":
        return "env"
    return "app"


def _looks_like_chainlit_project(root: Path) -> bool:
    chainlit_dir = root / ".chainlit"
    if chainlit_dir.is_dir():
        return True

    for manifest in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"):
        path = root / manifest
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "chainlit" in text:
            return True

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
            deps = data.get("project", {}).get("dependencies", [])
            optional = data.get("project", {}).get("optional-dependencies", {})
            all_deps = list(deps) + [
                item for group in optional.values() for item in group
            ]
            if any("chainlit" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in CHAINLIT_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_chainlit(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass

    return False


class ChainlitAnalyzer:
    """Audit Chainlit applications for security and production risks.

    Scans Chainlit entry files and configs for hardcoded secrets, missing authentication,
    permissive CORS, exposed user environment variables, unsafe file uploads, shell
    command execution, SSRF targets, and committed credential files.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ChainlitFinding] | None = None
        self._stats: ChainlitStats | None = None
        self._infos: list[ChainlitInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Chainlit application and config paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in CHAINLIT_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_chainlit(text):
                    found.append(path)
                    seen.add(path)

        chainlit_dir = self.root / ".chainlit"
        if chainlit_dir.is_dir():
            for config_name in ("config.toml", "secrets.toml", "credentials.toml"):
                config_path = chainlit_dir / config_name
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
                if "chainlit" in text.lower() or SECRETS_FILE_PATTERN.search(text):
                    found.append(env_path)
                    seen.add(env_path)

        if _looks_like_chainlit_project(self.root):
            for path in sorted(self.root.rglob("*.py")):
                if path in seen:
                    continue
                if any(part.startswith(".") and part != ".chainlit" for part in path.parts):
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
                if _contains_chainlit(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[ChainlitFinding],
        info: ChainlitInfo,
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        handler_match = re.search(
            r"@cl\.(on_message|on_chat_start|on_settings_update|action_callback|step)",
            stripped,
            re.IGNORECASE,
        )
        if handler_match and handler_match.group(1) not in info.handlers:
            info.handlers.append(handler_match.group(1))

        if AUTH_DECORATOR_PATTERN.search(stripped):
            info.has_auth = True
        if "AskFileMessage" in stripped:
            info.has_file_upload = True

        if is_config and rel.endswith((".toml", ".env")):
            if SECRETS_FILE_PATTERN.search(stripped):
                findings.append(
                    ChainlitFinding(
                        kind="committed_secrets",
                        severity="high",
                        message="config file contains hardcoded credentials — use environment variables or a secret manager",
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Chainlit app — use environment variables or a secret manager"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Chainlit app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Chainlit app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "allow_origins includes wildcard — restrict CORS to trusted origins"),
            (USER_ENV_EXPOSED_PATTERN, "user_env_exposed", "high",
             "user_env exposes sensitive environment variables to the client"),
            (AUTH_SECRET_IN_CONFIG_PATTERN, "auth_secret_hardcoded", "high",
             "CHAINLIT_AUTH_SECRET hardcoded — use environment variables"),
            (UNSAFE_HTML_PATTERN, "unsafe_html", "high",
             "cl.Markdown with user input — validate and sanitize to prevent XSS"),
            (REFLECTED_OUTPUT_PATTERN, "reflected_input", "high",
             "user input reflected in output — validate or encode to prevent XSS"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Chainlit app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (SPONTANEOUS_UPLOAD_PATTERN, "spontaneous_upload", "medium",
             "spontaneous file upload enabled — restrict file types and sizes"),
            (DEBUG_MODE_PATTERN, "debug_enabled", "medium",
             "debug mode enabled — may leak stack traces to users"),
            (BIND_ALL_PATTERN, "bind_all_interfaces", "medium",
             "Chainlit bound to 0.0.0.0 — ensure firewall and reverse proxy are configured"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    ChainlitFinding(
                        kind=kind,
                        severity=severity,
                        message=message,
                        path=rel,
                        lineno=lineno,
                        line=stripped[:120],
                    )
                )

        if is_config:
            return

    def _analyze_file(self, path: Path) -> tuple[list[ChainlitFinding], ChainlitInfo]:
        findings: list[ChainlitFinding] = []
        rel = str(path.relative_to(self.root))
        is_config = path.suffix in {".toml", ".env"}
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ChainlitInfo(path=rel)

        if rel.endswith("secrets.toml"):
            findings.append(
                ChainlitFinding(
                    kind="secrets_file_committed",
                    severity="high",
                    message=".chainlit/secrets.toml found in project — never commit secrets to version control",
                    path=rel,
                    lineno=1,
                    line="",
                )
            )

        raw_lines = raw_text.splitlines()
        info = ChainlitInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info, is_config=is_config)

        if not is_config and not info.has_auth and AUTH_DECORATOR_PATTERN.search(raw_text) is None:
            if "@cl.on_message" in raw_text or "@cl.on_chat_start" in raw_text:
                findings.append(
                    ChainlitFinding(
                        kind="missing_auth",
                        severity="medium",
                        message="no authentication decorator found — protect Chainlit apps with password, OAuth, or header auth",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if not is_config and FILE_UPLOAD_NO_VALIDATION_PATTERN.search(raw_text):
            if not any(f.kind == "file_upload_no_validation" for f in findings):
                findings.append(
                    ChainlitFinding(
                        kind="file_upload_no_validation",
                        severity="medium",
                        message="cl.AskFileMessage without accept/max_size restriction — validate uploaded files",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[ChainlitFinding]:
        """Scan Chainlit application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[ChainlitFinding] = []
        infos: list[ChainlitInfo] = []
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
        self._stats = ChainlitStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> ChainlitStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[ChainlitInfo]:
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
        """Scaffold a hardened Chainlit app.py entry template."""
        return """\
# Generated by DevAI ChainlitAnalyzer
import os

import chainlit as cl


@cl.password_auth_callback
def auth_callback(username: str, password: str):
    valid_user = os.environ.get("CHAINLIT_USER", "")
    valid_pass = os.environ.get("CHAINLIT_PASSWORD", "")
    if username == valid_user and password == valid_pass:
        return cl.User(identifier=username, metadata={"role": "user"})
    return None


@cl.on_chat_start
async def on_chat_start():
    await cl.Message(content="Welcome! How can I help you today?").send()


@cl.on_message
async def on_message(message: cl.Message):
    user_text = (message.content or "").strip()
    if not user_text or len(user_text) > 10_000:
        await cl.Message(content="Invalid input.").send()
        return
    await cl.Message(content=f"Processed: {user_text[:500]}").send()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "Chainlit: no application files found"
        return (
            f"Chainlit: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "Chainlit application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"handlers={','.join(info.handlers[:5]) or 'none'}, "
                f"auth={'yes' if info.has_auth else 'no'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
