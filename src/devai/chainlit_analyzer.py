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
)
CHAINLIT_IMPORT_PATTERN = re.compile(
    r"(?:import\s+chainlit|from\s+chainlit|\bcl\.)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|openai[_-]?api[_-]?key|"
    r"chainlit[_-]?auth[_-]?secret)\s*=\s*"
    r"(?!\s*(?:os\.environ|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
CORS_WILDCARD_PATTERN = re.compile(
    r"allow_origins\s*=\s*\[[^\]]*['\"]\*['\"]|"
    r"CORS_ALLOW_ORIGINS\s*=\s*\[[^\]]*['\"]\*['\"]",
    re.IGNORECASE,
)
AUTH_SECRET_HARDCODED_PATTERN = re.compile(
    r"CHAINLIT_AUTH_SECRET\s*=\s*['\"][^'\"${}]+['\"]",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:requests|httpx|urllib|aiohttp)\.(?:get|post|request)\s*\(\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(",
    re.IGNORECASE,
)
FILE_UPLOAD_PATTERN = re.compile(
    r"AskFileMessage|cl\.File\s*\(|on_file\s*\(",
    re.IGNORECASE,
)
PUBLIC_DEPLOY_PATTERN = re.compile(
    r"CHAINLIT_URL\s*=\s*['\"]https?://",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|yaml\.load\s*\()",
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
    """Parsed metadata about a Chainlit application file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_auth: bool = False
    has_cors: bool = False
    handlers: list[str] = field(default_factory=list)


@dataclass
class ChainlitStats:
    """Aggregate Chainlit analysis statistics."""

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


def _contains_chainlit(text: str) -> bool:
    return bool(CHAINLIT_IMPORT_PATTERN.search(text))


def _looks_like_chainlit_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "chainlit" in text:
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

    if (root / ".chainlit").is_dir():
        return True

    return False


class ChainlitAnalyzer:
    """Audit Chainlit applications for security and production risks.

    Scans Chainlit entry files and configs for hardcoded secrets, missing auth,
    open CORS, file upload risks, SSRF targets, and unsafe deserialization.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[ChainlitFinding] | None = None
        self._stats: ChainlitStats | None = None
        self._infos: list[ChainlitInfo] | None = None

    def configs(self) -> list[Path]:
        """Return Chainlit application paths found in the project."""
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

        config_dir = self.root / ".chainlit"
        if config_dir.is_dir():
            for path in sorted(config_dir.glob("config.toml")):
                if path not in seen:
                    found.append(path)
                    seen.add(path)

        if _looks_like_chainlit_project(self.root):
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
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        handler_match = re.search(r"@cl\.(on_\w+)", stripped)
        if handler_match and handler_match.group(1) not in info.handlers:
            info.handlers.append(handler_match.group(1))

        if any(
            k in stripped
            for k in (
                "password_auth_callback",
                "oauth_callback",
                "header_auth_callback",
                "@cl.password_auth_callback",
            )
        ):
            info.has_auth = True
        if "allow_origins" in stripped or "CORS_ALLOW_ORIGINS" in stripped:
            info.has_cors = True

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded secret in Chainlit app — use environment variables or secret stores"),
            (AUTH_SECRET_HARDCODED_PATTERN, "auth_secret_hardcoded", "high",
             "hardcoded CHAINLIT_AUTH_SECRET — load from environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in Chainlit app — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL in Chainlit app — use HTTPS"),
            (CORS_WILDCARD_PATTERN, "cors_wildcard", "high",
             "CORS allow_origins includes '*' — restrict to trusted origins"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in Chainlit app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/yaml.load) — use safe loaders"),
            (PUBLIC_DEPLOY_PATTERN, "public_deploy_url", "low",
             "public Chainlit URL configured — ensure authentication is enabled"),
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

        if FILE_UPLOAD_PATTERN.search(stripped) and "accept=" not in stripped:
            findings.append(
                ChainlitFinding(
                    kind="file_upload_unrestricted",
                    severity="medium",
                    message="file upload without accept restriction — validate uploaded file types",
                    path=rel,
                    lineno=lineno,
                    line=stripped[:120],
                )
            )

    def _analyze_file(self, path: Path) -> tuple[list[ChainlitFinding], ChainlitInfo]:
        findings: list[ChainlitFinding] = []
        rel = str(path.relative_to(self.root))
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, ChainlitInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = ChainlitInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if info.handlers and not info.has_auth:
            findings.append(
                ChainlitFinding(
                    kind="missing_auth",
                    severity="high",
                    message="Chainlit handlers without authentication — add password or OAuth auth",
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
  valid_user = os.environ.get("CHAINLIT_USER")
  valid_password = os.environ.get("CHAINLIT_PASSWORD")
  if username == valid_user and password == valid_password:
    return cl.User(identifier=username)
  return None


@cl.on_chat_start
async def start():
  await cl.Message(content="Authenticated session started.").send()
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
                f"handlers={','.join(info.handlers[:5]) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
