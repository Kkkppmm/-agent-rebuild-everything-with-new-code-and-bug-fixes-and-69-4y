"""LlamaIndexAnalyzer — audit LlamaIndex RAG pipelines for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LLAMAINDEX_ENTRY_NAMES = (
    "index.py",
    "app.py",
    "main.py",
    "rag.py",
    "query.py",
    "chat.py",
    "src/index.py",
    "src/app.py",
    "src/main.py",
    "src/rag.py",
)
LLAMAINDEX_IMPORT_PATTERN = re.compile(
    r"(?:from\s+llama_index|import\s+llama_index|from\s+llama_index\.|"
    r"\b(?:VectorStoreIndex|ServiceContext|Settings|SimpleDirectoryReader|"
    r"SQLDatabase|NLSQLTableQueryEngine|QueryEngine|RetrieverQueryEngine|"
    r"OpenAI|OpenAIEmbedding|load_index_from_storage|StorageContext))\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|openai[_-]?api[_-]?key|anthropic[_-]?api[_-]?key|"
    r"huggingface[_-]?token|hf[_-]?token|cohere[_-]?api[_-]?key)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|os\.getenv|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
INLINE_API_KEY_PATTERN = re.compile(
    r"(?:OpenAI|OpenAIEmbedding|Anthropic|Cohere|HuggingFaceInferenceAPI|"
    r"AzureOpenAI|Gemini)\s*\([^)]*api[_-]?key\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
DANGEROUS_DESERIALIZATION_PATTERN = re.compile(
    r"allow_dangerous_deserialization\s*=\s*True",
    re.IGNORECASE,
)
PICKLE_PATTERN = re.compile(
    r"\b(?:pickle\.(?:load|loads)|dill\.(?:load|loads))\s*\(",
    re.IGNORECASE,
)
SQL_RAW_PATTERN = re.compile(
    r"(?:NLSQLTableQueryEngine|SQLDatabase|text\s*\(\s*f?[\"']SELECT|"
    r"execute\s*\(\s*f?[\"']SELECT|raw_sql\s*=)",
    re.IGNORECASE,
)
SQL_INJECTION_PATTERN = re.compile(
    r"(?:f[\"']SELECT|\.format\s*\([^)]*\).*SELECT|%\s*\([^)]*\).*SELECT|"
    r"query\s*\+\s*|sql\s*\+\s*)",
    re.IGNORECASE,
)
WEB_LOADER_PATTERN = re.compile(
    r"(?:SimpleWebPageReader|TrafilaturaWebReader|BeautifulSoupWebReader|"
    r"RssReader|AsyncWebPageReader|SitemapReader|WholeSiteReader)\s*\(",
    re.IGNORECASE,
)
USER_URL_LOADER_PATTERN = re.compile(
    r"(?:SimpleWebPageReader|TrafilaturaWebReader|BeautifulSoupWebReader|"
    r"download_loader|load_data)\s*\([^)]*(?:user_|input_|query|request\.|params)",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\.verify_mode\s*=\s*ssl\.CERT_NONE|verify_ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination|endpoint|website|link)\s*[=:]\s*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:urllib|requests|httpx|aiohttp)\.(?:urlopen|get|post|request)\s*\([^)]*['\"]https?://(?:10\.|"
    r"192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
SHELL_COMMAND_PATTERN = re.compile(
    r"\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output)|asyncio\.create_subprocess_shell)\s*\(",
    re.IGNORECASE,
)
CODE_EXECUTOR_PATTERN = re.compile(
    r"(?:CodeExecutor|PythonREPLTool|FunctionTool|QueryEngineTool)\s*\(",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:SimpleDirectoryReader|PDFReader|DocxReader|CSVReader)\s*\([^)]*(?:user_|input_|query|request\.)",
    re.IGNORECASE,
)
SECRETS_FILE_PATTERN = re.compile(
    r"(?:OPENAI|ANTHROPIC|AWS|API|SECRET|TOKEN|PASSWORD|KEY|HF_TOKEN|COHERE)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
VERBOSE_LOGGING_PATTERN = re.compile(
    r"(?:verbose\s*=\s*True|log_level\s*=\s*[\"']DEBUG[\"']|"
    r"LlamaDebugHandler|CallbackManager\s*\([^)]*verbose\s*=\s*True)",
    re.IGNORECASE,
)
GLOBAL_SETTINGS_INLINE_PATTERN = re.compile(
    r"Settings\.(?:llm|embed_model|chunk_size|callback_manager)\s*=\s*",
    re.IGNORECASE,
)


@dataclass
class LlamaIndexFinding:
    """A security or best-practice issue in a LlamaIndex application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class LlamaIndexInfo:
    """Metadata about a scanned LlamaIndex application file."""

    path: str
    lines: int = 0
    file_kind: str = "python"
    has_query_engine: bool = False
    has_sql_retriever: bool = False
    has_web_loader: bool = False
    components: list[str] = field(default_factory=list)


@dataclass
class LlamaIndexStats:
    """Aggregate statistics from a LlamaIndex scan."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _contains_llamaindex(text: str) -> bool:
    return bool(LLAMAINDEX_IMPORT_PATTERN.search(text))


def _file_kind(path: Path) -> str:
    if path.suffix == ".py":
        return "python"
    if path.suffix in {".toml", ".yaml", ".yml"}:
        return "config"
    if path.name.startswith(".env"):
        return "env"
    return "other"


def _looks_like_llamaindex_project(root: Path) -> bool:
    for req_name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        req_path = root / req_name
        if not req_path.is_file():
            continue
        try:
            text = req_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "llama-index" in text.lower() or "llama_index" in text.lower():
            return True
        if req_name == "pyproject.toml":
            try:
                data = tomllib.loads(text)
                deps = data.get("project", {}).get("dependencies", [])
                optional = data.get("project", {}).get("optional-dependencies", {})
                all_deps = list(deps)
                for group in optional.values():
                    all_deps.extend(group)
                if any("llama-index" in str(dep).lower() or "llama_index" in str(dep).lower() for dep in all_deps):
                    return True
            except tomllib.TOMLDecodeError:
                pass

    for name in LLAMAINDEX_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_llamaindex(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                continue
    return False


class LlamaIndexAnalyzer:
    """Audit LlamaIndex RAG pipelines for security and production risks.

    Scans LlamaIndex application files for hardcoded API keys, dangerous
    deserialization, SQL injection in NLSQL retrievers, SSRF in web loaders,
    eval/exec usage, pickle deserialization, and path traversal in readers.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LlamaIndexFinding] | None = None
        self._stats: LlamaIndexStats | None = None
        self._infos: list[LlamaIndexInfo] | None = None

    def configs(self) -> list[Path]:
        """Return LlamaIndex application and config paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in LLAMAINDEX_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_llamaindex(text):
                    found.append(path)
                    seen.add(path)

        for env_name in (".env", ".env.local", ".env.production"):
            env_path = self.root / env_name
            if env_path.is_file() and env_path not in seen:
                try:
                    text = env_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "llama" in text.lower() or "openai" in text.lower() or SECRETS_FILE_PATTERN.search(text):
                    found.append(env_path)
                    seen.add(env_path)

        if _looks_like_llamaindex_project(self.root):
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
                if _contains_llamaindex(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LlamaIndexFinding],
        info: LlamaIndexInfo,
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for component in (
            "VectorStoreIndex",
            "QueryEngine",
            "RetrieverQueryEngine",
            "SQLDatabase",
            "NLSQLTableQueryEngine",
            "SimpleWebPageReader",
            "SimpleDirectoryReader",
            "load_index_from_storage",
        ):
            if component in stripped and component not in info.components:
                info.components.append(component)

        if "QueryEngine" in stripped or "RetrieverQueryEngine" in stripped:
            info.has_query_engine = True
        if "SQLDatabase" in stripped or "NLSQLTableQueryEngine" in stripped:
            info.has_sql_retriever = True
        if WEB_LOADER_PATTERN.search(stripped):
            info.has_web_loader = True

        if is_config and rel.endswith((".toml", ".env", ".yaml", ".yml")):
            if SECRETS_FILE_PATTERN.search(stripped):
                findings.append(
                    LlamaIndexFinding(
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
             "hardcoded secret in LlamaIndex app — use environment variables or a secret manager"),
            (INLINE_API_KEY_PATTERN, "inline_api_key", "high",
             "inline API key in LLM/embedding constructor — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in LlamaIndex app — rotate and use secret stores"),
            (DANGEROUS_DESERIALIZATION_PATTERN, "dangerous_deserialization", "high",
             "allow_dangerous_deserialization=True — may enable arbitrary code execution via pickle"),
            (PICKLE_PATTERN, "pickle_deserialization", "high",
             "pickle deserialization — use JSON or other safe serialization formats"),
            (SQL_INJECTION_PATTERN, "sql_injection", "high",
             "dynamic SQL construction — use parameterized queries to prevent SQL injection"),
            (USER_URL_LOADER_PATTERN, "user_controlled_url", "high",
             "web loader with user-controlled URL — validate URLs to prevent SSRF"),
            (PATH_TRAVERSAL_PATTERN, "path_traversal", "high",
             "document reader with user-controlled path — validate paths to prevent traversal"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL — use HTTPS for remote resources"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in LlamaIndex app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (VERBOSE_LOGGING_PATTERN, "verbose_logging", "medium",
             "verbose/debug logging enabled — may leak prompts and API keys to logs"),
            (GLOBAL_SETTINGS_INLINE_PATTERN, "global_settings", "medium",
             "global Settings mutation — prefer explicit dependency injection for testability and security"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    LlamaIndexFinding(
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

    def _analyze_file(self, path: Path) -> tuple[list[LlamaIndexFinding], LlamaIndexInfo]:
        findings: list[LlamaIndexFinding] = []
        rel = str(path.relative_to(self.root))
        is_config = path.suffix in {".toml", ".env", ".yaml", ".yml"}
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, LlamaIndexInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = LlamaIndexInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info, is_config=is_config)

        if not is_config and info.has_sql_retriever and SQL_RAW_PATTERN.search(raw_text):
            if not any(f.kind == "sql_retriever" for f in findings):
                findings.append(
                    LlamaIndexFinding(
                        kind="sql_retriever",
                        severity="medium",
                        message="SQL retriever detected — restrict database permissions and validate generated SQL",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if not is_config and info.has_web_loader and WEB_LOADER_PATTERN.search(raw_text):
            if not any(f.kind == "web_loader_ssrf" for f in findings):
                findings.append(
                    LlamaIndexFinding(
                        kind="web_loader_ssrf",
                        severity="medium",
                        message="web page loader detected — validate URLs and restrict outbound requests",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if not is_config and CODE_EXECUTOR_PATTERN.search(raw_text):
            if not any(f.kind == "code_executor" for f in findings):
                findings.append(
                    LlamaIndexFinding(
                        kind="code_executor",
                        severity="medium",
                        message="code executor or tool detected — sandbox execution and restrict file/network access",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[LlamaIndexFinding]:
        """Scan LlamaIndex application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LlamaIndexFinding] = []
        infos: list[LlamaIndexInfo] = []
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
        self._stats = LlamaIndexStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> LlamaIndexStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[LlamaIndexInfo]:
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
        """Scaffold a hardened LlamaIndex RAG pipeline entry template."""
        return """\
# Generated by DevAI LlamaIndexAnalyzer
import os

from llama_index.core import Settings, VectorStoreIndex, SimpleDirectoryReader
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding


def build_index(data_dir: str = "./data") -> VectorStoreIndex:
    Settings.llm = OpenAI(
        model="gpt-4o-mini",
        api_key=os.environ["OPENAI_API_KEY"],
    )
    Settings.embed_model = OpenAIEmbedding(
        model="text-embedding-3-small",
        api_key=os.environ["OPENAI_API_KEY"],
    )
    documents = SimpleDirectoryReader(data_dir).load_data()
    return VectorStoreIndex.from_documents(documents)


if __name__ == "__main__":
    index = build_index()
    query_engine = index.as_query_engine(similarity_top_k=3)
    response = query_engine.query("What is in the documents?")
    print(str(response))
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "LlamaIndex: no application files found"
        return (
            f"LlamaIndex: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "LlamaIndex application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"components={','.join(info.components[:5]) or 'none'}, "
                f"sql={'yes' if info.has_sql_retriever else 'no'}, "
                f"web_loader={'yes' if info.has_web_loader else 'no'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
