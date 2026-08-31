"""LlamaIndexAnalyzer — audit LlamaIndex RAG pipelines for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LLAMAINDEX_ENTRY_NAMES = (
    "main.py",
    "app.py",
    "server.py",
    "index.py",
    "rag.py",
    "pipeline.py",
    "src/main.py",
    "src/app.py",
    "src/server.py",
    "src/index.py",
    "src/rag.py",
    "src/pipeline.py",
    "app/main.py",
    "app/rag.py",
)
LLAMAINDEX_IMPORT_PATTERN = re.compile(
    r"(?:from\s+llama_index(?:\.\w+)*\s+import|import\s+llama_index|"
    r"\bVectorStoreIndex\b|\bServiceContext\b|\bSettings\b|\bQueryEngine\b|"
    r"\bload_index_from_storage\b|\bStorageContext\b)",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"openai[_-]?api[_-]?key|anthropic[_-]?api[_-]?key|azure[_-]?api[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|settings\.|config\.|getenv|environ\.get|SecretStr))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
AWS_ACCESS_KEY_PATTERN = re.compile(r"[\"']?AKIA[0-9A-Z]{16}[\"']?", re.IGNORECASE)
INSECURE_HTTP_PATTERN = re.compile(
    r"(?:api_base|base_url|endpoint)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]|"
    r"http://(?!localhost|127\.0\.0\.1)[^\s\"'<>]+",
    re.IGNORECASE,
)
REJECT_UNAUTHORIZED_FALSE_PATTERN = re.compile(
    r"verify\s*=\s*False|ssl\.verify_mode\s*=\s*ssl\.CERT_NONE|verify_ssl\s*=\s*False",
    re.IGNORECASE,
)
PROXY_INTERNAL_PATTERN = re.compile(
    r"(?:url|target|proxy|destination|file_path|input_dir)\s*=\s*['\"]https?://(?:10\.|192\.168\.|"
    r"172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)|"
    r"(?:SimpleWebPageReader|TrafilaturaWebReader|BeautifulSoupWebReader|"
    r"RssReader|ScrapeWebReader)\s*\([^)]*(?:url|urls)\s*=\s*(?:request\.|user_|input)",
    re.IGNORECASE,
)
EVAL_PATTERN = re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE)
PICKLE_PATTERN = re.compile(
    r"(?:pickle\.loads|pickle\.load|dill\.loads|yaml\.load\s*\()",
    re.IGNORECASE,
)
SQL_RAW_PATTERN = re.compile(
    r"(?:NLSQLTableQueryEngine|SQLDatabase|text_to_sql|execute)\s*\([^)]*(?:f['\"]|%s|\.format\()|"
    r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:\+|\.format\(|f['\"])",
    re.IGNORECASE,
)
USER_URL_LOADER_PATTERN = re.compile(
    r"(?:SimpleWebPageReader|TrafilaturaWebReader|BeautifulSoupWebReader|"
    r"download_loader|load_data)\s*\([^)]*(?:request\.|user_|input_|query_params)",
    re.IGNORECASE,
)
EXPOSED_QUERY_ENGINE_PATTERN = re.compile(
    r"(?:@app\.(?:get|post|route)|@router\.(?:get|post|route)|app\.(?:get|post))\s*\([^)]*\)[\s\S]{0,200}"
    r"(?:query_engine\.query|index\.as_query_engine|chat_engine\.chat)",
    re.IGNORECASE,
)
PROMPT_INJECTION_PATTERN = re.compile(
    r"(?:system_prompt|text_qa_template|refine_template)\s*=\s*f?['\"].*\{.*(?:user|input|query|request)",
    re.IGNORECASE,
)
DEBUG_MODE_PATTERN = re.compile(
    r"(?:Settings\.debug|debug\s*=\s*True|llama_index\.set_global_handler\s*\(\s*['\"]debug['\"])",
    re.IGNORECASE,
)
HARDCODED_INDEX_PATH_PATTERN = re.compile(
    r"(?:persist_dir|storage_dir)\s*=\s*['\"](?:/tmp|/var/tmp|\.\./)[^'\"]*['\"]",
    re.IGNORECASE,
)
SHELL_COMMAND_PATTERN = re.compile(
    r"(?:os\.system|subprocess\.(?:call|run|Popen))\s*\([^)]*(?:user|input|query|request)",
    re.IGNORECASE,
)


@dataclass
class LlamaIndexFinding:
    """A security or best-practice issue in a LlamaIndex RAG pipeline file."""

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
    """Parsed metadata about a LlamaIndex pipeline file."""

    path: str
    lines: int = 0
    file_kind: str = ""
    has_vector_store: bool = False
    has_query_engine: bool = False
    has_web_reader: bool = False
    has_sql_engine: bool = False
    components: list[str] = field(default_factory=list)


@dataclass
class LlamaIndexStats:
    """Aggregate LlamaIndex analysis statistics."""

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


def _contains_llamaindex(text: str) -> bool:
    return bool(
        LLAMAINDEX_IMPORT_PATTERN.search(text)
        or "llama_index" in text.lower()
        or "VectorStoreIndex" in text
    )


def _looks_like_llamaindex_project(root: Path) -> bool:
    for name in ("pyproject.toml", "requirements.txt", "Pipfile"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            if "llama-index" in text or "llama_index" in text:
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
            if any("llama-index" in str(dep).lower() or "llama_index" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in LLAMAINDEX_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_llamaindex(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass
    return False


class LlamaIndexAnalyzer:
    """Audit LlamaIndex RAG pipelines for security and production risks.

    Scans LlamaIndex entry files for hardcoded API keys, SQL injection in
    NLSQL engines, SSRF in web readers, unsafe deserialization, exposed query
    engines, and prompt injection patterns.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LlamaIndexFinding] | None = None
        self._stats: LlamaIndexStats | None = None
        self._infos: list[LlamaIndexInfo] | None = None

    def configs(self) -> list[Path]:
        """Return LlamaIndex pipeline paths found in the project."""
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
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        if "VectorStoreIndex" in stripped or "from_documents" in stripped:
            info.has_vector_store = True
            if "VectorStoreIndex" not in info.components:
                info.components.append("VectorStoreIndex")
        if "as_query_engine" in stripped or "QueryEngine" in stripped:
            info.has_query_engine = True
            if "QueryEngine" not in info.components:
                info.components.append("QueryEngine")
        if any(
            reader in stripped
            for reader in (
                "SimpleWebPageReader",
                "TrafilaturaWebReader",
                "BeautifulSoupWebReader",
                "RssReader",
            )
        ):
            info.has_web_reader = True
            if "WebReader" not in info.components:
                info.components.append("WebReader")
        if "NLSQLTableQueryEngine" in stripped or "SQLDatabase" in stripped:
            info.has_sql_engine = True
            if "SQLEngine" not in info.components:
                info.components.append("SQLEngine")

        checks: list[tuple[re.Pattern[str], str, str, str]] = [
            (HARDCODED_SECRET_PATTERN, "hardcoded_secret", "high",
             "hardcoded API key or secret — use environment variables or secret stores"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in LlamaIndex pipeline — rotate and use secret stores"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP endpoint — use HTTPS for LLM and vector store APIs"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (USER_URL_LOADER_PATTERN, "user_controlled_url", "high",
             "web reader loads user-controlled URL — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in RAG pipeline — avoid dynamic code execution"),
            (PICKLE_PATTERN, "unsafe_deserialization", "high",
             "unsafe deserialization (pickle/dill/yaml.load) — use safe loaders"),
            (SQL_RAW_PATTERN, "sql_injection", "high",
             "dynamic SQL in NLSQL engine — use parameterized queries"),
            (EXPOSED_QUERY_ENGINE_PATTERN, "exposed_query_engine", "high",
             "query engine exposed via HTTP route without visible auth — add authentication"),
            (PROMPT_INJECTION_PATTERN, "prompt_injection", "medium",
             "user input interpolated into prompt template — sanitize to prevent prompt injection"),
            (DEBUG_MODE_PATTERN, "debug_mode", "medium",
             "debug mode enabled — disable in production"),
            (HARDCODED_INDEX_PATH_PATTERN, "insecure_index_path", "medium",
             "index persisted to world-writable path — use secure storage location"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command with user input — command injection risk"),
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

    def _analyze_file(self, path: Path) -> tuple[list[LlamaIndexFinding], LlamaIndexInfo]:
        findings: list[LlamaIndexFinding] = []
        rel = str(path.relative_to(self.root))
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
            self._scan_line(raw.rstrip(), lineno, rel, findings, info)

        if EXPOSED_QUERY_ENGINE_PATTERN.search(raw_text):
            if not any(f.kind == "exposed_query_engine" for f in findings):
                findings.append(
                    LlamaIndexFinding(
                        kind="exposed_query_engine",
                        severity="high",
                        message="query engine exposed via HTTP route without visible auth — add authentication",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[LlamaIndexFinding]:
        """Scan LlamaIndex pipeline files and return findings."""
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
        """Scaffold a hardened LlamaIndex RAG pipeline template."""
        return """\
# Generated by DevAI LlamaIndexAnalyzer
import os

from llama_index.core import Settings, VectorStoreIndex, SimpleDirectoryReader
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding


def build_index(data_dir: str) -> VectorStoreIndex:
    Settings.llm = OpenAI(
        model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        api_key=os.environ["OPENAI_API_KEY"],
    )
    Settings.embed_model = OpenAIEmbedding(
        model=os.environ.get("OPENAI_EMBED_MODEL", "text-embedding-3-small"),
        api_key=os.environ["OPENAI_API_KEY"],
    )
    documents = SimpleDirectoryReader(data_dir).load_data()
    return VectorStoreIndex.from_documents(documents)


def main() -> None:
    index = build_index(os.environ.get("DATA_DIR", "./data"))
    query_engine = index.as_query_engine()
    response = query_engine.query("Summarize the documents.")
    print(response)


if __name__ == "__main__":
    main()
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "LlamaIndex: no pipeline files found"
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
            "LlamaIndex RAG pipeline analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"components={','.join(info.components) or 'none'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
