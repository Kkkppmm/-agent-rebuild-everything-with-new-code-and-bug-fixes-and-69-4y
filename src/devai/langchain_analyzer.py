"""LangChainAnalyzer — audit LangChain apps and agents for security and production risks."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LANGCHAIN_ENTRY_NAMES = (
    "app.py",
    "main.py",
    "agent.py",
    "chain.py",
    "rag.py",
    "src/app.py",
    "src/main.py",
    "src/agent.py",
    "src/chain.py",
    "src/rag.py",
)
LANGCHAIN_IMPORT_PATTERN = re.compile(
    r"(?:from\s+langchain(?:_[\w]+)?|import\s+langchain(?:_[\w]+)?|"
    r"\b(?:ChatOpenAI|OpenAI|AgentExecutor|create_sql_agent|SQLDatabase|"
    r"SQLDatabaseChain|load_tools|initialize_agent|create_react_agent|"
    r"PythonREPLTool|ShellTool|WebBaseLoader|UnstructuredURLLoader|"
    r"RequestsWrapper|RetrievalQA|ConversationalRetrievalChain|"
    r"create_retrieval_chain|create_stuff_documents_chain|"
    r"HumanInputRun|Tool|StructuredTool|hub\.pull))\b",
    re.IGNORECASE,
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|token|credential|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer|session[_-]?secret|"
    r"jwt[_-]?secret|secret_key|openai[_-]?api[_-]?key|anthropic[_-]?api[_-]?key|"
    r"huggingface[_-]?token|hf[_-]?token|cohere[_-]?api[_-]?key|langchain[_-]?api[_-]?key)\s*[=:]\s*"
    r"(?!\s*(?:os\.environ|os\.getenv|settings\.|config\.|getenv|environ\.get))(?:[\"'][^\"'\s${}][^\"']*[\"'])",
    re.IGNORECASE,
)
INLINE_API_KEY_PATTERN = re.compile(
    r"(?:ChatOpenAI|OpenAI|Anthropic|AzureChatOpenAI|AzureOpenAI|Cohere|"
    r"HuggingFaceHub|HuggingFaceEndpoint|GoogleGenerativeAI|Bedrock)\s*\([^)]*api[_-]?key\s*=\s*[\"'][^\"']+[\"']",
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
    r"(?:SQLDatabase|SQLDatabaseChain|create_sql_agent|QuerySQLDataBaseTool|"
    r"text\s*\(\s*f?[\"']SELECT|execute\s*\(\s*f?[\"']SELECT|run\s*\(\s*f?[\"']SELECT)",
    re.IGNORECASE,
)
SQL_INJECTION_PATTERN = re.compile(
    r"(?:f[\"']SELECT|\.format\s*\([^)]*\).*SELECT|%\s*\([^)]*\).*SELECT|"
    r"query\s*\+\s*|sql\s*\+\s*)",
    re.IGNORECASE,
)
WEB_LOADER_PATTERN = re.compile(
    r"(?:WebBaseLoader|UnstructuredURLLoader|AsyncHtmlLoader|RecursiveUrlLoader|"
    r"SitemapLoader|PlaywrightURLLoader|AsyncChromiumLoader)\s*\(",
    re.IGNORECASE,
)
USER_URL_LOADER_PATTERN = re.compile(
    r"(?:WebBaseLoader|UnstructuredURLLoader|AsyncHtmlLoader|RecursiveUrlLoader|"
    r"load_tools|requests\.(?:get|post))\s*\([^)]*(?:user_|input_|query|request\.|params)",
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
DANGEROUS_TOOL_PATTERN = re.compile(
    r"(?:PythonREPLTool|ShellTool|BashProcess|Terminal|HumanInputRun|"
    r"\"terminal\"|\"python_repl\"|\"shell\"|'terminal'|'python_repl'|'shell')",
    re.IGNORECASE,
)
LOAD_TOOLS_PATTERN = re.compile(
    r"load_tools\s*\(\s*\[[^\]]*(?:terminal|python_repl|shell|requests_all)",
    re.IGNORECASE,
)
AGENT_UNRESTRICTED_PATTERN = re.compile(
    r"(?:AgentExecutor|create_react_agent|initialize_agent)\s*\([^)]*(?:max_iterations\s*=\s*(?:None|\d{2,})|"
    r"handle_parsing_errors\s*=\s*True|return_intermediate_steps\s*=\s*True)",
    re.IGNORECASE,
)
HUB_PULL_PATTERN = re.compile(
    r"(?:hub\.pull|pull\s*\(\s*[\"'][^\"']+[\"'])",
    re.IGNORECASE,
)
SECRETS_FILE_PATTERN = re.compile(
    r"(?:OPENAI|ANTHROPIC|AWS|API|SECRET|TOKEN|PASSWORD|KEY|HF_TOKEN|COHERE|LANGCHAIN)\s*=\s*[\"'][^\"']+[\"']",
    re.IGNORECASE,
)
VERBOSE_LOGGING_PATTERN = re.compile(
    r"(?:verbose\s*=\s*True|set_debug\s*\(\s*True|LANGCHAIN_VERBOSE\s*=\s*[\"']?true[\"']?)",
    re.IGNORECASE,
)
TRACING_EXPOSED_PATTERN = re.compile(
    r"(?:LANGCHAIN_TRACING_V2\s*=\s*[\"']?true[\"']?|tracing_v2\s*=\s*True)",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(?:DirectoryLoader|PyPDFLoader|TextLoader|CSVLoader|UnstructuredFileLoader)\s*\([^)]*(?:user_|input_|query|request\.)",
    re.IGNORECASE,
)


@dataclass
class LangChainFinding:
    """A security or best-practice issue in a LangChain application file."""

    kind: str
    severity: str
    message: str
    path: str
    lineno: int
    line: str = ""

    def format(self) -> str:
        return f"[{self.severity}] {self.path}:{self.lineno} — {self.message}"


@dataclass
class LangChainInfo:
    """Metadata about a scanned LangChain application file."""

    path: str
    lines: int = 0
    file_kind: str = "app"
    components: list[str] = field(default_factory=list)
    has_agent: bool = False
    has_sql_chain: bool = False
    has_web_loader: bool = False
    has_dangerous_tool: bool = False


@dataclass
class LangChainStats:
    """Aggregate statistics from a LangChain scan."""

    configs: int = 0
    files: int = 0
    findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0


def _contains_langchain(text: str) -> bool:
    return bool(LANGCHAIN_IMPORT_PATTERN.search(text))


def _file_kind(path: Path) -> str:
    name = path.name.lower()
    if name in ("langchain.toml", "langsmith.toml"):
        return "config"
    if path.suffix == ".env":
        return "env"
    return "app"


def _looks_like_langchain_project(root: Path) -> bool:
    for manifest in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"):
        path = root / manifest
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if "langchain" in text:
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
            if any("langchain" in str(dep).lower() for dep in all_deps):
                return True
        except (tomllib.TOMLDecodeError, OSError):
            pass

    for name in LANGCHAIN_ENTRY_NAMES:
        path = root / name
        if path.is_file():
            try:
                if _contains_langchain(path.read_text(encoding="utf-8", errors="replace")):
                    return True
            except OSError:
                pass

    return False


class LangChainAnalyzer:
    """Audit LangChain applications for security and production risks.

    Scans LangChain application files for hardcoded API keys, dangerous tools
    (Python REPL, shell), SQL injection in SQL agents, SSRF in web loaders,
    eval/exec usage, pickle deserialization, and unrestricted agent execution.
    """

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self._findings: list[LangChainFinding] | None = None
        self._stats: LangChainStats | None = None
        self._infos: list[LangChainInfo] | None = None

    def configs(self) -> list[Path]:
        """Return LangChain application and config paths found in the project."""
        found: list[Path] = []
        seen: set[Path] = set()

        for name in LANGCHAIN_ENTRY_NAMES:
            path = self.root / name
            if path.is_file() and path not in seen:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _contains_langchain(text):
                    found.append(path)
                    seen.add(path)

        for env_name in (".env", ".env.local", ".env.production"):
            env_path = self.root / env_name
            if env_path.is_file() and env_path not in seen:
                try:
                    text = env_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "langchain" in text.lower() or "openai" in text.lower() or SECRETS_FILE_PATTERN.search(text):
                    found.append(env_path)
                    seen.add(env_path)

        if _looks_like_langchain_project(self.root):
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
                if _contains_langchain(text):
                    found.append(path)
                    seen.add(path)

        return found

    def _scan_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        findings: list[LangChainFinding],
        info: LangChainInfo,
        is_config: bool = False,
    ) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return

        for component in (
            "ChatOpenAI",
            "AgentExecutor",
            "SQLDatabase",
            "create_sql_agent",
            "RetrievalQA",
            "PythonREPLTool",
            "ShellTool",
            "WebBaseLoader",
            "load_tools",
        ):
            if component in stripped and component not in info.components:
                info.components.append(component)

        if "AgentExecutor" in stripped or "create_react_agent" in stripped or "initialize_agent" in stripped:
            info.has_agent = True
        if "SQLDatabase" in stripped or "create_sql_agent" in stripped or "SQLDatabaseChain" in stripped:
            info.has_sql_chain = True
        if WEB_LOADER_PATTERN.search(stripped):
            info.has_web_loader = True
        if DANGEROUS_TOOL_PATTERN.search(stripped):
            info.has_dangerous_tool = True

        if is_config and rel.endswith((".toml", ".env", ".yaml", ".yml")):
            if SECRETS_FILE_PATTERN.search(stripped):
                findings.append(
                    LangChainFinding(
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
             "hardcoded secret in LangChain app — use environment variables or a secret manager"),
            (INLINE_API_KEY_PATTERN, "inline_api_key", "high",
             "inline API key in LLM constructor — use environment variables"),
            (AWS_ACCESS_KEY_PATTERN, "aws_access_key", "high",
             "AWS access key in LangChain app — rotate and use secret stores"),
            (DANGEROUS_DESERIALIZATION_PATTERN, "dangerous_deserialization", "high",
             "allow_dangerous_deserialization=True — may enable arbitrary code execution via pickle"),
            (PICKLE_PATTERN, "pickle_deserialization", "high",
             "pickle deserialization — use JSON or other safe serialization formats"),
            (SQL_INJECTION_PATTERN, "sql_injection", "high",
             "dynamic SQL construction — use parameterized queries to prevent SQL injection"),
            (USER_URL_LOADER_PATTERN, "user_controlled_url", "high",
             "web loader with user-controlled URL — validate URLs to prevent SSRF"),
            (PATH_TRAVERSAL_PATTERN, "path_traversal", "high",
             "document loader with user-controlled path — validate paths to prevent traversal"),
            (INSECURE_HTTP_PATTERN, "insecure_http", "high",
             "insecure HTTP URL — use HTTPS for remote resources"),
            (REJECT_UNAUTHORIZED_FALSE_PATTERN, "tls_verify_disabled", "high",
             "TLS certificate verification disabled"),
            (PROXY_INTERNAL_PATTERN, "ssrf_internal", "high",
             "request to internal/private network address — SSRF risk"),
            (EVAL_PATTERN, "eval_exec", "high",
             "eval/exec in LangChain app — avoid dynamic code execution"),
            (SHELL_COMMAND_PATTERN, "shell_command", "high",
             "shell command execution — avoid os.system/subprocess with user input"),
            (DANGEROUS_TOOL_PATTERN, "dangerous_tool", "high",
             "dangerous tool (REPL/shell/terminal) — sandbox execution and restrict agent tools"),
            (LOAD_TOOLS_PATTERN, "dangerous_load_tools", "high",
             "load_tools includes dangerous tool — restrict agent capabilities"),
            (VERBOSE_LOGGING_PATTERN, "verbose_logging", "medium",
             "verbose/debug logging enabled — may leak prompts and API keys to logs"),
            (TRACING_EXPOSED_PATTERN, "tracing_enabled", "medium",
             "LangSmith tracing enabled — ensure traces do not contain secrets in production"),
            (HUB_PULL_PATTERN, "hub_pull", "medium",
             "pulling prompts/chains from LangChain Hub — pin revisions and audit remote content"),
            (AGENT_UNRESTRICTED_PATTERN, "unrestricted_agent", "medium",
             "agent with high iteration limit or permissive error handling — may amplify tool abuse"),
        ]

        for pattern, kind, severity, message in checks:
            if pattern.search(stripped):
                findings.append(
                    LangChainFinding(
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

    def _analyze_file(self, path: Path) -> tuple[list[LangChainFinding], LangChainInfo]:
        findings: list[LangChainFinding] = []
        rel = str(path.relative_to(self.root))
        is_config = path.suffix in {".toml", ".env", ".yaml", ".yml"}
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, LangChainInfo(path=rel)

        raw_lines = raw_text.splitlines()
        info = LangChainInfo(
            path=rel,
            lines=len(raw_lines),
            file_kind=_file_kind(path),
        )

        for lineno, raw in enumerate(raw_lines, start=1):
            self._scan_line(raw.rstrip(), lineno, rel, findings, info, is_config=is_config)

        if not is_config and info.has_sql_chain and SQL_RAW_PATTERN.search(raw_text):
            if not any(f.kind == "sql_chain" for f in findings):
                findings.append(
                    LangChainFinding(
                        kind="sql_chain",
                        severity="medium",
                        message="SQL agent/chain detected — restrict database permissions and validate generated SQL",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if not is_config and info.has_web_loader and WEB_LOADER_PATTERN.search(raw_text):
            if not any(f.kind == "web_loader_ssrf" for f in findings):
                findings.append(
                    LangChainFinding(
                        kind="web_loader_ssrf",
                        severity="medium",
                        message="web page loader detected — validate URLs and restrict outbound requests",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        if not is_config and info.has_agent and info.has_dangerous_tool:
            if not any(f.kind == "agent_with_dangerous_tools" for f in findings):
                findings.append(
                    LangChainFinding(
                        kind="agent_with_dangerous_tools",
                        severity="high",
                        message="agent configured with code execution tools — sandbox and restrict tool access",
                        path=rel,
                        lineno=1,
                        line="",
                    )
                )

        return findings, info

    def analyze(self) -> list[LangChainFinding]:
        """Scan LangChain application files and return findings."""
        if self._findings is not None:
            return self._findings

        findings: list[LangChainFinding] = []
        infos: list[LangChainInfo] = []
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
        self._stats = LangChainStats(
            configs=len(paths),
            files=len(paths),
            findings=len(findings),
            high_severity=high,
            medium_severity=medium,
            low_severity=low,
        )
        return findings

    @property
    def stats(self) -> LangChainStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    @property
    def infos(self) -> list[LangChainInfo]:
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
        """Scaffold a hardened LangChain RAG agent entry template."""
        return """\
# Generated by DevAI LangChainAnalyzer
import os

from langchain_openai import ChatOpenAI
from langchain_community.document_loaders import DirectoryLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain.chains import RetrievalQA


def build_qa_chain(data_dir: str = "./data") -> RetrievalQA:
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        api_key=os.environ["OPENAI_API_KEY"],
        temperature=0,
    )
    embeddings = OpenAIEmbeddings(api_key=os.environ["OPENAI_API_KEY"])
    loader = DirectoryLoader(data_dir)
    documents = loader.load()
    vectorstore = FAISS.from_documents(documents, embeddings)
    return RetrievalQA.from_chain_type(
        llm=llm,
        retriever=vectorstore.as_retriever(search_kwargs={"k": 3}),
    )


if __name__ == "__main__":
    chain = build_qa_chain()
    print(chain.invoke({"query": "What is in the documents?"}))
"""

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        if stats.configs == 0:
            return "LangChain: no application files found"
        return (
            f"LangChain: {stats.configs} file(s), "
            f"{stats.findings} finding(s) "
            f"({stats.high_severity} high, {stats.medium_severity} medium, "
            f"{stats.low_severity} low)"
        )

    def to_context(self) -> str:
        self.analyze()
        stats = self.stats
        lines = [
            "LangChain application analysis:",
            f"  files: {stats.configs}",
            f"  findings: {stats.findings}",
            f"  health score: {self.health_score()}/100",
        ]
        for info in self.infos:
            lines.append(
                f"  - {info.path} ({info.file_kind}): "
                f"components={','.join(info.components[:5]) or 'none'}, "
                f"agent={'yes' if info.has_agent else 'no'}, "
                f"sql={'yes' if info.has_sql_chain else 'no'}, "
                f"dangerous_tools={'yes' if info.has_dangerous_tool else 'no'}"
            )
        if self._findings:
            lines.append("  findings:")
            for finding in self._findings[:20]:
                lines.append(f"    [{finding.severity}] {finding.kind}: {finding.message}")
            if len(self._findings) > 20:
                lines.append(f"    ... and {len(self._findings) - 20} more")
        return "\n".join(lines)
