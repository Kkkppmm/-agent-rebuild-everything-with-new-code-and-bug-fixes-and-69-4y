"""Tests for LlamaIndexAnalyzer."""

from pathlib import Path

from devai.llamaindex_analyzer import LlamaIndexAnalyzer, LlamaIndexFinding


INSECURE_LLAMAINDEX_APP = """\
import os
import pickle
import subprocess

from llama_index.core import VectorStoreIndex, Settings
from llama_index.llms.openai import OpenAI
from llama_index.readers.web import SimpleWebPageReader
from llama_index.core import SQLDatabase, NLSQLTableQueryEngine

API_KEY = "sk-hardcoded-openai-key"
Settings.llm = OpenAI(api_key="sk-inline-key", model="gpt-4o-mini")

def build_index(user_url: str):
    docs = SimpleWebPageReader(html_to_text=True).load_data(urls=[user_url])
    return VectorStoreIndex.from_documents(docs)

def query_sql(user_query: str):
    sql_db = SQLDatabase(engine)
    engine = NLSQLTableQueryEngine(sql_database=sql_db)
    return engine.query(f"SELECT * FROM users WHERE name = '{user_query}'")

def load_persisted(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)

@some_handler
def on_request(request):
    subprocess.run(request.query, shell=True)
    eval(request.payload)
"""

HARDENED_LLAMAINDEX_APP = """\
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
"""


class TestLlamaIndexAnalyzer:
    def test_detects_insecure_llamaindex_app(self, tmp_path: Path):
        (tmp_path / "index.py").write_text(INSECURE_LLAMAINDEX_APP, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("llama-index>=0.10.0\n", encoding="utf-8")

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "inline_api_key" in kinds
        assert "pickle_deserialization" in kinds
        assert "sql_injection" in kinds
        assert "user_controlled_url" in kinds
        assert "eval_exec" in kinds
        assert "shell_command" in kinds
        assert analyzer.health_score() < 50

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "index.py").write_text(HARDENED_LLAMAINDEX_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["llama-index>=0.10.0"]\n',
            encoding="utf-8",
        )

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 80

    def test_no_files_returns_full_score(self, tmp_path: Path):
        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "no application files found" in analyzer.summary()

    def test_finding_format(self):
        finding = LlamaIndexFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="index.py",
            lineno=5,
            line="API_KEY = 'secret'",
        )
        assert "[high] index.py:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = LlamaIndexAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "os.environ" in template
        assert "VectorStoreIndex" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "rag.py").write_text(HARDENED_LLAMAINDEX_APP, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("llama-index\n", encoding="utf-8")

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "LlamaIndex application analysis" in context
        assert "health score" in context
