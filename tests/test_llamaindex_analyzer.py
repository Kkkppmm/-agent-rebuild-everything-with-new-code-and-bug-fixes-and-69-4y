"""Tests for LlamaIndexAnalyzer."""

from pathlib import Path

from devai.llamaindex_analyzer import LlamaIndexAnalyzer, LlamaIndexFinding


INSECURE_LLAMAINDEX_PIPELINE = """\
import pickle

from llama_index.core import VectorStoreIndex, Settings
from llama_index.llms.openai import OpenAI
from llama_index.readers.web import SimpleWebPageReader
from llama_index.core.query_engine import NLSQLTableQueryEngine

OPENAI_API_KEY = "sk-hardcoded-secret-key-value"

Settings.llm = OpenAI(api_key=OPENAI_API_KEY, api_base="http://api.example.com/v1")
Settings.debug = True

documents = SimpleWebPageReader().load_data(urls=[request.query_params.get("url")])
index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

@app.post("/query")
def query(request):
    return query_engine.query(request.json.get("q"))

def load_index():
    with open("/tmp/index.pkl", "rb") as f:
        return pickle.loads(f.read())

sql = f"SELECT * FROM users WHERE name = '{user_input}'"
engine = NLSQLTableQueryEngine(sql_database=db, text_to_sql_prompt=sql)
"""

HARDENED_LLAMAINDEX_PIPELINE = """\
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
        api_key=os.environ["OPENAI_API_KEY"],
    )
    documents = SimpleDirectoryReader(data_dir).load_data()
    return VectorStoreIndex.from_documents(documents)


def main() -> None:
    index = build_index(os.environ.get("DATA_DIR", "./data"))
    query_engine = index.as_query_engine()
    print(query_engine.query("Summarize the documents."))


if __name__ == "__main__":
    main()
"""


class TestLlamaIndexAnalyzer:
    def test_detects_insecure_pipeline(self, tmp_path: Path):
        (tmp_path / "rag.py").write_text(INSECURE_LLAMAINDEX_PIPELINE, encoding="utf-8")

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "insecure_http" in kinds
        assert "user_controlled_url" in kinds
        assert "unsafe_deserialization" in kinds
        assert "debug_mode" in kinds
        assert analyzer.health_score() < 50

    def test_hardened_pipeline_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "rag.py").write_text(HARDENED_LLAMAINDEX_PIPELINE, encoding="utf-8")

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        assert len(findings) == 0
        assert analyzer.health_score() == 100.0

    def test_detects_llamaindex_from_pyproject(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndependencies = ["llama-index>=0.10.0"]\n',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.py").write_text(
            "from llama_index.core import VectorStoreIndex\n",
            encoding="utf-8",
        )

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        assert len(analyzer.configs()) >= 1

    def test_finding_format(self):
        finding = LlamaIndexFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="rag.py",
            lineno=5,
            line="API_KEY = 'x'",
        )
        assert "[high]" in finding.format()
        assert "rag.py:5" in finding.format()

    def test_generate_hardened_template(self):
        template = LlamaIndexAnalyzer(".").generate_hardened_template()
        assert "VectorStoreIndex" in template
        assert "os.environ" in template
        assert "OPENAI_API_KEY" in template

    def test_summary_and_context(self, tmp_path: Path):
        (tmp_path / "rag.py").write_text(INSECURE_LLAMAINDEX_PIPELINE, encoding="utf-8")

        analyzer = LlamaIndexAnalyzer(str(tmp_path))
        assert "LlamaIndex:" in analyzer.summary()
        context = analyzer.to_context()
        assert "LlamaIndex RAG pipeline analysis:" in context
        assert "health score:" in context
