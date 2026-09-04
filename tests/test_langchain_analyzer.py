"""Tests for LangChainAnalyzer."""

from pathlib import Path

from devai.langchain_analyzer import LangChainAnalyzer, LangChainFinding


INSECURE_LANGCHAIN_APP = """\
import os
import pickle
import subprocess

from langchain_openai import ChatOpenAI
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import create_sql_agent
from langchain_community.tools import ShellTool, PythonREPLTool
from langchain_community.document_loaders import WebBaseLoader
from langchain.agents import AgentExecutor, load_tools

API_KEY = "sk-hardcoded-openai-key"
llm = ChatOpenAI(api_key="sk-inline-key", model="gpt-4o-mini")

def build_agent(user_url: str):
  tools = load_tools(["terminal", "python_repl"])
  loader = WebBaseLoader(web_paths=[user_url])
  return AgentExecutor.from_agent_and_tools(
      tools=tools + [ShellTool(), PythonREPLTool()],
      llm=llm,
      max_iterations=50,
      handle_parsing_errors=True,
      verbose=True,
  )

def query_sql(user_query: str):
    db = SQLDatabase.from_uri("sqlite:///app.db")
    agent = create_sql_agent(llm, db=db, verbose=True)
    return agent.run(f"SELECT * FROM users WHERE name = '{user_query}'")

def load_persisted(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)

@some_handler
def on_request(request):
    subprocess.run(request.query, shell=True)
    eval(request.payload)
"""

HARDENED_LANGCHAIN_APP = """\
import os

from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.document_loaders import DirectoryLoader
from langchain_community.vectorstores import FAISS
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
"""


class TestLangChainAnalyzer:
    def test_detects_insecure_langchain_app(self, tmp_path: Path):
        (tmp_path / "agent.py").write_text(INSECURE_LANGCHAIN_APP, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("langchain>=0.2.0\nlangchain-openai\n", encoding="utf-8")

        analyzer = LangChainAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "inline_api_key" in kinds
        assert "pickle_deserialization" in kinds
        assert "sql_injection" in kinds
        assert "user_controlled_url" in kinds
        assert "eval_exec" in kinds
        assert "shell_command" in kinds
        assert "dangerous_tool" in kinds
        assert "dangerous_load_tools" in kinds
        assert "agent_with_dangerous_tools" in kinds
        assert analyzer.health_score() < 50

    def test_hardened_app_has_fewer_findings(self, tmp_path: Path):
        (tmp_path / "rag.py").write_text(HARDENED_LANGCHAIN_APP, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["langchain>=0.2.0", "langchain-openai"]\n',
            encoding="utf-8",
        )

        analyzer = LangChainAnalyzer(str(tmp_path))
        findings = analyzer.analyze()

        high = [f for f in findings if f.severity == "high"]
        assert len(high) == 0
        assert analyzer.health_score() >= 80

    def test_no_files_returns_full_score(self, tmp_path: Path):
        analyzer = LangChainAnalyzer(str(tmp_path))
        assert analyzer.health_score() == 100.0
        assert "no application files found" in analyzer.summary()

    def test_finding_format(self):
        finding = LangChainFinding(
            kind="hardcoded_secret",
            severity="high",
            message="test message",
            path="agent.py",
            lineno=5,
            line="API_KEY = 'secret'",
        )
        assert "[high] agent.py:5" in finding.format()

    def test_generate_hardened_template(self):
        analyzer = LangChainAnalyzer(".")
        template = analyzer.generate_hardened_template()
        assert "os.environ" in template
        assert "RetrievalQA" in template

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "chain.py").write_text(HARDENED_LANGCHAIN_APP, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("langchain\n", encoding="utf-8")

        analyzer = LangChainAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "LangChain application analysis" in context
        assert "health score" in context
