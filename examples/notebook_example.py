"""Example: Jupyter notebook support and developer diagnostics."""

from devai import CodeAssistant, NotebookReader
from devai.core import MockLLMClient

client = MockLLMClient(default_response="Analysis complete.")
assistant = CodeAssistant(client=client)

# Analyze test failures
failures = assistant.analyze_test_failures(
    "FAILED tests/test_math.py::test_add - AssertionError: assert 3 == 4",
    code="def add(a, b):\n    return a + b",
)
print("Test failure analysis:", failures)

# Analyze a stack trace
trace = assistant.analyze_stacktrace(
    "Traceback (most recent call last):\n  File 'app.py', line 10, in main\n    user = users[key]\nKeyError: 'missing'",
    context="User lookup in authentication flow",
)
print("Stack trace analysis:", trace)

# Review a configuration file
config_review = assistant.review_config(
    "[tool.pytest.ini_options]\nasyncio_mode = auto",
    config_type="pyproject.toml",
)
print("Config review:", config_review)

# NotebookReader extracts code from .ipynb files (no API call)
# reader = NotebookReader("analysis.ipynb")
# print(reader.extract_code())
# print(assistant.review_notebook("analysis.ipynb"))
