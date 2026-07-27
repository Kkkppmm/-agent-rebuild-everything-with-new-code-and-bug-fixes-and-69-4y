"""Tests for CodeAssistant."""


from devai import CodeAssistant, MockLLMClient


def test_code_assistant_review():
  client = MockLLMClient(default_response="Looks good!")
  assistant = CodeAssistant(client=client)
  result = assistant.review("def add(a, b): return a + b")
  assert result == "Looks good!"
  assert "def add" in client.calls[0][1].content


def test_code_assistant_explain():
  client = MockLLMClient(default_response="This adds two numbers.")
  assistant = CodeAssistant(client=client)
  result = assistant.explain("def add(a, b): return a + b")
  assert "adds" in result.lower() or result == "This adds two numbers."


def test_code_assistant_debug():
  client = MockLLMClient(default_response="Fix: define x before use.")
  assistant = CodeAssistant(client=client)
  result = assistant.debug("NameError: x", "print(x)")
  assert "Fix" in result


def test_code_assistant_refactor():
  client = MockLLMClient(default_response="refactored code")
  assistant = CodeAssistant(client=client)
  result = assistant.refactor("x=1+2", goal="use constants")
  assert result == "refactored code"


def test_code_assistant_security():
  client = MockLLMClient(default_response="No issues found.")
  assistant = CodeAssistant(client=client)
  assert assistant.security_audit("safe_code = True") == "No issues found."


def test_code_assistant_generate_tests():
  client = MockLLMClient(default_response="def test_add(): pass")
  assistant = CodeAssistant(client=client)
  assert "test" in assistant.generate_tests("def add(a,b): return a+b")


def test_code_assistant_docstrings():
  client = MockLLMClient(default_response="def add(a, b):\n    '''Add.'''")
  assistant = CodeAssistant(client=client)
  assert assistant.generate_docstrings("def add(a, b): pass")


def test_code_assistant_commit_message():
  client = MockLLMClient(default_response="feat: add function")
  assistant = CodeAssistant(client=client)
  assert assistant.commit_message("+ def add(): pass") == "feat: add function"


def test_code_assistant_review_file(tmp_path):
  f = tmp_path / "sample.py"
  f.write_text("def hello(): pass")
  client = MockLLMClient(default_response="reviewed")
  assistant = CodeAssistant(client=client)
  assert assistant.review_file(str(f)) == "reviewed"


def test_code_assistant_full_review(tmp_path):
  f = tmp_path / "sample.py"
  f.write_text("def hello(): pass")
  client = MockLLMClient(responses=["review", "security", "tests"])
  assistant = CodeAssistant(client=client)
  result = assistant.full_review(str(f))
  assert set(result.keys()) == {"review", "security", "tests"}
