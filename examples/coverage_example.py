"""Example: docstring coverage and test mapping with DevAI."""

from devai import DevAI, DocstringCoverage, TestMapper

# Static analysis — no LLM required
doc_cov = DocstringCoverage(".")
print(doc_cov.summary())
print(doc_cov.to_context(limit=10))

test_map = TestMapper(".")
print(test_map.summary())
print(test_map.to_context(limit=10))

# Via the DevAI facade
ai = DevAI.mock()
print(ai.docstrings(".").coverage_pct())
print(ai.test_map(".").untested_modules())
