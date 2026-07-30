"""DevAI developer tools — imports, secrets, typing, docstrings, and more."""

from devai import DevTools

tools = DevTools(".")
print(tools.summary())

report = tools.analyze_all()
print(report.to_context(limit=10))
