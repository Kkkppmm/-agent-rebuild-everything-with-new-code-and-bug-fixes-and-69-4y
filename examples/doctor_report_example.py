"""Example: environment diagnostics and structured report export."""

from devai import DevRuntime, run_doctor
from devai.report import ProgramReport

# Diagnose your DevAI environment
print("=== Doctor ===")
doctor_result = run_doctor(use_mock=True)
print(doctor_result.summary())
print()

# Run a program and export a report
runtime = DevRuntime.create(use_mock=True)
results = runtime.run("pre-commit", {"code": "def add(a, b):\n    return a + b\n"})
report = ProgramReport.from_program("pre-commit", results, context={"code": "def add..."})

print("=== Markdown Report ===")
print(report.to_markdown())

print("=== JSON Report (preview) ===")
print(report.to_json()[:300], "...")
