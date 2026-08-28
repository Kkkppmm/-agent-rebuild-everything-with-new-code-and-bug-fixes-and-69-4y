"""Example: audit Task (taskfile.dev) configs with TaskfileAnalyzer."""

from devai.taskfile_analyzer import TaskfileAnalyzer

analyzer = TaskfileAnalyzer(".")
findings = analyzer.analyze()

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in findings[:10]:
    print(finding.format())

if not findings:
    print("No issues found — or no Taskfile present.")
    print("\nHardened template:\n")
    print(analyzer.generate_hardened_template())
