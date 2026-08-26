"""Example: audit Taskfile.yml with TaskfileAnalyzer."""

from devai.taskfile_analyzer import TaskfileAnalyzer

analyzer = TaskfileAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
