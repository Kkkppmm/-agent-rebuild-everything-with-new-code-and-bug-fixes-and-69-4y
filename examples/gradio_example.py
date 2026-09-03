"""Audit a Gradio project for security risks."""

from devai import GradioAnalyzer

analyzer = GradioAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
