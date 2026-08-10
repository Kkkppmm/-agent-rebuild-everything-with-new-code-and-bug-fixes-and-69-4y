"""Example: audit Jenkinsfiles for pipeline security issues."""

from devai import JenkinsfileAnalyzer

analyzer = JenkinsfileAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
