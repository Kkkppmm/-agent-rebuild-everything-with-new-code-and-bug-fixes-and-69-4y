"""Example: detect Jinja2 environments without autoescape."""

from devai import TemplateAutoescapeAnalyzer, SecurityScanner

if __name__ == "__main__":
  analyzer = TemplateAutoescapeAnalyzer("examples")
  for finding in analyzer.analyze():
    print(finding.format())

  report = SecurityScanner("examples", checks=("template_autoescape",)).scan()
  print(report.summary())
