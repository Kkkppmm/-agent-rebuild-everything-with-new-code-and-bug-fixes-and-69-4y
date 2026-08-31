"""Example: audit .envrc and direnv.toml with DirenvAnalyzer."""

from devai.direnv_analyzer import DirenvAnalyzer

analyzer = DirenvAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
