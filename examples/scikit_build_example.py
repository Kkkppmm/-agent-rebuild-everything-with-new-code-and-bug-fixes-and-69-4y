"""Example: audit scikit-build-core pyproject.toml and CMakeLists.txt with ScikitBuildAnalyzer."""

from devai.scikit_build_analyzer import ScikitBuildAnalyzer

analyzer = ScikitBuildAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
