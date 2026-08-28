"""Example: audit lefthook git hook configs with LefthookAnalyzer."""

from devai.lefthook_analyzer import LefthookAnalyzer

analyzer = LefthookAnalyzer(".")
print(analyzer.summary())

findings = analyzer.analyze()
if findings:
    print(f"\n{len(findings)} finding(s):")
    for finding in findings[:10]:
        print(f"  {finding.format()}")
else:
    print("No issues found — or no lefthook config present.")
