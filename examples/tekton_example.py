"""Example: audit Tekton pipelines with TektonAnalyzer."""

from pathlib import Path

from devai import DevAI

if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    analyzer = DevAI.mock().tekton(root)
    print(analyzer.summary())
    if analyzer.stats.findings:
        print("\nFindings:")
        for finding in analyzer.analyze()[:10]:
            print(finding.format())
