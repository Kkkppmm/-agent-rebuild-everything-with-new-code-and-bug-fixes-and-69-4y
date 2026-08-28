"""Example: audit Flux CD GitOps configs with FluxCDAnalyzer."""

from pathlib import Path

from devai import DevAI

if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    analyzer = DevAI.mock().flux_cd(root)
    print(analyzer.summary())
    if analyzer.stats.findings:
        print("\nFindings:")
        for finding in analyzer.analyze()[:10]:
            print(finding.format())
