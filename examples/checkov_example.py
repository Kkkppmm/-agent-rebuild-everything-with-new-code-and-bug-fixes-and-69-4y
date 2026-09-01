"""Example: audit Checkov IaC scanner configs with DevAI."""

from devai import CheckovAnalyzer, DevAI

if __name__ == "__main__":
    analyzer = DevAI.mock().checkov(".")
    print(analyzer.summary())
    for finding in analyzer.analyze()[:10]:
        print(finding.format())

    print("\n--- Hardened template ---")
    print(CheckovAnalyzer(".").generate_hardened_template())
