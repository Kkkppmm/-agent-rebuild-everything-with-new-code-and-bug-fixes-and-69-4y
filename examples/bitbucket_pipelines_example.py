"""Audit Bitbucket Pipelines with DevAI."""

from pathlib import Path

from devai import DevAI

if __name__ == "__main__":
    root = Path(".")
    analyzer = DevAI.mock().bitbucket_pipelines(root)
    print(analyzer.summary())
    for finding in analyzer.analyze()[:10]:
        print(finding.format())
