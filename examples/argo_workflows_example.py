"""Audit Argo Workflows with DevAI."""

from devai import DevAI

analyzer = DevAI.mock().argo_workflows(".")
print(analyzer.summary())

if analyzer.stats.findings:
    print("\nFindings:")
    for finding in analyzer.analyze()[:10]:
        print(finding.format())
else:
    print("\nNo issues found (or no Argo Workflows present).")
    print("\nHardened template:\n")
    print(analyzer.generate_hardened_template())
