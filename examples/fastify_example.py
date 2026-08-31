"""Example: audit a Fastify application with DevAI."""

from devai import FastifyAnalyzer

analyzer = FastifyAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
