"""Example: scan for insecure Redis, MongoDB, and Kafka configuration."""

from devai import (
    InsecureKafkaSettingsAnalyzer,
    InsecureMongoSettingsAnalyzer,
    InsecureRedisSettingsAnalyzer,
    SecurityScanner,
)

checks = (
    "insecure_redis_settings",
    "insecure_mongo_settings",
    "insecure_kafka_settings",
)
report = SecurityScanner(".", checks=checks).scan()
print(report.summary())

for analyzer_cls in (
    InsecureRedisSettingsAnalyzer,
    InsecureMongoSettingsAnalyzer,
    InsecureKafkaSettingsAnalyzer,
):
    analyzer = analyzer_cls(".")
    for finding in analyzer.analyze():
        print(finding.format())
