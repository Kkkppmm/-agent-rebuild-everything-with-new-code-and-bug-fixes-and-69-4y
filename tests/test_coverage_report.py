"""Tests for DevAI CoverageReport."""

from pathlib import Path

import pytest

from devai.coverage_report import CoverageReport


SAMPLE_XML = """<?xml version="1.0" ?>
<coverage line-rate="0.75" lines-covered="3" lines-valid="4" version="7.0">
  <packages>
    <package name="src" line-rate="0.75" lines-covered="3" lines-valid="4">
      <classes>
        <class name="app.py" filename="src/app.py" line-rate="0.5" lines-covered="1" lines-valid="2">
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="0"/>
          </lines>
        </class>
        <class name="util.py" filename="src/util.py" line-rate="1.0" lines-covered="2" lines-valid="2">
          <lines>
            <line number="1" hits="3"/>
            <line number="2" hits="1"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"""


class TestCoverageReport:
    def test_parse_summary(self):
        report = CoverageReport(SAMPLE_XML)
        stats = report.parse()
        assert stats.lines_valid == 4
        assert stats.lines_covered == 3
        assert stats.coverage_pct == 75.0
        assert stats.files == 2

    def test_uncovered_files(self):
        report = CoverageReport(SAMPLE_XML)
        uncovered = report.uncovered_files(100.0)
        assert len(uncovered) == 1
        assert uncovered[0].path == "src/app.py"
        assert uncovered[0].missing_lines == [2]

    def test_worst_files(self):
        report = CoverageReport(SAMPLE_XML)
        worst = report.worst_files()
        assert worst[0].path == "src/app.py"
        assert worst[0].coverage_pct == 50.0

    def test_summary_and_context(self):
        report = CoverageReport(SAMPLE_XML)
        summary = report.summary()
        assert "75.0%" in summary
        context = report.to_context()
        assert "Test coverage analysis" in context
        assert "src/app.py" in context

    def test_from_file(self, tmp_path: Path):
        xml_path = tmp_path / "coverage.xml"
        xml_path.write_text(SAMPLE_XML, encoding="utf-8")
        report = CoverageReport(xml_path)
        assert report.stats.coverage_pct == 75.0

    def test_invalid_xml(self):
        with pytest.raises(ValueError, match="Invalid coverage XML"):
            CoverageReport("<not valid xml").parse()
