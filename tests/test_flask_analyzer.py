"""Tests for FlaskAnalyzer."""

from pathlib import Path

from devai.flask_analyzer import FlaskAnalyzer, FlaskFinding


INSECURE_FLASK_APP = """\
from flask import Flask, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded-flask-secret-key'
app.config['DEBUG'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)

CORS_ORIGINS = '*'
WEBHOOK = 'http://192.168.1.50/callback'
API_URL = 'http://example.com/api'

@app.route('/render')
def render_page():
    return render_template_string(request.args.get('tpl', ''))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
"""

HARDENED_FLASK_APP = """\
import os

from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
app.config['SESSION_COOKIE_SECURE'] = not app.config['DEBUG']
app.config['SESSION_COOKIE_HTTPONLY'] = True
"""


class TestFlaskAnalyzer:
    def test_detects_insecure_flask_app(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(INSECURE_FLASK_APP, encoding="utf-8")
        analyzer = FlaskAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "hardcoded_secret" in kinds
        assert "debug_enabled" in kinds
        assert "ssti_risk" in kinds
        assert "cors_wildcard" in kinds
        assert "session_insecure" in kinds
        assert "httponly_disabled" in kinds
        assert "internal_url" in kinds
        assert "long_session_lifetime" in kinds
        assert analyzer.health_score() < 50.0

    def test_hardened_flask_app_scores_well(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_FLASK_APP, encoding="utf-8")
        analyzer = FlaskAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_no_app_returns_empty(self, tmp_path: Path):
        analyzer = FlaskAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no application" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = FlaskFinding(
            kind="test",
            severity="high",
            message="test message",
            path="app.py",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(HARDENED_FLASK_APP, encoding="utf-8")
        analyzer = FlaskAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "Flask application analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = FlaskAnalyzer(".").generate_hardened_template()
        assert 'SESSION_COOKIE_HTTPONLY"] = True' in template or "SESSION_COOKIE_HTTPONLY" in template
        assert "SECRET_KEY" in template
