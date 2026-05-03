"""Tests for the analyzer module."""

import os
import tempfile
import pytest
from reviewkit.analyzer import analyze_line, analyze_files, analyze_diff, RULES


class TestAnalyzeLine:
    """Test individual line analysis."""

    def test_detects_hardcoded_secret(self):
        line = 'API_KEY = "sk-abc123def456ghi789"'
        issues = analyze_line(line, 1, "config.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-001" in rule_ids

    def test_detects_sql_injection(self):
        line = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        issues = analyze_line(line, 1, "db.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-002" in rule_ids

    def test_detects_eval(self):
        line = "result = eval(user_input)"
        issues = analyze_line(line, 1, "utils.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-004" in rule_ids

    def test_detects_shell_true(self):
        line = 'subprocess.run(cmd, shell=True)'
        issues = analyze_line(line, 1, "runner.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-003" in rule_ids

    def test_detects_innerhtml(self):
        line = 'element.innerHTML = userInput;'
        issues = analyze_line(line, 1, "app.js")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-JS-001" in rule_ids

    def test_detects_console_log(self):
        line = 'console.log("debug");'
        issues = analyze_line(line, 1, "app.js")
        rule_ids = [i["rule_id"] for i in issues]
        assert "QUAL-JS-001" in rule_ids

    def test_detects_bare_except(self):
        line = "except:"
        issues = analyze_line(line, 1, "handler.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "QUAL-003" in rule_ids

    def test_detects_todo(self):
        line = "# TODO: fix this later"
        issues = analyze_line(line, 1, "code.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "QUAL-001" in rule_ids

    def test_detects_pickle(self):
        line = "data = pickle.loads(raw_bytes)"
        issues = analyze_line(line, 1, "loader.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-008" in rule_ids

    def test_detects_disabled_ssl(self):
        line = 'requests.get(url, verify=False)'
        issues = analyze_line(line, 1, "client.py")
        rule_ids = [i["rule_id"] for i in issues]
        assert "SEC-006" in rule_ids

    def test_no_false_positive_on_normal_code(self):
        line = "def hello():"
        issues = analyze_line(line, 1, "app.py")
        # Should not trigger security issues
        security_issues = [i for i in issues if i["category"] == "security"]
        assert len(security_issues) == 0

    def test_severity_filter(self):
        line = 'API_KEY = "sk-abc123def456ghi789"'
        # min_severity=2 means only critical
        issues = analyze_line(line, 1, "config.py", min_severity=2)
        for issue in issues:
            assert issue["severity"] == "critical"


class TestAnalyzeDiff:
    """Test diff analysis."""

    def test_analyzes_added_lines_only(self):
        diff = """--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
-API_KEY = "old"
+API_KEY = "sk-newsecret12345678"
+DEBUG = True"""
        issues = analyze_diff(diff)
        # Should find the secret in the added line
        sec_issues = [i for i in issues if i["rule_id"] == "SEC-001"]
        assert len(sec_issues) >= 1

    def test_skips_deleted_lines(self):
        diff = """--- a/config.py
+++ b/config.py
@@ -1,2 +1,1 @@
-API_KEY = "sk-oldsecret12345678"
+API_KEY = os.environ["API_KEY"]"""
        issues = analyze_diff(diff)
        sec_issues = [i for i in issues if i["rule_id"] == "SEC-001"]
        assert len(sec_issues) == 0


class TestAnalyzeFiles:
    """Test file scanning."""

    def test_scans_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file with a known issue
            filepath = os.path.join(tmpdir, "test.py")
            with open(filepath, "w") as f:
                f.write('password = "supersecret123"\n')

            issues = analyze_files(tmpdir)
            assert len(issues) > 0
            sec_issues = [i for i in issues if i["category"] == "security"]
            assert len(sec_issues) >= 1

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create node_modules dir
            nm_dir = os.path.join(tmpdir, "node_modules", "pkg")
            os.makedirs(nm_dir)
            filepath = os.path.join(nm_dir, "index.js")
            with open(filepath, "w") as f:
                f.write('password = "secret123"\n')

            issues = analyze_files(tmpdir)
            nm_issues = [i for i in issues if "node_modules" in i.get("file", "")]
            assert len(nm_issues) == 0

    def test_skips_binary_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "image.png")
            with open(filepath, "wb") as f:
                f.write(b"\x89PNG\r\n\x1a\n")

            issues = analyze_files(tmpdir)
            assert len(issues) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
