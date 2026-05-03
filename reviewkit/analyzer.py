"""Code analysis engine with built-in review rules."""

import re
import os


# ─── Review Rules ───────────────────────────────────────────────────────────

RULES = [
    # Security - Critical
    {
        "id": "SEC-001",
        "category": "security",
        "severity": "critical",
        "description": "Hardcoded secret or API key detected",
        "pattern": r"""(?i)(api[_-]?key|secret|password|token|auth)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{8,}['"]""",
        "message": "Hardcoded secret detected. Use environment variables or a secrets manager.",
    },
    {
        "id": "SEC-002",
        "category": "security",
        "severity": "critical",
        "description": "SQL injection vulnerability",
        "pattern": r"""(?i)(execute|cursor\.execute|query)\s*\(\s*['"].*%s|.*\.format\(|.*f['"]\{.*\}.*['"].*\)""",
        "message": "Possible SQL injection. Use parameterized queries instead.",
    },
    {
        "id": "SEC-003",
        "category": "security",
        "severity": "critical",
        "description": "Command injection via os.system or subprocess with shell=True",
        "pattern": r"""(os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True)""",
        "message": "Command injection risk. Avoid shell=True or use shlex.quote().",
    },
    {
        "id": "SEC-004",
        "category": "security",
        "severity": "critical",
        "description": "Use of eval() or exec()",
        "pattern": r"""\b(eval|exec)\s*\(""",
        "message": "eval()/exec() can execute arbitrary code. Avoid or validate input strictly.",
    },
    {
        "id": "SEC-005",
        "category": "security",
        "severity": "high",
        "description": "Insecure random number generation",
        "pattern": r"""random\.(random|randint|choice|randrange)\s*\(""",
        "message": "Using 'random' module for security-sensitive operations. Use 'secrets' module instead.",
    },
    {
        "id": "SEC-006",
        "category": "security",
        "severity": "high",
        "description": "Disabled SSL verification",
        "pattern": r"""(verify\s*=\s*False|CERT_NONE|ssl_verify\s*[:=]\s*false)""",
        "message": "SSL verification disabled. This exposes connections to MITM attacks.",
    },
    {
        "id": "SEC-007",
        "category": "security",
        "severity": "high",
        "description": "Dangerous file permissions",
        "pattern": r"""chmod\s+[0-7]*7[0-7]*\s""",
        "message": "Setting world-readable/writable permissions. Restrict file access.",
    },
    {
        "id": "SEC-008",
        "category": "security",
        "severity": "high",
        "description": "Use of pickle for deserialization",
        "pattern": r"""pickle\.loads?\s*\(""",
        "message": "Pickle deserialization can execute arbitrary code. Use JSON or msgpack.",
    },
    {
        "id": "SEC-009",
        "category": "security",
        "severity": "medium",
        "description": "Use of deprecated MD5/SHA1 for hashing",
        "pattern": r"""hashlib\.(md5|sha1)\s*\(""",
        "message": "MD5/SHA1 are cryptographically broken. Use SHA-256 or better.",
    },

    # Performance
    {
        "id": "PERF-001",
        "category": "performance",
        "severity": "medium",
        "description": "String concatenation in a loop",
        "pattern": r"""(\+\s*=\s*['"].*['"]|\.join\()""",
        "message": "Consider using list.append() + join() for string building in loops.",
        "check_context": "in_loop",
    },
    {
        "id": "PERF-002",
        "category": "performance",
        "severity": "medium",
        "description": "Using 'in' on a list in a loop (O(n) lookup)",
        "pattern": r"""\bin\s+\[([^\]]+)\]""",
        "message": "Using a list for membership testing. Convert to a set for O(1) lookup.",
    },
    {
        "id": "PERF-003",
        "category": "performance",
        "severity": "medium",
        "description": "Nested loop detected",
        "pattern": r"""for\s+\w+.*:\s*$""",
        "message": "Nested loop detected. Consider if this can be optimized.",
        "check_nested": True,
    },
    {
        "id": "PERF-004",
        "category": "performance",
        "severity": "low",
        "description": "Using len() in loop condition",
        "pattern": r"""while\s+.*len\(""",
        "message": "len() in while condition is fine for lists, but cache it for custom objects.",
    },

    # Code Quality
    {
        "id": "QUAL-001",
        "category": "quality",
        "severity": "medium",
        "description": "TODO/FIXME/HACK comment left in code",
        "pattern": r"""(TODO|FIXME|HACK|XXX|TEMP)\b""",
        "message": "Unresolved TODO/FIXME comment. Address before merging.",
    },
    {
        "id": "QUAL-002",
        "category": "quality",
        "severity": "medium",
        "description": "Function too long (>50 lines)",
        "pattern": r"""^(def |async def )""",
        "message": "Consider breaking long functions into smaller ones.",
        "check_length": 50,
    },
    {
        "id": "QUAL-003",
        "category": "quality",
        "severity": "low",
        "description": "Bare except clause",
        "pattern": r"""except\s*:""",
        "message": "Bare except catches all exceptions including KeyboardInterrupt. Catch specific exceptions.",
    },
    {
        "id": "QUAL-004",
        "category": "quality",
        "severity": "low",
        "description": "Unused import (heuristic)",
        "pattern": r"""^import\s+(\w+)|^from\s+\S+\s+import\s+(\w+)""",
        "message": "Potentially unused import. Verify it's actually used.",
        "check_usage": True,
    },
    {
        "id": "QUAL-005",
        "category": "quality",
        "severity": "medium",
        "description": "Magic number",
        "pattern": r"""(?<![.\w])\b(?!0[xXbBoO])[2-9]\d{2,}\b(?![.\w])""",
        "message": "Magic number detected. Consider extracting to a named constant.",
        "exclude_context": ["import", "version", "port", "status", "http"],
    },

    # JavaScript/TypeScript specific
    {
        "id": "SEC-JS-001",
        "category": "security",
        "severity": "critical",
        "description": "Dangerous use of innerHTML",
        "pattern": r"""\.innerHTML\s*=""",
        "message": "innerHTML assignment can lead to XSS. Use textContent or sanitize input.",
    },
    {
        "id": "SEC-JS-002",
        "category": "security",
        "severity": "critical",
        "description": "Use of document.write",
        "pattern": r"""document\.write\s*\(""",
        "message": "document.write() is dangerous and blocks parsing. Use DOM manipulation.",
    },
    {
        "id": "QUAL-JS-001",
        "category": "quality",
        "severity": "low",
        "description": "Use of console.log in production code",
        "pattern": r"""console\.(log|debug|info)\s*\(""",
        "message": "Remove console.log before production. Use a proper logging library.",
    },
    {
        "id": "QUAL-JS-002",
        "category": "quality",
        "severity": "medium",
        "description": "Use of == instead of ===",
        "pattern": r"""[^=!<>]==[^=]""",
        "message": "Use === for strict equality comparison to avoid type coercion bugs.",
    },

    # Go specific
    {
        "id": "QUAL-GO-001",
        "category": "quality",
        "severity": "medium",
        "description": "Ignored error return value",
        "pattern": r"""^\s+\w+\.\w+\([^)]*\)\s*$""",
        "message": "Possible ignored error. Check if the function returns an error.",
        "file_ext": [".go"],
    },

    # General
    {
        "id": "GEN-001",
        "category": "quality",
        "severity": "low",
        "description": "Line too long (>120 characters)",
        "pattern": r"""^.{121,}$""",
        "message": "Line exceeds 120 characters. Consider breaking it up.",
    },
    {
        "id": "GEN-002",
        "category": "quality",
        "severity": "low",
        "description": "Trailing whitespace",
        "pattern": r"""[ \t]+$""",
        "message": "Trailing whitespace detected.",
    },
]


# ─── File extensions to skip ────────────────────────────────────────────────

SKIP_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock", ".sum",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class", ".o",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".next", ".nuxt",
    "coverage", ".pytest_cache", ".mypy_cache",
}


# ─── Analysis Functions ─────────────────────────────────────────────────────

def _should_skip_file(filepath):
    """Check if a file should be skipped."""
    filepath_lower = filepath.lower()
    for ext in SKIP_EXTENSIONS:
        if filepath_lower.endswith(ext):
            return True
    parts = filepath.replace("\\", "/").split("/")
    for part in parts:
        if part in SKIP_DIRS:
            return True
    return False


def _get_file_lines(filepath):
    """Read file lines, handling encoding errors."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except (OSError, IOError):
        return []


def _check_rule_on_line(rule, line, line_num, filepath, file_lines=None):
    """Check a single rule against a single line. Returns issue or None."""
    pattern = rule["pattern"]

    # File extension filter
    if "file_ext" in rule:
        if not any(filepath.endswith(ext) for ext in rule["file_ext"]):
            return None

    # Skip non-code lines for certain patterns
    stripped = line.strip()
    if not stripped or stripped.startswith("#") and rule["category"] != "quality":
        # Still check quality rules on comments (for TODO etc)
        if "TODO" not in pattern and "FIXME" not in pattern:
            return None

    # Exclude context check (skip if line contains certain keywords)
    if "exclude_context" in rule:
        if any(kw in line.lower() for kw in rule["exclude_context"]):
            return None

    # Length check for QUAL-002
    if rule.get("check_length"):
        if rule["id"] == "QUAL-002" and re.match(pattern, line):
            # Count function length
            if file_lines:
                func_start = line_num - 1
                indent = len(line) - len(line.lstrip())
                count = 0
                for i in range(func_start + 1, len(file_lines)):
                    if file_lines[i].strip() == "":
                        count += 1
                        continue
                    current_indent = len(file_lines[i]) - len(file_lines[i].lstrip())
                    if current_indent <= indent and file_lines[i].strip():
                        break
                    count += 1
                if count > rule["check_length"]:
                    return _make_issue(rule, filepath, line_num, f"Function is {count} lines long (>{rule['check_length']}).")
            return None

    # Nested loop check
    if rule.get("check_nested") and file_lines:
        if re.match(pattern, line) and line_num < len(file_lines):
            # Check if there's another for loop inside
            indent = len(line) - len(line.lstrip())
            for i in range(line_num, min(line_num + 30, len(file_lines))):
                if file_lines[i].strip() == "":
                    continue
                current_indent = len(file_lines[i]) - len(file_lines[i].lstrip())
                if current_indent <= indent and i > line_num:
                    break
                if current_indent > indent and re.match(r"\s*for\s+", file_lines[i]):
                    return _make_issue(rule, filepath, line_num)
            return None

    # In-loop context check
    if rule.get("check_context") == "in_loop" and file_lines:
        # Simple heuristic: check if previous lines have a for/while
        in_loop = False
        for i in range(max(0, line_num - 20), line_num):
            if re.match(r"\s*(for|while)\s+", file_lines[i]):
                in_loop = True
                break
        if not in_loop:
            return None

    # Main pattern match
    if re.search(pattern, line):
        return _make_issue(rule, filepath, line_num)

    return None


def _make_issue(rule, filepath, line, extra_message=None):
    """Create an issue dict."""
    return {
        "rule_id": rule["id"],
        "category": rule["category"],
        "severity": rule["severity"],
        "description": rule["description"],
        "message": extra_message or rule["message"],
        "file": filepath,
        "line": line,
    }


def analyze_line(line, line_num, filepath, file_lines=None, min_severity=0):
    """Analyze a single line against all rules."""
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    issues = []

    for rule in RULES:
        if severity_order.get(rule["severity"], 0) < min_severity:
            continue
        issue = _check_rule_on_line(rule, line, line_num, filepath, file_lines)
        if issue:
            issues.append(issue)

    return issues


def analyze_diff(diff_text, files=None, min_severity=0):
    """Analyze a diff string for issues. Only checks added lines."""
    issues = []
    current_file = None
    line_num = 0

    for line in diff_text.split("\n"):
        # Track file changes
        if line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@"):
            # Parse line number from hunk header
            match = re.search(r"\+(\d+)", line)
            if match:
                line_num = int(match.group(1))
            continue

        # Only analyze added lines
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            if current_file and not _should_skip_file(current_file):
                found = analyze_line(content, line_num, current_file, min_severity=min_severity)
                issues.extend(found)
            line_num += 1
        elif not line.startswith("-"):
            line_num += 1

    return issues


def analyze_files(directory, min_severity=0):
    """Analyze all files in a directory."""
    issues = []

    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)

            if _should_skip_file(rel_path):
                continue

            file_lines = _get_file_lines(filepath)
            for line_num, line in enumerate(file_lines, 1):
                found = analyze_line(line, line_num, rel_path, file_lines, min_severity)
                issues.extend(found)

    return issues
