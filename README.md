# reviewkit

AI-powered code review CLI. Runs 100% locally — your code never leaves your machine.

## Install

```bash
pip install reviewkit
```

## Usage

### Review a GitHub PR

```bash
reviewkit review https://github.com/owner/repo/pull/123
```

### Review local changes

```bash
reviewkit review --path ./myproject
```

### Scan entire directory

```bash
reviewkit scan ./src
```

### Output formats

```bash
# JSON output
reviewkit review https://github.com/owner/repo/pull/123 --format json

# Markdown report
reviewkit scan . --format markdown --output report.md
```

### Filter by severity

```bash
reviewkit scan . --severity high
```

## What it checks

### Security (SEC-*)
- Hardcoded secrets and API keys
- SQL injection vulnerabilities
- Command injection (os.system, shell=True)
- Dangerous eval()/exec() usage
- Insecure random for crypto
- Disabled SSL verification
- Insecure deserialization (pickle)
- XSS via innerHTML
- Weak hash algorithms (MD5/SHA1)

### Performance (PERF-*)
- String concatenation in loops
- List membership testing (use sets)
- Nested loop detection
- len() in loop conditions

### Code Quality (QUAL-*)
- TODO/FIXME/HACK comments
- Overly long functions (>50 lines)
- Bare except clauses
- Unused imports
- Magic numbers
- console.log in JS
- == instead of === in JS

### General (GEN-*)
- Lines over 120 characters
- Trailing whitespace

## Rules

```bash
reviewkit rules
```

Lists all available review rules with severity levels.

## CI Integration

### GitHub Actions

```yaml
- name: Code Review
  run: |
    pip install reviewkit
    reviewkit review ${{ github.event.pull_request.html_url }} --severity high
```

Exit codes:
- `0` — No critical/high issues
- `1` — Critical issues found (blocks merge)

## GitHub Token

For private repos, set `GITHUB_TOKEN`:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx
```

## License

MIT
