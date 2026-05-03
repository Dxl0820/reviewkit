# Reddit / HN / V2EX Post

## Title (Reddit r/commandline)

I built reviewkit: an open-source code review CLI that runs 100% locally

## Body

Hey r/commandline! I built `reviewkit`, a CLI tool for code review that runs entirely on your machine.

**What it does:**
- Scans code for security issues (hardcoded secrets, SQL injection, XSS, command injection)
- Performance anti-patterns (nested loops, list membership in loops)
- Code quality issues (bare excepts, magic numbers, TODO comments)
- Works with GitHub PRs or local files

**Install:**
```bash
pip install reviewkit
```

**Usage:**
```bash
# Review a GitHub PR
reviewkit review https://github.com/owner/repo/pull/123

# Scan local files
reviewkit scan ./src

# Filter by severity
reviewkit scan . --severity high
```

**Why local?** No code uploads, no API keys needed, no privacy concerns. Everything runs on your machine with regex-based pattern matching.

25 built-in rules across security, performance, and quality categories. Supports Python, JavaScript, TypeScript, Go, and more.

GitHub: https://github.com/Dxl0820/reviewkit

Would love feedback on what rules to add next!

---

## Title (Hacker News)

Show HN: reviewkit – Open-source code review CLI, 100% local

## Body

I built reviewkit, a code review CLI tool that analyzes code for security, performance, and quality issues without sending anything to external servers.

Unlike cloud-based review tools, reviewkit runs entirely locally using regex pattern matching. No API keys, no code uploads, no subscriptions required for the core features.

It supports reviewing GitHub PRs directly from the CLI and can output in text, JSON, or Markdown formats for CI integration.

25 built-in rules including: hardcoded secrets detection, SQL/command injection, XSS, insecure crypto, nested loops, bare excepts, and more.

pip install reviewkit && reviewkit scan ./src

GitHub: https://github.com/Dxl0820/reviewkit

---

## V2EX (中文)

开了一个开源项目 reviewkit — 本地代码审查 CLI 工具

不需要上传代码到云端，不需要 API key，所有检查都在本地运行。

安装：pip install reviewkit
用法：reviewkit scan ./src

支持 25 条内置规则，覆盖安全、性能、代码质量。支持 Python/JS/TS/Go 等语言。

GitHub: https://github.com/Dxl0820/reviewkit
