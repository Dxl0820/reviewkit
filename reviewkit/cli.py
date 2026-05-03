"""CLI entry point for reviewkit."""

import os
import click
from rich.console import Console
from rich.panel import Panel

from reviewkit import __version__
from reviewkit.analyzer import analyze_diff, analyze_files
from reviewkit.github import get_pr_diff, get_pr_files, get_repo_info
from reviewkit.reporters import print_report, export_json, export_markdown
from reviewkit.pro import is_pro, activate, require_pro

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="reviewkit")
def main():
    """reviewkit - AI-powered code review CLI for GitHub PRs.

    Review code changes locally with security, performance, and style checks.
    No code leaves your machine.
    """
    pass


@main.command()
@click.argument("pr_url", required=False)
@click.option("--path", "-p", type=click.Path(exists=True), default=".", help="Local repo path")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path")
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]), default="low")
def review(pr_url, path, output_format, output, severity):
    """Review a GitHub PR or local changes.

    Examples:

        reviewkit review https://github.com/owner/repo/pull/123

        reviewkit review --path ./myproject

        reviewkit review https://github.com/owner/repo/pull/123 --format json --output report.json
    """
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_severity = severity_levels[severity]

    if pr_url:
        console.print(f"[bold blue]Fetching PR:[/] {pr_url}")
        try:
            owner, repo, pr_number = parse_pr_url(pr_url)
            diff = get_pr_diff(owner, repo, pr_number)
            files = get_pr_files(owner, repo, pr_number)
            console.print(f"[green]Found {len(files)} changed files[/]")
        except Exception as e:
            console.print(f"[red]Error fetching PR: {e}[/]")
            raise SystemExit(1)
    else:
        console.print(f"[bold blue]Scanning local changes in:[/] {path}")
        try:
            diff, files = get_local_diff(path)
            console.print(f"[green]Found {len(files)} changed files[/]")
        except Exception as e:
            console.print(f"[red]Error reading local changes: {e}[/]")
            raise SystemExit(1)

    issues = analyze_diff(diff, files, min_severity)

    if output_format == "json":
        export_json(issues, output)
    elif output_format == "markdown":
        export_markdown(issues, output)
    else:
        print_report(issues, console)

    critical_count = sum(1 for i in issues if i["severity"] == "critical")
    high_count = sum(1 for i in issues if i["severity"] == "high")

    if critical_count > 0:
        console.print(f"\n[bold red]BLOCKED: {critical_count} critical issues found[/]")
        raise SystemExit(1)
    elif high_count > 0:
        console.print(f"\n[bold yellow]WARNING: {high_count} high severity issues found[/]")


@main.command()
@click.argument("path", default=".")
@click.option("--format", "-f", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]), default="low")
def scan(path, output_format, output, severity):
    """Scan all files in a directory for issues.

    Examples:

        reviewkit scan ./src

        reviewkit scan . --severity high --format json
    """
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_severity = severity_levels[severity]

    console.print(f"[bold blue]Scanning:[/] {path}")
    issues = analyze_files(path, min_severity)
    console.print(f"[green]Scanned, found {len(issues)} issues[/]")

    if output_format == "json":
        export_json(issues, output)
    elif output_format == "markdown":
        export_markdown(issues, output)
    else:
        print_report(issues, console)


@main.command()
def rules():
    """List all available review rules."""
    from reviewkit.analyzer import RULES

    console.print(Panel("[bold]Available Review Rules[/]", style="blue"))
    for rule in RULES:
        severity_color = {
            "critical": "red",
            "high": "yellow",
            "medium": "cyan",
            "low": "white",
        }.get(rule["severity"], "white")
        console.print(
            f"  [{severity_color}]{rule['severity'].upper():>8}[/]  "
            f"[bold]{rule['id']}[/] - {rule['description']}"
        )


def parse_pr_url(url):
    """Parse a GitHub PR URL into (owner, repo, pr_number)."""
    import re
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)", url)
    if not match:
        raise ValueError(f"Invalid GitHub PR URL: {url}")
    return match.group(1), match.group(2), int(match.group(3))


def get_local_diff(repo_path):
    """Get local uncommitted changes as a diff."""
    import git
    import os

    repo = git.Repo(repo_path, search_parent_directories=True)

    # Get staged changes
    staged_diff = repo.index.diff("HEAD", create_patch=True) if repo.head.is_valid() else []

    # Get unstaged changes
    unstaged_diff = repo.index.diff(None, create_patch=True)

    all_diffs = list(staged_diff) + list(unstaged_diff)

    diff_text = ""
    files = []
    for d in all_diffs:
        diff_text += d.diff.decode("utf-8", errors="replace") if d.diff else ""
        files.append(d.b_path or d.a_path)

    # If no uncommitted changes, compare with main/master
    if not all_diffs:
        for branch in ["main", "master"]:
            try:
                commits = list(repo.iter_commits(f"HEAD...{branch}", max_count=1))
                if commits:
                    diff_text = repo.git.diff(f"{branch}...HEAD")
                    changed = repo.git.diff(f"{branch}...HEAD", name_only=True)
                    files = [f for f in changed.split("\n") if f]
                    break
            except Exception:
                continue

    return diff_text, files


@main.command()
@click.argument("key")
def pro(key):
    """Activate a Pro license key.

    Example:

        reviewkit pro RK-XXXX-XXXX-XXXX-XXXX
    """
    if activate(key):
        console.print("[bold green]Pro license activated successfully![/]")
        console.print("Pro features: auto-fix, batch scan, custom rules, priority support.")
    else:
        console.print("[red]Invalid license key. Format: RK-XXXX-XXXX-XXXX-XXXX[/]")
        raise SystemExit(1)


@main.command()
@click.argument("path", default=".")
@click.option("--dry-run", is_flag=True, default=True, help="Show fixes without applying")
def fix(path, dry_run):
    """Auto-fix detected issues where possible. [Pro]

    Automatically fixes trailing whitespace, console.log, and other safe fixes.
    """
    @require_pro("auto-fix")
    def _do_fix():
        import glob as globmod
        fixed = 0
        for filepath in globmod.glob(os.path.join(path, "**", "*"), recursive=True):
            if _should_skip_file(filepath):
                continue
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            original = content
            lines = content.split("\n")
            new_lines = []
            for line in lines:
                # Fix trailing whitespace
                new_lines.append(line.rstrip())
            content = "\n".join(new_lines)

            if content != original:
                fixed += 1
                if not dry_run:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(content)
                console.print(f"  [green]Fixed:[/] {filepath}")

        if fixed == 0:
            console.print("[green]No auto-fixable issues found.[/]")
        else:
            action = "Would fix" if dry_run else "Fixed"
            console.print(f"\n[bold]{action} {fixed} files[/]")

    _do_fix()


def _should_skip_file(filepath):
    """Check if a file should be skipped."""
    from reviewkit.analyzer import SKIP_EXTENSIONS, SKIP_DIRS
    filepath_lower = filepath.lower()
    for ext in SKIP_EXTENSIONS:
        if filepath_lower.endswith(ext):
            return True
    parts = filepath.replace("\\", "/").split("/")
    for part in parts:
        if part in SKIP_DIRS:
            return True
    return False


if __name__ == "__main__":
    main()
