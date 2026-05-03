"""Output formatters for review results."""

import json
from rich.table import Table
from rich.panel import Panel


def print_report(issues, console):
    """Print a rich formatted report to the console."""
    if not issues:
        console.print(Panel("[bold green]No issues found! Code looks clean.[/]", style="green"))
        return

    severity_styles = {
        "critical": "bold red",
        "high": "yellow",
        "medium": "cyan",
        "low": "white",
    }

    table = Table(title="Code Review Report", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=20)
    table.add_column("File", style="dim")
    table.add_column("Line", width=6, justify="right")
    table.add_column("Message")

    for issue in sorted(issues, key=lambda x: ["low", "medium", "high", "critical"].index(x["severity"])):
        style = severity_styles.get(issue["severity"], "white")
        table.add_row(
            f"[{style}]{issue['severity'].upper()}[/]",
            issue["rule_id"],
            issue.get("file", "-"),
            str(issue.get("line", "-")),
            issue["message"],
        )

    console.print(table)

    # Summary
    counts = {}
    for issue in issues:
        counts[issue["severity"]] = counts.get(issue["severity"], 0) + 1

    summary_parts = []
    for sev in ["critical", "high", "medium", "low"]:
        if sev in counts:
            style = severity_styles[sev]
            summary_parts.append(f"[{style}]{counts[sev]} {sev}[/]")

    console.print(f"\nTotal: {len(issues)} issues ({', '.join(summary_parts)})")


def export_json(issues, output_path=None):
    """Export issues as JSON."""
    data = {
        "total": len(issues),
        "issues": issues,
    }
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)


def export_markdown(issues, output_path=None):
    """Export issues as Markdown."""
    lines = ["# Code Review Report\n"]

    if not issues:
        lines.append("No issues found! Code looks clean.\n")
    else:
        lines.append(f"**{len(issues)} issues found**\n")
        lines.append("| Severity | Rule | File | Line | Message |")
        lines.append("|----------|------|------|------|---------|")
        for issue in sorted(issues, key=lambda x: ["low", "medium", "high", "critical"].index(x["severity"])):
            lines.append(
                f"| {issue['severity'].upper()} | {issue['rule_id']} "
                f"| {issue.get('file', '-')} | {issue.get('line', '-')} "
                f"| {issue['message']} |"
            )

    text = "\n".join(lines) + "\n"
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)
