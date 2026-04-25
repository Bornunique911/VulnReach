"""vulnreach scan — start a scan and optionally wait for results."""

import sys
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

console = Console()

_TERMINAL = {"completed", "blocked", "partial", "failed"}


def _print_summary(scan: dict) -> None:
    meta = scan.get("metadata") or {}
    corr = scan.get("correlation") or []
    verdicts = {}
    for f in corr:
        v = f.get("verdict", "UNKNOWN")
        verdicts[v] = verdicts.get(v, 0) + 1

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("[bold]Scan ID[/bold]", scan.get("scan_id", "—"))
    table.add_row("[bold]Status[/bold]", scan.get("status", "—"))
    table.add_row("[bold]Repo[/bold]", meta.get("repo_path") or meta.get("repo_url") or "—")
    for verdict, count in sorted(verdicts.items()):
        colour = {"CONFIRMED": "red", "LIKELY": "yellow", "POSSIBLE": "blue"}.get(verdict, "dim")
        table.add_row(f"[bold]{verdict}[/bold]", f"[{colour}]{count}[/{colour}]")
    console.print(table)


def _print_coverage_warning(scan: dict) -> None:
    coverage = scan.get("analysis_coverage") or {}
    skipped = coverage.get("tools_skipped") or {}
    errored = coverage.get("tools_errored") or {}
    if not skipped and not errored:
        return

    console.print()
    console.print("[bold yellow][!] Partial analysis — not all evidence layers were collected[/bold yellow]")
    for tool, reason in skipped.items():
        console.print(f"    [yellow]skipped[/yellow]  {tool}: {reason}")
    for tool, reason in errored.items():
        console.print(f"    [red]errored[/red]   {tool}: {reason}")

    layers = coverage.get("evidence_layers") or {}
    missing = [name for name, ran in layers.items() if not ran]
    if missing:
        console.print(f"    [dim]Missing layers: {', '.join(missing)}[/dim]")
    console.print("    [dim]Results may under-report reachability. Check docs/configuration.md for setup.[/dim]")


@click.command()
@click.option("--repo-path", default=None, help="Local path to the repository.")
@click.option("--repo-url", default=None, help="Remote repository URL (git clone).")
@click.option("--config", "config_path", default=None, help="Path to a vulnreach YAML config.")
@click.option("--tools", default=None, help="Comma-separated list of tools to run.")
@click.option("--wait/--no-wait", default=True, show_default=True, help="Wait for the scan to finish.")
@click.option(
    "--fail-on",
    default="none",
    type=click.Choice(["CONFIRMED", "LIKELY", "POSSIBLE", "none"], case_sensitive=False),
    show_default=True,
    help="Exit code 1 if any finding reaches this verdict or worse.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    repo_path: Optional[str],
    repo_url: Optional[str],
    config_path: Optional[str],
    tools: Optional[str],
    wait: bool,
    fail_on: str,
) -> None:
    """Start a vulnerability reachability scan."""
    if not repo_path and not repo_url:
        raise click.UsageError("Provide --repo-path or --repo-url.")

    tools_list = [t.strip() for t in tools.split(",")] if tools else None
    mode = ctx.obj.get("mode", "local")

    if mode == "client":
        if repo_path and not config_path:
            raise click.UsageError(
                "Server mode requires --config when using --repo-path. "
                "Use --repo-url instead for zero-config remote scans."
            )
        from vulnreach.client import VulnReachClient
        client = VulnReachClient(ctx.obj["url"], ctx.obj.get("token"))
        result = client.start_scan(repo_path=repo_path, repo_url=repo_url, config_path=config_path, tools=tools_list)
        scan_id = result.get("scan_id")
        console.print(f"[green]Scan started:[/green] {scan_id}")
        if not wait:
            click.echo(scan_id)
            return
        console.print("Waiting for scan to complete…", style="dim")
        scan_data = client.poll_scan(scan_id)
    else:
        from vulnreach.local import run_local_scan
        console.print("Running scan locally…", style="dim")
        scan_data = run_local_scan(
            repo_path=repo_path,
            repo_url=repo_url,
            config_path=config_path,
            tools=tools_list,
        )

    _print_summary(scan_data)
    _print_coverage_warning(scan_data)

    # Emit scan_id to stdout for scripting
    click.echo(scan_data.get("scan_id", ""))

    if fail_on != "none":
        severity_order = ["CONFIRMED", "LIKELY", "POSSIBLE"]
        threshold = severity_order.index(fail_on.upper()) if fail_on.upper() in severity_order else 99
        for finding in scan_data.get("correlation") or []:
            v = (finding.get("verdict") or "").upper()
            if v in severity_order and severity_order.index(v) <= threshold:
                console.print(f"[red]Failing: found {v} finding(s)[/red]")
                sys.exit(1)
