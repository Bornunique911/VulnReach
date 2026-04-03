"""vulnreach explain — human-readable explanation of a CVE finding."""

from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

console = Console()


@click.command()
@click.argument("cve_id")
@click.option("--scan-id", required=True, help="Scan ID containing the finding.")
@click.option(
    "--provider",
    default="none",
    type=click.Choice(["none", "anthropic"], case_sensitive=False),
    show_default=True,
    help="none = offline structured summary; anthropic = LLM-generated explanation.",
)
@click.option("--model", default=None, help="LLM model override (anthropic provider only).")
@click.pass_context
def explain(ctx: click.Context, cve_id: str, scan_id: str, provider: str, model: Optional[str]) -> None:
    """Explain how a CVE is reachable in the scanned codebase.

    \b
    Examples:
      vulnreach explain CVE-2023-32681 --scan-id abc123
      vulnreach explain CVE-2023-32681 --scan-id abc123 --provider anthropic
    """
    mode = ctx.obj.get("mode", "local")

    if mode == "client":
        from vulnreach.client import VulnReachClient
        client = VulnReachClient(ctx.obj["url"], ctx.obj.get("token"))
        data = client.get_explanation(scan_id, cve_id, provider=provider)
        explanation = data.get("explanation", "")
    else:
        from storage import get_repository
        from api.explain import build_explanation
        storage = get_repository()
        scan = storage.get_scan(scan_id)
        if not scan:
            raise click.ClickException(f"Scan {scan_id!r} not found.")
        explanation = build_explanation(scan, cve_id, provider=provider, model=model)

    console.print(Panel(explanation, title=f"[bold]{cve_id}[/bold]", border_style="cyan"))
