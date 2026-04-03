"""
vulnreach — main CLI entry point.

Mode detection:
  --url / VULNREACH_URL set  →  client mode (HTTP calls to a running server)
  otherwise                  →  standalone mode (runs pipeline locally via SQLite)
"""

import click

from vulnreach.cli import scan as _scan_mod
from vulnreach.cli import fix_plan as _fix_plan_mod
from vulnreach.cli import replay as _replay_mod
from vulnreach.cli import explain as _explain_mod


@click.group()
@click.option(
    "--url",
    envvar="VULNREACH_URL",
    default=None,
    metavar="URL",
    help="VulnReach server URL.  If omitted, runs the pipeline locally (standalone mode).",
)
@click.option(
    "--token",
    envvar="VULNREACH_TOKEN",
    default=None,
    metavar="TOKEN",
    help="Bearer token for the VulnReach API (client mode only).",
)
@click.version_option(package_name="vulnreach")
@click.pass_context
def cli(ctx: click.Context, url: str, token: str) -> None:
    """VulnReach — proves which CVEs are actually exploitable."""
    ctx.ensure_object(dict)
    ctx.obj["mode"] = "client" if url else "local"
    ctx.obj["url"] = url
    ctx.obj["token"] = token


cli.add_command(_scan_mod.scan)
cli.add_command(_fix_plan_mod.fix_plan, name="fix-plan")
cli.add_command(_replay_mod.replay)
cli.add_command(_explain_mod.explain)
