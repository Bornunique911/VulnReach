"""vulnreach replay — show the call graph for a CVE."""

import re
from typing import Optional

import click
from rich.console import Console

console = Console()


def _ascii_tree(mermaid: str) -> str:
    """Convert a Mermaid graph to a simple indented ASCII edge list."""
    edges = re.findall(r'"?([^">\n]+)"?\s*--[>-]+\s*"?([^";\n]+)"?', mermaid)
    if not edges:
        return mermaid  # fallback: return raw if we can't parse

    # Build adjacency list
    adj: dict[str, list[str]] = {}
    roots: list[str] = []
    all_targets: set[str] = set()
    for src, dst in edges:
        src, dst = src.strip(), dst.strip()
        adj.setdefault(src, []).append(dst)
        all_targets.add(dst)

    for src, _ in edges:
        src = src.strip()
        if src not in all_targets:
            roots.append(src)

    roots = list(dict.fromkeys(roots)) or ([edges[0][0]] if edges else [])
    visited: set[str] = set()
    lines: list[str] = []

    def walk(node: str, depth: int) -> None:
        prefix = "  " * depth + ("└─ " if depth else "")
        lines.append(prefix + node)
        if node in visited:
            return
        visited.add(node)
        for child in adj.get(node, []):
            walk(child, depth + 1)

    for root in roots:
        walk(root, 0)

    return "\n".join(lines)


@click.command()
@click.argument("cve_id")
@click.option("--scan-id", required=True, help="Scan ID to look up the call graph in.")
@click.option(
    "--format",
    "fmt",
    default="tree",
    type=click.Choice(["tree", "mermaid"], case_sensitive=False),
    show_default=True,
    help="tree = ASCII call tree; mermaid = raw Mermaid string (pipe to mmdc).",
)
@click.pass_context
def replay(ctx: click.Context, cve_id: str, scan_id: str, fmt: str) -> None:
    """Show the evidence call graph for a CVE.

    \b
    Examples:
      vulnreach replay CVE-2023-32681 --scan-id abc123
      vulnreach replay CVE-2023-32681 --scan-id abc123 --format mermaid | mmdc -o graph.svg
    """
    mode = ctx.obj.get("mode", "local")
    graph_str: Optional[str] = None
    package: Optional[str] = None

    if mode == "client":
        from vulnreach.client import VulnReachClient
        client = VulnReachClient(ctx.obj["url"], ctx.obj.get("token"))
        data = client.get_graph(scan_id, cve_id)
        graph_str = data.get("call_chain_graph")
        package = data.get("package")
    else:
        from storage import get_repository
        storage = get_repository()
        scan = storage.get_scan(scan_id)
        if not scan:
            raise click.ClickException(f"Scan {scan_id!r} not found.")

        # Step 1: resolve package from reachability evidence
        for ev in scan.get("reachability") or []:
            if ev.get("cve_id") == cve_id:
                package = ev.get("package")
                break
        if not package:
            for vuln in scan.get("vulnerabilities") or []:
                if vuln.get("cve_id") == cve_id:
                    package = vuln.get("package")
                    break

        # Step 2: find call_chain_graph for that package in raw outputs
        if package:
            raw = scan.get("raw") or {}
            for tool_name in ("python_reachability", "java_reachability", "multi_language_reachability"):
                payload = raw.get(tool_name) or {}
                analyses = payload.get("vulnerabilities") or payload.get("analyses") or []
                for analysis in analyses:
                    if analysis.get("package_name") == package:
                        graph_str = analysis.get("call_chain_graph")
                        break
                if graph_str:
                    break

    if not graph_str:
        click.echo(
            f"No call graph found for {cve_id} in scan {scan_id}. "
            "The vulnerability may not have been statically analysed or no call chain was traced."
        )
        return

    if package:
        console.print(f"[bold]CVE:[/bold] {cve_id}  [bold]Package:[/bold] {package}\n")

    if fmt == "mermaid":
        click.echo(graph_str)
    else:
        click.echo(_ascii_tree(graph_str))
