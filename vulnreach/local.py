"""
Standalone scan runner — executes the full VulnReach pipeline locally
without requiring a running server.  Uses SQLiteRepository for storage.
"""

import asyncio
from typing import Any, Dict, List, Optional

from vulnreach.scan_response import augment_scan_response


async def _run(
    repo_path: Optional[str],
    repo_url: Optional[str],
    config_path: Optional[str],
    tools: Optional[List[str]],
) -> Dict[str, Any]:
    from storage import get_repository
    from agents.runner import AgentRunner
    from core.orchestrator import Orchestrator
    from correlation.service import CorrelationService
    from config.schema import load_config, default_config

    storage = get_repository()
    runner = AgentRunner(storage)
    correlation_service = CorrelationService()
    orchestrator = Orchestrator(storage, runner, correlation_service)

    # Build config
    if config_path:
        config = load_config(config_path)
    else:
        config = default_config()

    if tools:
        config = config.model_copy(update={"scan": config.scan.model_copy(update={"tools": tools})})

    scan_id = storage.create_scan(
        status="started",
        metadata={
            "repo_path": repo_path or "",
            "repo_url": repo_url or "",
            "config_path": config_path or "",
            "tools": list(config.scan.tools),
            "started_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        },
    )

    await orchestrator.execute_scan(
        scan_id=scan_id,
        repo_path=repo_path or "",
        config_path=config_path or "",
        config=config,
        repo_url=repo_url,
    )

    scan = storage.get_scan(scan_id) or {}
    return augment_scan_response(scan)


def run_local_scan(
    repo_path: Optional[str] = None,
    repo_url: Optional[str] = None,
    config_path: Optional[str] = None,
    tools: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Synchronous entry point for CLI commands."""
    return asyncio.run(_run(repo_path, repo_url, config_path, tools))
