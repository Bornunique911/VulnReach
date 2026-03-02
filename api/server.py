from dotenv import load_dotenv
import os
import logging
from typing import Any, Dict, List

from fastapi import BackgroundTasks, FastAPI, HTTPException

from agents.runner import AgentRunner
from core.orchestrator import Orchestrator
from config.schema import load_config
from core.models import ScanContext, AgentResult
from correlation.service import CorrelationService
from storage.repository import PostgresRepository

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = FastAPI(title="VulnReach v2")

storage = PostgresRepository(os.getenv("DATABASE_URL"))
runner = AgentRunner(storage)
correlation_service = CorrelationService()
orchestrator = Orchestrator(storage, runner, correlation_service)
AVAILABLE_TOOLS: List[str] = ["git", "trivy", "tainter", "python_reachability", "dynamic_reachability", "semgrep", "route_extractor", "metadata"]


@app.post("/scan")
async def start_scan(payload: Dict[str, Any], background_tasks: BackgroundTasks):
    repo_path = payload.get("repo_path")
    repo_url = payload.get("repo_url")
    config_path = payload.get("config_path")
    if (not repo_path and not repo_url) or not config_path:
        raise HTTPException(status_code=400, detail="repo_path or repo_url and config_path are required")

    try:
        config = load_config(config_path)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    requested_tools = payload.get("tools")
    tools = list(requested_tools if requested_tools else (config.scan.tools or []))

    # Auto-inject dynamic_reachability if runtime is enabled and not already present
    if config.scan.runtime.enabled and "dynamic_reachability" not in tools:
        tools.append("dynamic_reachability")

    if repo_url and "git" not in tools:
        tools.insert(0, "git")

    # Validate all tools are known
    unknown = set(tools) - set(AVAILABLE_TOOLS)
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown tools: {sorted(unknown)}")

    scan_id = storage.create_scan(metadata={"repo_path": repo_path, "repo_url": repo_url, "tools": tools})
    background_tasks.add_task(orchestrator.execute_scan, scan_id, repo_path or "", config_path, config, repo_url)
    return {"scan_id": scan_id, "status": "started", "tools": tools, "repo_path": repo_path, "repo_url": repo_url}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    try:
        scan = storage.get_scan(scan_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Invalid scan id")
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, **scan}


@app.get("/scans")
async def list_scans():
    return {"scans": storage.list_scans()}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/tools")
async def list_tools():
    return {"available_tools": AVAILABLE_TOOLS}
