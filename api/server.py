from dotenv import load_dotenv
from pathlib import Path
import os
import uuid
import logging
from typing import Any, Dict, List

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from pydantic import BaseModel

from agents.runner import AgentRunner
from api.auth import (
    UserPrincipal,
    create_token,
    hash_password,
    require_admin,
    require_user,
    verify_password,
)
from core.orchestrator import Orchestrator
from config.schema import load_config
from core.models import ScanContext, AgentResult
from correlation.service import CorrelationService
from storage.repository import PostgresRepository

# Load .env.local first (secrets), then .env as fallback
load_dotenv(dotenv_path=Path(".env.local"), override=True)
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = FastAPI(title="VulnReach v2")

storage = PostgresRepository(os.getenv("DATABASE_URL"))
runner = AgentRunner(storage)
correlation_service = CorrelationService()
orchestrator = Orchestrator(storage, runner, correlation_service)
AVAILABLE_TOOLS: List[str] = ["git", "trivy", "tainter", "python_reachability", "dynamic_reachability", "intelligent_dast", "semgrep", "route_extractor", "metadata"]


# ── Seed admin user on startup ───────────────────────────────────

def _seed_admin() -> None:
    username = os.getenv("SEED_ADMIN_USERNAME")
    password = os.getenv("SEED_ADMIN_PASSWORD")
    if not username or not password:
        logger.info("SEED_ADMIN_USERNAME/PASSWORD not set — skipping admin seed")
        return
    existing = storage.get_user_by_username(username)
    if existing:
        return
    storage.create_user(
        user_id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(password),
        role="admin",
    )
    logger.info("Seeded admin user '%s'", username)


@app.on_event("startup")
async def on_startup() -> None:
    _seed_admin()


# ── Auth endpoints ───────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(body: LoginRequest):
    user = storage.get_user_by_username(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    principal = UserPrincipal(id=str(user["id"]), username=user["username"], role=user["role"])
    return {"access_token": create_token(principal), "token_type": "bearer"}


# ── Protected endpoints ──────────────────────────────────────────

@app.post("/scan")
async def start_scan(
    payload: Dict[str, Any],
    background_tasks: BackgroundTasks,
    _principal: UserPrincipal = Depends(require_user),
):
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
async def get_scan(scan_id: str, _principal: UserPrincipal = Depends(require_user)):
    try:
        scan = storage.get_scan(scan_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Invalid scan id")
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, **scan}


@app.get("/scans")
async def list_scans(_principal: UserPrincipal = Depends(require_user)):
    return {"scans": storage.list_scans()}


# ── Public endpoints ─────────────────────────────────────────────

_BOOT_ID = uuid.uuid4().hex

@app.get("/health")
async def health():
    return {"status": "ok", "boot_id": _BOOT_ID}


@app.get("/tools")
async def list_tools():
    return {"available_tools": AVAILABLE_TOOLS}
