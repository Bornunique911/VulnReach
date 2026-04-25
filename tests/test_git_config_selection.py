import asyncio

from agents.agent_git import GitAgent
from agents.runner import AgentRunner
from config.schema import default_config
from core.models import AgentResult, ScanContext
from core.orchestrator import Orchestrator


def test_git_agent_succeeds_with_default_config_when_no_repo_config_found(tmp_path, monkeypatch):
    """When the repo has no vulnreach config and the request has no config_path,
    the git agent should succeed and leave context.config unchanged (soft-fail)."""
    agent = GitAgent()

    async def _run_cmd(cmd):
        if cmd[:3] == ["git", "clone", "--depth"]:
            return 0, "", ""
        if len(cmd) >= 5 and cmd[0] == "git" and cmd[1] == "-C" and cmd[3] == "rev-parse":
            return 0, "deadbeef\n", ""
        return 1, "", "unexpected command"

    monkeypatch.setattr(agent, "_run_cmd", _run_cmd)
    monkeypatch.setattr("agents.agent_git._WORK_BASE", str(tmp_path))

    original_config = default_config()
    context = ScanContext(repo_url="https://example.invalid/repo.git", scan_id="scan-1", config=original_config)
    result = asyncio.run(agent.run(context))

    assert result.metadata.get("error") is None
    assert result.metadata.get("fatal") is not True
    # config_path not set in context — no repo config was discovered
    assert context.config_path is None
    # config object unchanged
    assert context.config is original_config


def test_git_agent_prefers_request_config_over_repository_config(tmp_path, monkeypatch):
    agent = GitAgent()
    caller_config = default_config()
    clone_dir = tmp_path / "cloned"

    async def _run_cmd(cmd):
        if cmd[:3] == ["git", "clone", "--depth"]:
            clone_dir.mkdir(parents=True, exist_ok=True)
            (clone_dir / "vulnreach.yaml").write_text(
                "scan:\n  static_reachability: true\n  tools: [trivy]\n",
                encoding="utf-8",
            )
            return 0, "", ""
        if len(cmd) >= 5 and cmd[0] == "git" and cmd[1] == "-C" and cmd[3] == "rev-parse":
            return 0, "deadbeef\n", ""
        return 1, "", "unexpected command"

    def _mkdtemp(**_kwargs):
        clone_dir.mkdir(parents=True, exist_ok=True)
        return str(clone_dir)

    monkeypatch.setattr(agent, "_run_cmd", _run_cmd)
    monkeypatch.setattr("agents.agent_git.tempfile.mkdtemp", _mkdtemp)

    context = ScanContext(
        repo_url="https://example.invalid/repo.git",
        config=caller_config,
        config_path="/ui/override.yml",
        scan_id="scan-2",
    )
    result = asyncio.run(agent.run(context))

    assert result.metadata.get("error") is None
    assert context.config is caller_config
    assert context.config_path == "/ui/override.yml"
    assert result.findings[0]["config_source"] == "request"


def test_runner_stops_after_fatal_git_error():
    class _Storage:
        def store_raw_output(self, scan_id, tool_name, payload):
            return None

    runner = AgentRunner(_Storage())
    cfg = default_config()
    cfg.scan.tools = ["git", "trivy"]

    async def _fatal_git(_context):
        return AgentResult(
            tool_name="git",
            findings=[],
            metadata={"error": "missing_repo_config", "fatal": True},
        )

    async def _unexpected(_context):
        raise AssertionError("trivy should not run after fatal git error")

    runner.git.run = _fatal_git
    runner.trivy.run = _unexpected

    results = asyncio.run(
        runner.run_all(
            ScanContext(repo_url="https://example.invalid/repo.git", config=cfg, scan_id="scan-3")
        )
    )

    assert [result.tool_name for result in results] == ["git"]


def test_runner_refreshes_tools_after_git_discovers_repo_config(monkeypatch, tmp_path):
    class _Storage:
        def store_raw_output(self, scan_id, tool_name, payload):
            return None

        def store_vulnerabilities(self, scan_id, findings):
            return None

        def store_reachability(self, scan_id, findings):
            return None

        def store_routes(self, scan_id, findings):
            return None

    runner = AgentRunner(_Storage())
    initial_config = default_config()
    initial_config.scan.tools = ["git", "trivy"]

    discovered_config = default_config()
    discovered_config.scan.tools = ["trivy", "route_extractor"]
    calls = []

    async def _git(_context):
        calls.append("git")
        _context.repo_path = str(tmp_path)
        _context.config = discovered_config
        _context.config_path = str(tmp_path / "vulnreach.yaml")
        return AgentResult(tool_name="git", findings=[], metadata={"status": "ok"})

    async def _trivy(_context):
        calls.append("trivy")
        return AgentResult(tool_name="trivy", findings=[], metadata={"status": "ok"})

    async def _route_extractor(_context):
        calls.append("route_extractor")
        return AgentResult(tool_name="route_extractor", findings=[], metadata={"status": "ok"})

    runner.git.run = _git
    runner.trivy.run = _trivy
    runner.route_extractor.run = _route_extractor
    monkeypatch.setattr(runner, "_detect_project_languages", lambda context: ["python"])

    results = asyncio.run(
        runner.run_all(
            ScanContext(
                repo_url="https://example.invalid/repo.git",
                config=initial_config,
                scan_id="scan-5",
            )
        )
    )

    assert calls == ["git", "trivy", "route_extractor"]
    assert [result.tool_name for result in results] == ["git", "trivy", "route_extractor"]


def test_orchestrator_marks_scan_failed_for_fatal_git_config_error():
    class _Storage:
        def __init__(self) -> None:
            self.status = None

        def store_raw_output(self, scan_id, tool_name, payload):
            return None

        def store_correlation(self, scan_id, results):
            return None

        def update_scan_status(self, scan_id, status):
            self.status = (scan_id, status)

    class _FatalGitRunner:
        async def run_all(self, context):
            return [
                AgentResult(
                    tool_name="git",
                    findings=[],
                    metadata={"error": "missing_repo_config", "fatal": True},
                )
            ]

    class _Correlation:
        def correlate(
            self,
            vulnerabilities,
            static_reachability,
            dynamic_reachability,
            exposure,
            policy_rules=None,
            semgrep_findings=None,
            dast_findings=None,
            reachability=None,
        ):
            return {
                "correlation": [],
                "dynamically_reachable": [],
                "statically_reachable": [],
                "not_reachable": [],
                "uncertain": [],
                "pipeline_status": "PASS",
                "summary": {},
            }

    storage = _Storage()
    orchestrator = Orchestrator(storage=storage, runner=_FatalGitRunner(), correlation_service=_Correlation())

    asyncio.run(
        orchestrator.execute_scan(
            scan_id="scan-4",
            repo_path="",
            config_path="",
            config=default_config(),
            repo_url="https://example.invalid/repo.git",
        )
    )

    assert storage.status == ("scan-4", "failed")
