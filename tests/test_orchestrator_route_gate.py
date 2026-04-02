import asyncio

from config.schema import default_config
from core.models import AgentResult
from core.orchestrator import Orchestrator


class _FakeStorage:
    def __init__(self) -> None:
        self.status = None
        self.correlation = None
        self.raw_outputs = []

    def store_raw_output(self, scan_id, tool_name, payload):
        self.raw_outputs.append((scan_id, tool_name, payload))

    def store_correlation(self, scan_id, results):
        self.correlation = (scan_id, results)

    def update_scan_status(self, scan_id, status):
        self.status = (scan_id, status)


class _FakeRunner:
    async def run_all(self, context):
        context.vulnerabilities = [
            {"package": "pkg-one", "cve_id": ["CVE-2026-0001"], "severity": "HIGH"}
        ]
        return [
            AgentResult(
                tool_name="tainter",
                findings=[
                    {
                        "package": "pkg-one",
                        "cve_id": "CVE-2026-0001",
                        "import_detected": True,
                        "call_chain_exists": True,
                        "sink_reachable": False,
                    }
                ],
                metadata={},
            ),
            AgentResult(
                tool_name="dynamic_reachability",
                findings=[
                    {
                        "package": "pkg-one",
                        "cve_id": "CVE-2026-0001",
                        "import_detected": True,
                        "call_chain_exists": True,
                        "sink_reachable": True,
                        "confidence": 0.95,
                    }
                ],
                metadata={},
            ),
            # Route extractor returns no routes -> dynamic findings must be gated out.
            AgentResult(tool_name="route_extractor", findings=[], metadata={}),
        ]


class _CaptureCorrelationService:
    def __init__(self) -> None:
        self.dynamic_reachability = None

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
        self.dynamic_reachability = dynamic_reachability
        return {
            "correlation": [],
            "dynamically_reachable": [],
            "statically_reachable": [],
            "not_reachable": [],
            "uncertain": [],
            "pipeline_status": "PASS",
            "summary": {},
        }


def test_orchestrator_enforces_route_gate_for_dynamic_findings() -> None:
    storage = _FakeStorage()
    runner = _FakeRunner()
    correlation = _CaptureCorrelationService()
    orchestrator = Orchestrator(storage=storage, runner=runner, correlation_service=correlation)

    cfg = default_config()

    asyncio.run(
        orchestrator.execute_scan(
            scan_id="scan-1",
            repo_path=".",
            config_path="",
            config=cfg,
            repo_url=None,
        )
    )

    assert correlation.dynamic_reachability == {}
    assert storage.status == ("scan-1", "completed")
