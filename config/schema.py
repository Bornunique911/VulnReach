from pathlib import Path
from typing import List, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator


class EbpfSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    # "openat" traces file-open syscalls (portable, no USDT needed).
    # "usdt"   uses Python USDT probes (requires Python built with --with-dtrace).
    mode: str = "openat"
    # "bpftrace" or "bcc" — whichever is installed on the host.
    tracer: str = "bpftrace"


class RuntimeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    timeout: int = 60
    coverage_wait: int = 10
    container_port: int = 3000
    ebpf: EbpfSettings = EbpfSettings()


class ScanSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    static_reachability: bool = True
    tools: List[str] = ["trivy", "tainter"]
    runtime: RuntimeSettings = RuntimeSettings()



class RiskSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exposure: Literal["public", "private", "internal"] = "private"
    data_sensitivity: Literal["low", "medium", "high"] = "low"


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    verdict: Literal["CONFIRMED", "LIKELY", "POSSIBLE", "NOT_OBSERVED"]


class PolicySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    block_if: List[PolicyRule] = []

    @field_validator("block_if", mode="before")
    def default_block_if(cls, value):  # type: ignore
        return value or []


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan: ScanSettings
    risk: RiskSettings
    policy: PolicySettings


def load_config(path: str) -> ScanConfig:
    """Load and validate YAML scan config."""

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    try:
        return ScanConfig.model_validate(raw)
    except ValidationError as exc:  # pragma: no cover - pydantic formats errors
        raise ValueError(f"Invalid config: {exc}")
