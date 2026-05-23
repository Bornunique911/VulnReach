"""On-demand next-steps reasoning API.

Lazy / optional layer on top of the deterministic scan pipeline:

  * scans stay fast, cheap, reproducible — they do not call the LLM;
  * analysts hit ``POST /findings/{id}/next-steps`` when they want
    augmentation;
  * LLM failures NEVER fail scans, and never fail anything else either —
    the endpoint always returns a stable response shape, with an
    ``error`` field set when the LLM was unavailable.

Finding id format: ``"<scan_id>:<cve_id>"`` (optionally
``"<scan_id>:<cve_id>:<package>"`` for CVEs that appear under multiple
packages in the same scan).

Cache key: ``finding_id + evidence_hash + prompt_version`` so that
re-running with identical evidence is free, but stale data (new scan
results, prompt bump, graph schema bump) invalidates correctly.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

from agents.agent_next_steps import PROMPT_VERSION, NextStepsReasoner
from correlation.evidence_graph import (
    EVIDENCE_GRAPH_VERSION,
    EvidenceGraphBuilder,
    evidence_hash,
    parse_finding_id,
)

log = logging.getLogger(__name__)

_CACHE_MAX_ENTRIES = 512


class _LRUCache:
    """Thread-safe bounded LRU. In-memory only — process-restart loses it."""

    def __init__(self, max_entries: int = _CACHE_MAX_ENTRIES) -> None:
        self._max = max_entries
        self._data: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Tuple[str, str, str]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if key not in self._data:
                return None
            self._data.move_to_end(key)
            return self._data[key]

    def set(self, key: Tuple[str, str, str], value: Dict[str, Any]) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


_cache = _LRUCache()


class NextStepsService:
    """Owns the EvidenceGraphBuilder, reasoner factory, and response cache."""

    def __init__(
        self,
        storage: Any,
        reasoner_factory: Optional[Any] = None,
    ) -> None:
        self._builder = EvidenceGraphBuilder(storage)
        # The reasoner is lazily constructed per-request so an unset
        # ANTHROPIC_API_KEY doesn't crash app startup.
        self._reasoner_factory = reasoner_factory or NextStepsReasoner

    def build_graph(self, finding_id: str) -> Dict[str, Any]:
        """Build and return the EvidenceGraph (no LLM involvement)."""
        return self._builder.build(finding_id)

    def get_next_steps(
        self,
        finding_id: str,
        *,
        bypass_cache: bool = False,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return a fully-formed API response for ``finding_id``.

        Never raises on LLM failure: returns a payload with
        ``status="degraded"`` and an ``error`` field instead.
        """
        graph = self._builder.build(finding_id)
        ev_hash = evidence_hash(graph)
        cache_key = (finding_id, ev_hash, PROMPT_VERSION)

        if not bypass_cache:
            cached = _cache.get(cache_key)
            if cached is not None:
                log.info("next_steps_cache hit finding_id=%s", finding_id)
                return {**cached, "cache": "hit"}

        try:
            reasoner = self._reasoner_factory(model=model)
            llm_output = reasoner.reason(graph)
        except Exception as exc:  # noqa: BLE001 — never fail the request
            log.warning(
                "next_steps_llm_failure finding_id=%s error=%s",
                finding_id, exc,
            )
            return {
                "finding_id": finding_id,
                "status": "degraded",
                "error": str(exc),
                "evidence_graph": graph,
                "evidence_graph_version": EVIDENCE_GRAPH_VERSION,
                "evidence_hash": ev_hash,
                "prompt_version": PROMPT_VERSION,
                "result": None,
                "telemetry": None,
                "cache": "miss",
            }

        response = {
            "finding_id": finding_id,
            "status": "ok",
            "result": llm_output["result"],
            "telemetry": llm_output["telemetry"],
            "evidence_graph": graph,
            "evidence_graph_version": EVIDENCE_GRAPH_VERSION,
            "evidence_hash": ev_hash,
            "prompt_version": llm_output.get("prompt_version", PROMPT_VERSION),
        }
        _cache.set(cache_key, response)
        return {**response, "cache": "miss"}


def cache_stats() -> Dict[str, int]:
    """Expose simple cache metrics for ops/debugging."""
    with _cache._lock:  # noqa: SLF001 — internal lock, used for snapshot only
        return {"entries": len(_cache._data), "max_entries": _cache._max}


def clear_cache() -> None:
    """Drop all cached next-steps results (test / ops helper)."""
    _cache.clear()


__all__ = [
    "NextStepsService",
    "cache_stats",
    "clear_cache",
    "parse_finding_id",
]
