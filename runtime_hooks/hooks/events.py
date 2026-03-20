"""Minimal in-memory event collector for runtime observations."""
from __future__ import annotations

import json
from typing import Any, Dict, List

# Simple in-memory buffer; no disk I/O in this phase
_events: List[Dict[str, Any]] = []


def emit(event_type: str, data: Dict[str, Any]) -> None:
    """Record a structured event.

    Args:
        event_type: Short identifier for the event (e.g., "import", "sink").
        data: Arbitrary structured payload describing the event.
    """
    _events.append({"event_type": event_type, "data": data})


def get_events() -> List[Dict[str, Any]]:
    """Return all collected events without clearing them.
    
    Returns:
        List of event dictionaries
    """
    return _events.copy()


def clear_events() -> None:
    """Clear all collected events."""
    _events.clear()


def flush() -> None:
    """Print all collected events as JSON and clear the buffer."""
    if not _events:
        print("[]")
        return

    print(json.dumps(_events))
    _events.clear()


def flush_to_file(path: str) -> None:
    """Write all collected events to a file as JSON and clear the buffer.

    Called from sitecustomize.py atexit handler so each worker process
    writes its own events (use a PID-specific path to avoid conflicts).
    """
    import pathlib
    pathlib.Path(path).write_text(json.dumps(_events), encoding="utf-8")
    _events.clear()
