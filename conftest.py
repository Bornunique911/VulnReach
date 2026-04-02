"""
Root conftest.py – ensures agents/reachability is importable during test
collection so that tests/test_reachability_*.py files are picked up without
requiring an editable install.
"""
import sys
from pathlib import Path

# Project root (directory containing this file)
_ROOT = Path(__file__).parent.resolve()

# Make the reachability sub-package importable as a top-level path as well
# as through its full agents.reachability package path.
for _path in (_ROOT, _ROOT / "agents" / "reachability"):
    _path_str = str(_path)
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)
