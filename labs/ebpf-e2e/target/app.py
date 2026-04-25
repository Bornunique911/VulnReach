"""
VulnReach eBPF E2E target app.

Controlled vulnerability exposure for E2E testing:

  Route /parse  → calls yaml.safe_load()  (pyyaml — CVE-2020-14343 installed)
                  MUST appear as DYNAMICALLY_REACHABLE
  Route /health → never calls yaml or pickle
                  MUST NOT cause pyyaml/pickle to be DYNAMICALLY_REACHABLE

Negative control:
  pickle is installed but NEVER called at runtime.
  CVEs in pickle/related packages must NOT be DYNAMICALLY_REACHABLE.

Line map (do not reorder without updating test_ebpf_e2e.py assertions):
  line 24 — import yaml          ← imported at module level
  line 25 — import pickle        ← imported at module level (never called)
  line 30 — def parse():         ← MUST appear when /parse is called
  line 32 —   yaml.safe_load()  ← MUST appear in eBPF coverage
  line 35 — def unused_pickle(): ← MUST NOT appear in eBPF output
  line 36 —   pickle.dumps()    ← MUST NOT appear in eBPF output
"""
import os
from flask import Flask, request, jsonify
import yaml
import pickle  # installed but intentionally never called via HTTP

app = Flask(__name__)


@app.route("/parse")
def parse():
    """Calls yaml.safe_load — pyyaml CVE path is exercised."""
    data = request.args.get("data", "key: value")
    result = yaml.safe_load(data)
    return jsonify(parsed=str(result))


def unused_pickle():
    """Never called at runtime — negative control for pickle CVEs."""
    return pickle.dumps({"never": "executed"})


@app.route("/health")
def health():
    return jsonify(status="ok")


PORT = int(os.environ.get("PORT", 5001))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
