"""Minimal deterministic Flask app for eBPF coverage verification.

Line map (do not reorder without updating compare_coverage.py):
  line  1 — module docstring
  line  3 — import os
  line  4 — from flask import Flask, request, jsonify
  line  6 — app = Flask(__name__)
  line  8 — def add(a, b):
  line  9 —     return a + b           ← MUST appear in eBPF when /add is called
  line 11 — def unused():
  line 12 —     return "never called"  ← MUST NOT appear in eBPF (negative control)
  line 14 — @app.route("/add")
  line 15 — def handle_add():
  line 16 —     a = ...
  line 17 —     b = ...
  line 18 —     result = add(a, b)
  line 19 —     return jsonify(...)
  line 21 — @app.route("/health")
  line 22 — def health():
  line 23 —     return jsonify(status="ok")
  line 25 — PORT = ...
  line 27 — if __name__ == "__main__":
  line 28 —     app.run(...)
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

def add(a, b):
    return a + b           # covered when /add is called

def unused():
    return "never called"  # negative control — must not appear in coverage

@app.route("/add")
def handle_add():
    a = int(request.args.get("a", 0))
    b = int(request.args.get("b", 0))
    result = add(a, b)
    return jsonify(result=result)

@app.route("/health")
def health():
    return jsonify(status="ok")

PORT = int(os.environ.get("PORT", 5000))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
