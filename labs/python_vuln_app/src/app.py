#!/usr/bin/env python3
"""
Simple Flask web application with intentionally vulnerable dependencies
for testing SBOM and SCA security scanning tools.

WARNING: This application contains known vulnerabilities and should only be used
in isolated testing environments for security tool validation.

=============================================================================
TAINT-ANALYSIS LEGEND
=============================================================================
[SOURCE]       — Untrusted data enters the program here
[PROPAGATE]    — Tainted data is copied / transformed but still dirty
[SANITIZE]     — Data is validated / escaped (taint cleared if correct)
[SINK]         — Tainted data reaches a dangerous function
[SAFE-SINK]    — Data reaches a sensitive function BUT taint has been cleared
[VULN]         — Confirmed exploitable sink (no sanitisation on path)
=============================================================================
"""

from flask import Flask, request, render_template_string, jsonify
import requests
import yaml
import pickle
import base64

app = Flask(__name__)

TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Security Test App</title>
</head>
<body>
    <h1>SBOM/SCA Testing Application</h1>
    <p>This app uses vulnerable dependencies for testing security scanners.</p>

    <h2>Test Endpoints:</h2>
    <ul>
        <li><a href="/health">/health</a>                        - Health check</li>
        <li><a href="/yaml-test">/yaml-test</a>                  - YAML safe load (no taint)</li>
        <li><a href="/yaml-unsafe?data=key: val">/yaml-unsafe</a>- YAML unsafe load (RCE)</li>
        <li><a href="/request-test">/request-test</a>            - External request (no taint)</li>
        <li><a href="/ssrf?url=https://httpbin.org/get">/ssrf</a>- SSRF via user URL</li>
        <li><a href="/render-test?name=world">/render-test</a>   - SSTI via template injection</li>
        <li><a href="/deserialize?data=">/deserialize</a>        - Pickle RCE via user bytes</li>
    </ul>
</body>
</html>
'''


@app.route('/')
def home():
    return render_template_string(TEMPLATE)


# ---------------------------------------------------------------------------
# /health  —  no user input, no taint
# ---------------------------------------------------------------------------
@app.route('/health')
def health():
    return jsonify({
        'status': 'running',
        'message': 'SBOM/SCA test application is running'
    })


# ---------------------------------------------------------------------------
# /yaml-test  —  SAFE  (hardcoded YAML, yaml.safe_load)
# ---------------------------------------------------------------------------
@app.route('/yaml-test')
def yaml_test():
    # No external input — no taint source on this path.
    sample_yaml = """
    config:
      name: test
      version: 1.0
    """
    try:
        # [SAFE-SINK] yaml.safe_load rejects !!python/object tags.
        #             Input is a string literal, not user-controlled.
        data = yaml.safe_load(sample_yaml)
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)})


# ---------------------------------------------------------------------------
# /yaml-unsafe  —  VULNERABLE  (yaml.load + user input → RCE)
#
# Taint flow  T1:
#   [SOURCE]    request.args["data"]          ← HTTP query parameter
#       │
#   [PROPAGATE] user_yaml = request.args.get(...)
#       │        (no validation, no schema check)
#       │
#   [SINK/VULN] yaml.load(user_yaml, Loader=yaml.Loader)
#                → yaml.Loader processes !!python/object/* tags
#                → arbitrary Python object instantiation
#                → RCE
#
# Exploit example:
#   GET /yaml-unsafe?data=!!python/object/apply:os.system+['id']
# ---------------------------------------------------------------------------
@app.route('/yaml-unsafe')
def yaml_unsafe():
    # [SOURCE T1] Attacker-controlled query-string parameter.
    user_yaml = request.args.get('data', 'key: value')   # ← SOURCE T1

    try:
        # [SINK/VULN T1] yaml.load with the full Loader deserialises
        #                !!python/object tags.  T1 is passed in directly.
        data = yaml.load(user_yaml, Loader=yaml.Loader)   # ← SINK T1 → RCE
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)})


# ---------------------------------------------------------------------------
# /request-test  —  SAFE  (URL is a string literal)
# ---------------------------------------------------------------------------
@app.route('/request-test')
def request_test():
    try:
        # [SAFE-SINK] requests.get receives a hardcoded URL — no taint.
        response = requests.get('https://httpbin.org/get', timeout=5)
        return jsonify({
            'status_code': response.status_code,
            'message': 'External request successful'
        })
    except Exception as e:
        return jsonify({'error': str(e)})


# ---------------------------------------------------------------------------
# /ssrf  —  VULNERABLE  (user controls the URL → SSRF)
#
# Taint flow  T2:
#   [SOURCE]    request.args["url"]           ← HTTP query parameter
#       │
#   [PROPAGATE] target_url = request.args.get(...)
#       │        (no scheme allowlist, no hostname allowlist)
#       │
#   [SINK/VULN] requests.get(target_url)
#                → HTTP request to attacker-specified destination
#                → SSRF (can reach internal services, metadata endpoints)
#
# Exploit example:
#   GET /ssrf?url=http://169.254.169.254/latest/meta-data/
# ---------------------------------------------------------------------------
@app.route('/ssrf')
def ssrf():
    # [SOURCE T2] Attacker-controlled URL string.
    target_url = request.args.get('url', 'https://httpbin.org/get')  # ← SOURCE T2

    # No allowlist / scheme check → taint is NOT cleared.
    try:
        # [SINK/VULN T2] requests.get receives T2 directly.
        response = requests.get(target_url, timeout=5)                # ← SINK T2 → SSRF
        return jsonify({'status_code': response.status_code})
    except Exception as e:
        return jsonify({'error': str(e)})


# ---------------------------------------------------------------------------
# /render-test  —  VULNERABLE  (user input injected into Jinja2 → SSTI/RCE)
#
# Taint flow  T3:
#   [SOURCE]    request.args["name"]          ← HTTP query parameter
#       │
#   [PROPAGATE] name = request.args.get(...)
#       │
#   [PROPAGATE] template = f"<h1>Hello, {name}!</h1>"
#       │        (T3 is string-formatted into a template — no escaping)
#       │
#   [SINK/VULN] render_template_string(template)
#                → Jinja2 evaluates {{ ... }} / {% ... %} inside template
#                → SSTI → arbitrary code execution
#
# Exploit examples:
#   GET /render-test?name={{7*7}}           → renders "49"
#   GET /render-test?name={{config}}        → leaks Flask config
#   GET /render-test?name={{self.__class__.__mro__[1].__subclasses__()}}
# ---------------------------------------------------------------------------
@app.route('/render-test')
def render_test():
    # [SOURCE T3] Attacker-controlled query parameter.
    name = request.args.get('name', 'world')      # ← SOURCE T3

    # [PROPAGATE T3] T3 is interpolated directly into the template string.
    #                No Markup() escaping, no allowlist — taint still live.
    template = f"<h1>Hello, {name}!</h1>"         # ← PROPAGATE T3

    # [SINK/VULN T3] render_template_string evaluates Jinja2 in the string.
    #                T3 is inside the template being executed.
    return render_template_string(template)       # ← SINK T3 → SSTI / RCE


# ---------------------------------------------------------------------------
# /deserialize  —  VULNERABLE  (pickle.loads on user-supplied bytes → RCE)
#
# Taint flow  T4:
#   [SOURCE]    request.args["data"]          ← base64-encoded pickle blob
#       │
#   [PROPAGATE] encoded_data = request.args.get(...)
#       │
#   [PROPAGATE] raw_bytes = base64.b64decode(encoded_data)
#       │        (decoding transforms format but does NOT sanitise content)
#       │
#   [SINK/VULN] pickle.loads(raw_bytes)
#                → pickle executes __reduce__ on the deserialised object
#                → arbitrary Python code execution
#                → RCE
#
# Exploit example (Python):
#   import pickle, os, base64
#   class Exploit:
#       def __reduce__(self):
#           return (os.system, ('id',))
#   payload = base64.b64encode(pickle.dumps(Exploit())).decode()
#   GET /deserialize?data=<payload>
# ---------------------------------------------------------------------------
@app.route('/deserialize')
def deserialize():
    # [SOURCE T4] Attacker-controlled base64 string.
    encoded_data = request.args.get('data', '')       # ← SOURCE T4

    try:
        # [PROPAGATE T4] base64.b64decode changes encoding but taint remains.
        raw_bytes = base64.b64decode(encoded_data)    # ← PROPAGATE T4

        # [SINK/VULN T4] pickle.loads executes __reduce__ on the object.
        #                T4 flows in as the sole argument — no integrity check.
        obj = pickle.loads(raw_bytes)                 # ← SINK T4 → RCE

        return jsonify({'result': str(obj)})
    except Exception as e:
        return jsonify({'error': str(e)})


if __name__ == '__main__':
    print("Starting SBOM/SCA test application...")
    print("WARNING: This application contains vulnerable dependencies for testing only!")
    app.run(debug=True, host='127.0.0.1', port=8002)