"""
build_explanation — generate a human-readable explanation for a CVE finding.

provider="none"      → deterministic structured summary (works offline, no API key)
provider="anthropic" → LLM-generated explanation via Anthropic SDK
"""

import ipaddress
import logging
import os
import urllib.parse
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# ── SSRF guard ────────────────────────────────────────────────────────────────
_BLOCKED_HOSTS = frozenset({
    "169.254.169.254",           # AWS / GCP / Azure IMDS (IPv4 link-local)
    "fd00:ec2::254",             # AWS IMDS (IPv6)
    "[fd00:ec2::254]",
    "metadata.google.internal",
    "metadata.internal",
})
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (IMDS lives here)
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
]


def _validate_ollama_url(url: str) -> None:
    """Raise ValueError if the URL could be an SSRF target.

    Only the server-configured VULNREACH_OLLAMA_URL is ever passed here —
    this is defence-in-depth in case of a misconfigured env var.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Ollama URL scheme must be http or https, got {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Ollama URL must specify a hostname")
    if host in _BLOCKED_HOSTS:
        raise ValueError(f"Ollama URL host {host!r} is not permitted")
    try:
        addr = ipaddress.ip_address(host)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                raise ValueError(f"Ollama URL host {host!r} is in a blocked IP range ({net})")
    except ValueError as exc:
        # Re-raise our own blocked errors; swallow AddressValueError (hostname, not IP)
        if "blocked" in str(exc) or "permitted" in str(exc):
            raise


def _find_finding(scan: Dict[str, Any], cve_id: str) -> Optional[Dict[str, Any]]:
    for finding in scan.get("correlation") or []:
        if finding.get("cve_id") == cve_id:
            return finding
    return None


def _find_vuln(scan: Dict[str, Any], cve_id: str) -> Optional[Dict[str, Any]]:
    for vuln in scan.get("vulnerabilities") or []:
        cve_ids = vuln.get("cve_id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        if cve_id in cve_ids:
            return vuln
    return None


def _template_explanation(scan: Dict[str, Any], cve_id: str) -> str:
    finding = _find_finding(scan, cve_id)
    vuln = _find_vuln(scan, cve_id)

    if not finding and not vuln:
        return f"No finding found for {cve_id} in this scan."

    pkg = (vuln or {}).get("package") or (finding or {}).get("package") or "unknown package"
    severity = (vuln or {}).get("severity", "UNKNOWN")
    verdict = (finding or {}).get("verdict", "NOT_OBSERVED")
    evidence = (finding or {}).get("evidence") or {}
    reach_class = (finding or {}).get("reachability_class") or evidence.get("reachability_class", "UNCERTAIN")
    fix_version = (vuln or {}).get("fix_version")
    files: List[str] = evidence.get("files") or []
    fn = evidence.get("function")
    call_chain = evidence.get("call_chain_exists", False)
    import_detected = evidence.get("import_detected", False)
    coverage_hit = evidence.get("coverage_hit", False)

    # Reachability summary
    if reach_class == "DYNAMICALLY_REACHABLE":
        reach_summary = (
            f"{pkg} was called at runtime during analysis — the vulnerable code path "
            "was observed executing, which means an attacker could trigger it."
        )
    elif reach_class == "STATICALLY_REACHABLE":
        reach_summary = (
            f"{pkg} is imported and used in the codebase. Static analysis traced a call "
            "chain from application code to the vulnerable component, but runtime confirmation "
            "was not collected."
        )
    elif reach_class == "NOT_REACHABLE":
        reach_summary = (
            f"{pkg} is present as a dependency but no call path to the vulnerable code "
            "was found. This CVE is unlikely to be exploitable in this deployment."
        )
    else:
        reach_summary = (
            f"{pkg} is present as a dependency. Reachability could not be determined "
            "with confidence — manual review is recommended."
        )

    # Evidence detail
    evidence_lines = []
    if coverage_hit:
        evidence_lines.append("• Runtime coverage confirmed code execution")
    if call_chain:
        evidence_lines.append("• Static call chain traced from entry point to vulnerable sink")
    if import_detected:
        evidence_lines.append("• Package import detected in application source")
    if fn:
        evidence_lines.append(f"• Relevant function: {fn}")
    if files:
        evidence_lines.append(f"• Affected files: {', '.join(files[:3])}" + (" …" if len(files) > 3 else ""))

    # Urgency
    if verdict == "CONFIRMED":
        urgency = "URGENT — runtime-confirmed reachable vulnerability. Prioritise immediately."
    elif verdict == "LIKELY":
        urgency = "HIGH — statically reachable. Schedule upgrade in the next sprint."
    elif verdict == "POSSIBLE":
        urgency = "MEDIUM — possible reachability. Review and assess before next release."
    else:
        urgency = "LOW — not observed as reachable. Monitor but no immediate action required."

    upgrade_note = f"Upgrade {pkg} to {fix_version} to resolve." if fix_version else f"Check for an available patch for {pkg}."

    lines = [
        f"CVE: {cve_id}  |  Package: {pkg}  |  Severity: {severity}  |  Verdict: {verdict}",
        "",
        reach_summary,
        "",
    ]
    if evidence_lines:
        lines += ["Evidence collected:"] + evidence_lines + [""]
    lines += [f"Recommended action: {urgency}", upgrade_note]
    return "\n".join(lines)


async def _llm_explanation(scan: Dict[str, Any], cve_id: str, model: Optional[str]) -> str:
    try:
        import anthropic
    except ImportError:
        return _template_explanation(scan, cve_id) + "\n\n[anthropic package not installed — showing offline summary]"

    finding = _find_finding(scan, cve_id)
    vuln = _find_vuln(scan, cve_id)
    evidence = (finding or {}).get("evidence") or {}

    import json
    evidence_json = json.dumps({
        "verdict": (finding or {}).get("verdict"),
        "reachability_class": (finding or {}).get("reachability_class") or evidence.get("reachability_class"),
        "call_chain_exists": evidence.get("call_chain_exists"),
        "coverage_hit": evidence.get("coverage_hit"),
        "import_detected": evidence.get("import_detected"),
        "function": evidence.get("function"),
        "files": (evidence.get("files") or [])[:5],
    }, indent=2)

    prompt = (
        f"You are a senior security engineer reviewing a vulnerability reachability scan.\n\n"
        f"CVE: {cve_id}\n"
        f"Package: {(vuln or {}).get('package', 'unknown')}\n"
        f"Severity: {(vuln or {}).get('severity', 'unknown')}\n"
        f"Fix version: {(vuln or {}).get('fix_version', 'unknown')}\n"
        f"Reachability evidence:\n{evidence_json}\n\n"
        "In 3-5 concise sentences explain:\n"
        "1. What this vulnerability is and how it could be exploited\n"
        "2. How an attacker could reach it based on the evidence above\n"
        "3. Urgency and recommended action\n\n"
        "Be direct and developer-friendly. Avoid jargon."
    )

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    message = client.messages.create(
        model=model or os.getenv("VULNREACH_EXPLAIN_MODEL", "claude-haiku-4-5-20251001"),
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def _ollama_explanation(
    scan: Dict[str, Any],
    cve_id: str,
    model: Optional[str],
    base_url: Optional[str],
) -> str:
    """Generate an explanation using a locally-running Ollama model."""
    try:
        import ollama
    except ImportError:
        return _template_explanation(scan, cve_id) + "\n\n[ollama package not installed — showing offline summary]"

    finding = _find_finding(scan, cve_id)
    vuln = _find_vuln(scan, cve_id)
    evidence = (finding or {}).get("evidence") or {}

    import json
    evidence_json = json.dumps({
        "verdict": (finding or {}).get("verdict"),
        "reachability_class": (finding or {}).get("reachability_class") or evidence.get("reachability_class"),
        "call_chain_exists": evidence.get("call_chain_exists"),
        "coverage_hit": evidence.get("coverage_hit"),
        "import_detected": evidence.get("import_detected"),
        "function": evidence.get("function"),
        "files": (evidence.get("files") or [])[:5],
    }, indent=2)

    prompt = (
        f"You are a senior security engineer reviewing a vulnerability reachability scan.\n\n"
        f"CVE: {cve_id}\n"
        f"Package: {(vuln or {}).get('package', 'unknown')}\n"
        f"Severity: {(vuln or {}).get('severity', 'unknown')}\n"
        f"Fix version: {(vuln or {}).get('fix_version', 'unknown')}\n"
        f"Reachability evidence:\n{evidence_json}\n\n"
        "In 3-5 concise sentences explain:\n"
        "1. What this vulnerability is and how it could be exploited\n"
        "2. How an attacker could reach it based on the evidence above\n"
        "3. Urgency and recommended action\n\n"
        "Be direct and developer-friendly. Avoid jargon."
    )

    resolved_url = base_url or os.getenv("VULNREACH_OLLAMA_URL", "http://host.docker.internal:11434")
    _validate_ollama_url(resolved_url)
    client = ollama.Client(host=resolved_url)
    response = client.chat(
        model=model or "llama3",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.message.content


def build_explanation(
    scan: Dict[str, Any],
    cve_id: str,
    provider: str = "none",
    model: Optional[str] = None,
    ollama_url: Optional[str] = None,
) -> str:
    """Build an explanation synchronously (wraps async LLM call if needed)."""
    if provider == "none":
        return _template_explanation(scan, cve_id)

    if provider == "ollama":
        try:
            return _ollama_explanation(scan, cve_id, model, ollama_url)
        except Exception as exc:
            log.exception("Ollama explanation failed for %s", cve_id)
            return _template_explanation(scan, cve_id) + f"\n\n[Ollama call failed: {exc} — showing offline summary]"

    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _llm_explanation(scan, cve_id, model))
                return future.result(timeout=60)
        return loop.run_until_complete(_llm_explanation(scan, cve_id, model))
    except Exception as exc:
        return _template_explanation(scan, cve_id) + f"\n\n[LLM call failed: {exc} — showing offline summary]"
