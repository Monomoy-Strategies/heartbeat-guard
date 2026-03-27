"""
HeartbeatGuard Dashboard — Scanner-to-Dashboard Data Transform

Converts the output of run_security_scan() into the MODULES[] format
expected by the dashboard JavaScript orbit visualization.

Copyright (c) 2026 Monomoy Strategies LLC
"""

from typing import Any, Dict, List

try:
    from .. import __version__
except ImportError:
    __version__ = "1.6.0"


# ---------------------------------------------------------------------------
# Category -> Dashboard tile metadata
# ---------------------------------------------------------------------------

MODULE_META: Dict[str, Dict[str, Any]] = {
    # Core checks (scanner.py) — always run
    "system_health":                  {"id": 1,  "name": "System Health"},
    "firewall":                       {"id": 2,  "name": "Firewall Status"},
    "open_ports":                     {"id": 3,  "name": "Open Ports"},
    # Light-mode checks
    "credential_rotation":            {"id": 4,  "name": "Credential Rotation"},
    "command_audit":                  {"id": 5,  "name": "Command Audit"},
    "skill_safety":                   {"id": 6,  "name": "Skill Safety"},
    "dangerous_config_flags":         {"id": 7,  "name": "Config Flags"},
    "insecure_ws_connections":        {"id": 8,  "name": "WebSocket Security"},
    "openclaw_version_gate":          {"id": 9,  "name": "Version Gate"},
    "ssrf_legacy_key":                {"id": 10, "name": "SSRF Legacy Key"},
    "openclaw_version_gate_223":      {"id": 11, "name": "Version Gate 2.23"},
    "telegram_401_retry_risk":        {"id": 12, "name": "Telegram Health"},
    "gateway_restart_loop":           {"id": 13, "name": "Gateway Status"},
    # Checks subpackage — light mode
    "dm_policy_verify":               {"id": 14, "name": "DM Policy Verify"},
    "acp_session_lifecycle":          {"id": 15, "name": "Session Lifecycle"},
    "config_validate":                {"id": 16, "name": "Config Validation"},
    "secret_ref_audit":               {"id": 17, "name": "Secrets Hygiene"},
    "media_sandbox_verify":           {"id": 18, "name": "Media Sandbox",      "badge": "v1.6"},
    "channel_id_injection":           {"id": 19, "name": "Channel ID Guard",   "badge": "v1.6"},
    "long_session_monitor":           {"id": 20, "name": "Session Duration",   "badge": "v1.6"},
    # Full-scan-only checks
    "ssl_certs":                      {"id": 21, "name": "SSL Certificates"},
    "failed_logins":                  {"id": 22, "name": "Failed Logins"},
    "processes":                      {"id": 23, "name": "Suspicious Processes"},
    "file_integrity":                 {"id": 24, "name": "File Integrity"},
    "cve_updates":                    {"id": 25, "name": "CVE Updates"},
    "anomalies":                      {"id": 26, "name": "Anomaly Detection"},
    "sysmon_logs":                    {"id": 27, "name": "Sysmon Logs"},
    "outbound_connections":           {"id": 28, "name": "Network Anomaly"},
    "tamper_detection":               {"id": 29, "name": "Tamper Detection"},
    "path_binary_shadowing":          {"id": 30, "name": "Path Shadowing"},
    "open_group_policies":            {"id": 31, "name": "Group Policies"},
    "hsts_missing_for_public_gateway":{"id": 32, "name": "HSTS Check"},
    "csp_integrity":                  {"id": 33, "name": "CSP Integrity",      "badge": "v1.6"},
    "cache_trace_audit":              {"id": 34, "name": "Cache Trace Audit",  "badge": "v1.6"},
    "clawhub_supply_chain":           {"id": 35, "name": "Supply Chain Audit", "badge": "v1.6"},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_status(result: Dict[str, Any]) -> str:
    """Map a check result to a dashboard status color."""
    if result.get("critical"):
        return "red"
    if result.get("warnings"):
        return "amber"
    return "green"


def _build_description(result: Dict[str, Any]) -> str:
    """Compose a human-readable description from check data."""
    critical = result.get("critical", [])
    warnings = result.get("warnings", [])
    findings = result.get("findings", [])

    if critical:
        return "; ".join(str(c)[:200] for c in critical[:2])
    if warnings:
        parts = ["; ".join(str(w)[:200] for w in warnings[:2])]
        if findings:
            parts.append(f"{len(findings)} check(s) passing.")
        return " ".join(parts)
    if findings:
        # Show first 2 findings, trimmed
        items = [str(f)[:150] for f in findings[:2]]
        suffix = f" (+{len(findings) - 2} more)" if len(findings) > 2 else ""
        return "; ".join(items) + suffix
    return "No data available for this check."


def _build_alert(result: Dict[str, Any]) -> str:
    """Build the alert text from critical items (shown in red tooltip box)."""
    critical = result.get("critical", [])
    if not critical:
        return ""
    return "\n".join(str(c)[:300] for c in critical[:5])


# ---------------------------------------------------------------------------
# Main transform
# ---------------------------------------------------------------------------

def scan_to_modules(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert run_security_scan() output to the dashboard API response.

    Returns:
        {
            "modules": [{id, name, s, desc, btn, badge?, alert?}, ...],
            "summary": {total, passing, warnings, critical},
            "scan_level": "light"|"full",
            "scan_duration": float,
            "timestamp": str,
            "version": str,
        }
    """
    results = scan_result.get("results", [])
    modules: List[Dict[str, Any]] = []
    seen: set = set()

    for result in results:
        category = result.get("category", "unknown")
        if category in seen:
            continue
        seen.add(category)

        meta = MODULE_META.get(category)
        if not meta:
            # Unknown check — assign a dynamic ID and show it anyway
            meta = {
                "id": 100 + len(modules),
                "name": category.replace("_", " ").title(),
            }

        status = _check_status(result)
        module: Dict[str, Any] = {
            "id": meta["id"],
            "name": meta["name"],
            "s": status,
            "desc": _build_description(result),
            "btn": (
                "Fix Now" if status == "red"
                else "Review" if status == "amber"
                else "View Details"
            ),
        }

        if meta.get("badge"):
            module["badge"] = meta["badge"]

        alert = _build_alert(result)
        if alert:
            module["alert"] = alert

        modules.append(module)

    # Sort by id for consistent orbit positioning
    modules.sort(key=lambda m: m["id"])

    # Compute summary counts
    green = sum(1 for m in modules if m["s"] == "green")
    amber = sum(1 for m in modules if m["s"] == "amber")
    red = sum(1 for m in modules if m["s"] == "red")

    return {
        "modules": modules,
        "summary": {
            "total": len(modules),
            "passing": green,
            "warnings": amber,
            "critical": red,
        },
        "scan_level": scan_result.get("scan_level", "light"),
        "scan_duration": round(scan_result.get("scan_duration", 0), 2),
        "timestamp": scan_result.get("timestamp", ""),
        "version": __version__,
    }
