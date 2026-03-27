"""
HeartbeatGuard — checks subpackage

Each module in this package provides one or more standalone check functions
that follow the standard HeartbeatGuard return contract:

    {
        "category": "<snake_case_name>",
        "findings": [...],   # informational / PASS messages
        "warnings": [...],   # WARN — needs attention
        "critical": [...],   # FAIL — needs immediate action
    }
"""

from .dm_policy_verify import check_dm_policy_verify
from .acp_session_lifecycle import check_acp_session_lifecycle
from .code_safety import check_code_safety
from .config_validate import check_config_validate
from .secret_ref_audit import check_secret_ref_audit
from .media_sandbox_verify import check_media_sandbox_verify
from .csp_integrity import check_csp_integrity
from .channel_id_injection import check_channel_id_injection
from .long_session_monitor import check_long_session_monitor
from .cache_trace_audit import check_cache_trace_audit
from .clawhub_supply_chain import check_clawhub_supply_chain

__all__ = [
    "check_dm_policy_verify",
    "check_acp_session_lifecycle",
    "check_code_safety",
    "check_config_validate",
    "check_secret_ref_audit",
    "check_media_sandbox_verify",
    "check_csp_integrity",
    "check_channel_id_injection",
    "check_long_session_monitor",
    "check_cache_trace_audit",
    "check_clawhub_supply_chain",
]
