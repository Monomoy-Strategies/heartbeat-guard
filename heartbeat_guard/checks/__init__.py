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

__all__ = [
    "check_dm_policy_verify",
    "check_acp_session_lifecycle",
    "check_code_safety",
    "check_config_validate",
    "check_secret_ref_audit",
]
