"""
HeartbeatGuard - Your AI Agent's Security Watchdog

A comprehensive security monitoring system designed for OpenClaw AI agents.
Provides real-time security scanning, threat detection, and system health monitoring.

Author: Monomoy Strategies
Website: https://heartbeatguard.com
License: MIT
"""

__version__ = "1.2.0"  # 2026.2.22: Added 7 new security checks for OpenClaw 2026.2.22
__author__ = "Monomoy Strategies"
__email__ = "bsifflard@monomoystrategies.com"

# Import main functionality
from .scanner import run_security_scan, HeartbeatGuard
from .skill_scanner import SkillScanner
from .cli import main as cli_main

__all__ = [
    "run_security_scan", 
    "HeartbeatGuard", 
    "SkillScanner", 
    "cli_main",
    "__version__",
    "__author__"
]