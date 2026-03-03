#!/usr/bin/env python3
"""
HeartbeatGuard - Security Monitoring Module

This module provides comprehensive security monitoring capabilities for
OpenClaw AI agents, including system health checks, firewall monitoring,
intrusion detection, and credential rotation tracking.

Copyright (c) 2026 Monomoy Strategies LLC
"""

import sys
import os
import json
import subprocess
import socket
import ssl
import hashlib
import time
import re
import glob
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import sqlite3
import ipaddress

# Import checks subpackage
try:
    from .checks import (
        check_dm_policy_verify,
        check_acp_session_lifecycle,
        check_config_validate,
        check_secret_ref_audit,
    )
    CHECKS_SUBPACKAGE_AVAILABLE = True
except ImportError:
    try:
        from heartbeat_guard.checks import (
            check_dm_policy_verify,
            check_acp_session_lifecycle,
            check_config_validate,
            check_secret_ref_audit,
        )
        CHECKS_SUBPACKAGE_AVAILABLE = True
    except ImportError:
        CHECKS_SUBPACKAGE_AVAILABLE = False

# Try to import psutil, fallback to subprocess-based methods if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available, using fallback methods for system monitoring")

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import skill scanner
try:
    from skill_scanner import SkillScanner
    SKILL_SCANNER_AVAILABLE = True
except ImportError:
    SKILL_SCANNER_AVAILABLE = False
    print("Warning: Skill scanner not available")

# Constants
DATA_DIR = os.environ.get("HEARTBEAT_DATA_DIR", os.path.expanduser("~/.heartbeat-guard/data"))
STATE_FILE = os.path.join(DATA_DIR, "heartbeat-guard-state.json")
CREDENTIAL_FILE = os.path.join(DATA_DIR, "credential-tracker.json")
BASELINE_FILE = os.path.join(DATA_DIR, "heartbeat-guard-baseline.json")

# Default known good ports
# Common Windows ports: 135 (RPC), 139 (NetBIOS), 445 (SMB), 5040 (WSD),
# 5357 (WSDAPI), 7679-7680 (Delivery Optimization), 49664-49670 (Dynamic RPC)
DEFAULT_KNOWN_PORTS_WINDOWS = [
    22, 80, 443, 135, 139, 445, 5040, 5357, 5678,  # Core + n8n
    7679, 7680,  # Windows Delivery Optimization
    11434,  # Ollama
    49664, 49665, 49666, 49667, 49668, 49669, 49670,  # Windows Dynamic RPC
]
DEFAULT_KNOWN_PORTS = [22, 3001, 5678, 8443, 18789]
DEFAULT_DOMAINS = ['monomoystrategies.com', 'openclawhq.ai', 'jasper-hq.vercel.app']

# Critical files to monitor
CRITICAL_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    # Note: We use OpenClaw cron, not system crontab
]


def is_windows() -> bool:
    return os.name == "nt" or sys.platform.startswith("win")


def parse_env_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    # Support comma and path-separator delimited lists
    parts = []
    for chunk in value.split(','):
        parts.extend(chunk.split(os.pathsep))
    return [p.strip() for p in parts if p.strip()]


def get_critical_files() -> List[str]:
    env_files = parse_env_list(os.environ.get("HEARTBEAT_CRITICAL_FILES"))
    if env_files:
        return env_files

    if is_windows():
        windows_files = [
            r"C:\\Windows\\System32\\drivers\\etc\\hosts",
            r"C:\\Windows\\System32\\drivers\\etc\\services",
            r"C:\\Windows\\System32\\drivers\\etc\\networks",
            r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            r"C:\\Windows\\System32\\cmd.exe",
        ]
        defender_globs = [
            r"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe",
            r"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
        ]
        for pattern in defender_globs:
            windows_files.extend(glob.glob(pattern))
        return windows_files

    return CRITICAL_FILES


def compute_file_hash(file_path: str) -> Optional[str]:
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None


def ensure_data_files():
    """Ensure required data files exist with defaults."""
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Create default state file
    if not os.path.exists(STATE_FILE):
        default_state = {
            "last_full_scan": None,
            "last_light_scan": None,
            "known_good_ports": DEFAULT_KNOWN_PORTS,
            "known_good_firewall_rules_hash": None,
            "file_integrity": {},
            "baseline_api_calls_per_hour": 10,
            "baseline_messages_per_hour": 5,
            "baseline_files_written_per_hour": 20
        }
        save_state(default_state)
    
    # Create default credential tracker
    if not os.path.exists(CREDENTIAL_FILE):
        default_credentials = {
            "credentials": [
                {"name": "OpenClaw Gateway Token", "type": "token", "last_rotated": "2026-01-25", "location": "gateway config"},
                {"name": "Database Service Key", "type": "api_key", "last_rotated": "2026-01-25", "location": "backend/.env"},
                {"name": "Web Scraping API Key", "type": "api_key", "last_rotated": "2026-01-25", "location": "~/.config/agent/scraping.env"},
                {"name": "AI Model API Key", "type": "api_key", "last_rotated": "2026-01-25", "location": "~/.config/agent/ai.env"},
                {"name": "TTS API Key", "type": "api_key", "last_rotated": "2026-01-25", "location": "~/.config/agent/tts.env"},
                {"name": "Search API Key", "type": "api_key", "last_rotated": "2026-01-25", "location": "gateway config"},
                {"name": "Cloud Storage OAuth", "type": "oauth", "last_rotated": "2026-02-08", "location": "encrypted vault"},
                {"name": "Email OAuth Tokens", "type": "oauth", "last_rotated": "2026-02-07", "location": "secure storage"}
            ]
        }
        save_credentials(default_credentials)
    
    # Create default baseline file
    if not os.path.exists(BASELINE_FILE):
        default_baseline = {
            "last_updated": datetime.now().isoformat(),
            "api_calls_per_hour": 10,
            "messages_per_hour": 5,
            "files_written_per_hour": 20,
            "cpu_usage_avg": 15.0,
            "memory_usage_avg": 40.0,
            "disk_usage_avg": 60.0
        }
        save_baseline(default_baseline)


def load_state() -> Dict[str, Any]:
    """Load the current state from file."""
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        ensure_data_files()
        with open(STATE_FILE, 'r') as f:
            return json.load(f)


def save_state(state: Dict[str, Any]) -> None:
    """Save the current state to file."""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def load_credentials() -> Dict[str, Any]:
    """Load credential tracking data."""
    try:
        with open(CREDENTIAL_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        ensure_data_files()
        with open(CREDENTIAL_FILE, 'r') as f:
            return json.load(f)


def save_credentials(creds: Dict[str, Any]) -> None:
    """Save credential tracking data."""
    with open(CREDENTIAL_FILE, 'w') as f:
        json.dump(creds, f, indent=2)


def load_baseline() -> Dict[str, Any]:
    """Load baseline metrics."""
    try:
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        ensure_data_files()
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)


def save_baseline(baseline: Dict[str, Any]) -> None:
    """Save baseline metrics."""
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)


def run_command(cmd: List[str], timeout: int = 10) -> Tuple[bool, str, str]:
    """
    Run a system command safely.
    
    Args:
        cmd: Command to run as list
        timeout: Timeout in seconds
    
    Returns:
        Tuple of (success, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            check=False
        )
        return True, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return False, "", str(e)


def check_system_health() -> Dict[str, Any]:
    """
    Check disk usage, memory, CPU, load average.
    Returns warnings if disk > 80%, memory > 90%, load > 4.0
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        if PSUTIL_AVAILABLE:
            # Use psutil for accurate monitoring
            # Check disk usage
            disk_path = 'C:\\' if is_windows() else '/'
            disk_usage = psutil.disk_usage(disk_path)
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            
            if disk_percent > 90:
                critical.append(f"Disk usage critical: {disk_percent:.1f}%")
            elif disk_percent > 80:
                warnings.append(f"Disk usage high: {disk_percent:.1f}%")
            else:
                findings.append(f"Disk usage normal: {disk_percent:.1f}%")
            
            # Check memory usage
            memory = psutil.virtual_memory()
            mem_percent = memory.percent
            
            if mem_percent > 95:
                critical.append(f"Memory usage critical: {mem_percent:.1f}%")
            elif mem_percent > 90:
                warnings.append(f"Memory usage high: {mem_percent:.1f}%")
            else:
                findings.append(f"Memory usage normal: {mem_percent:.1f}%")
            
            # Check CPU usage (1-second average)
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                critical.append(f"CPU usage critical: {cpu_percent:.1f}%")
            elif cpu_percent > 80:
                warnings.append(f"CPU usage high: {cpu_percent:.1f}%")
            else:
                findings.append(f"CPU usage normal: {cpu_percent:.1f}%")
            
            # Check load average
            load_avg = psutil.getloadavg()
            load_1min = load_avg[0]
            
            if load_1min > 8.0:
                critical.append(f"Load average critical: {load_1min:.2f}")
            elif load_1min > 4.0:
                warnings.append(f"Load average high: {load_1min:.2f}")
            else:
                findings.append(f"Load average normal: {load_1min:.2f}")
        
        else:
            # Fallback to command-line tools
            
            if is_windows():
                # Windows fallback without psutil
                # Disk
                success, stdout, stderr = run_command(
                    ["powershell", "-Command",
                     "Get-PSDrive C | ForEach-Object { [math]::Round(($_.Used / ($_.Used + $_.Free)) * 100, 1) }"],
                    timeout=10
                )
                if success and stdout.strip():
                    try:
                        disk_percent = float(stdout.strip())
                        if disk_percent > 90:
                            critical.append(f"Disk usage critical: {disk_percent:.1f}%")
                        elif disk_percent > 80:
                            warnings.append(f"Disk usage high: {disk_percent:.1f}%")
                        else:
                            findings.append(f"Disk usage normal: {disk_percent:.1f}%")
                    except ValueError:
                        warnings.append("Could not parse disk usage")
                else:
                    warnings.append("Could not check disk usage")
                
                # Memory
                success, stdout, stderr = run_command(
                    ["powershell", "-Command",
                     "$os = Get-CimInstance Win32_OperatingSystem; "
                     "[math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)"],
                    timeout=10
                )
                if success and stdout.strip():
                    try:
                        mem_percent = float(stdout.strip())
                        if mem_percent > 95:
                            critical.append(f"Memory usage critical: {mem_percent:.1f}%")
                        elif mem_percent > 90:
                            warnings.append(f"Memory usage high: {mem_percent:.1f}%")
                        else:
                            findings.append(f"Memory usage normal: {mem_percent:.1f}%")
                    except ValueError:
                        warnings.append("Could not parse memory usage")
                else:
                    warnings.append("Could not check memory usage")
                
                # CPU
                success, stdout, stderr = run_command(
                    ["powershell", "-Command",
                     "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average"],
                    timeout=10
                )
                if success and stdout.strip():
                    try:
                        cpu_percent = float(stdout.strip())
                        if cpu_percent > 90:
                            critical.append(f"CPU usage critical: {cpu_percent:.1f}%")
                        elif cpu_percent > 80:
                            warnings.append(f"CPU usage high: {cpu_percent:.1f}%")
                        else:
                            findings.append(f"CPU usage normal: {cpu_percent:.1f}%")
                    except ValueError:
                        warnings.append("Could not parse CPU usage")
                else:
                    warnings.append("Could not check CPU usage")
                
                findings.append("System health check completed (Windows fallback mode)")
                return {
                    "category": "system_health",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            # Linux fallback to command-line tools
            
            # Check disk usage with df
            success, stdout, stderr = run_command(["df", "-h", "/"])
            if success:
                lines = stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        usage_str = parts[4].rstrip('%')
                        try:
                            disk_percent = float(usage_str)
                            if disk_percent > 90:
                                critical.append(f"Disk usage critical: {disk_percent:.1f}%")
                            elif disk_percent > 80:
                                warnings.append(f"Disk usage high: {disk_percent:.1f}%")
                            else:
                                findings.append(f"Disk usage normal: {disk_percent:.1f}%")
                        except ValueError:
                            warnings.append("Could not parse disk usage")
            else:
                warnings.append("Could not check disk usage")
            
            # Check memory with free
            success, stdout, stderr = run_command(["free", "-m"])
            if success:
                lines = stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 3:
                        try:
                            total_mem = float(parts[1])
                            used_mem = float(parts[2])
                            mem_percent = (used_mem / total_mem) * 100
                            
                            if mem_percent > 95:
                                critical.append(f"Memory usage critical: {mem_percent:.1f}%")
                            elif mem_percent > 90:
                                warnings.append(f"Memory usage high: {mem_percent:.1f}%")
                            else:
                                findings.append(f"Memory usage normal: {mem_percent:.1f}%")
                        except ValueError:
                            warnings.append("Could not parse memory usage")
            else:
                warnings.append("Could not check memory usage")
            
            # Check load average with uptime
            success, stdout, stderr = run_command(["uptime"])
            if success:
                # Parse load average from uptime output
                if "load average:" in stdout:
                    load_part = stdout.split("load average:")[1].strip()
                    load_values = load_part.split(",")
                    if load_values:
                        try:
                            load_1min = float(load_values[0].strip())
                            if load_1min > 8.0:
                                critical.append(f"Load average critical: {load_1min:.2f}")
                            elif load_1min > 4.0:
                                warnings.append(f"Load average high: {load_1min:.2f}")
                            else:
                                findings.append(f"Load average normal: {load_1min:.2f}")
                        except ValueError:
                            warnings.append("Could not parse load average")
            else:
                warnings.append("Could not check load average")
            
            findings.append("System health check completed (fallback mode)")
            
    except Exception as e:
        warnings.append(f"System health check failed: {str(e)}")
    
    return {
        "category": "system_health",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_firewall_status() -> Dict[str, Any]:
    """
    Verify firewall is active and rules haven't changed.
    Windows: checks Windows Firewall via netsh.
    Linux: checks UFW.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        if is_windows():
            # Check Windows Firewall status via netsh
            success, stdout, stderr = run_command(
                ["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=15
            )
            if not success:
                warnings.append("Cannot verify Windows Firewall status")
                return {
                    "category": "firewall",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            # Parse profiles - each should show "State ON"
            profiles_off = []
            current_profile = None
            for line in stdout.splitlines():
                line_stripped = line.strip()
                if "Profile Settings" in line_stripped or "profile" in line_stripped.lower():
                    # Extract profile name (Domain, Private, Public)
                    for name in ("Domain", "Private", "Public"):
                        if name in line_stripped:
                            current_profile = name
                            break
                if "State" in line_stripped and current_profile:
                    if "OFF" in line_stripped.upper():
                        profiles_off.append(current_profile)
                    current_profile = None
            
            if profiles_off:
                critical.append(f"Windows Firewall OFF for profiles: {', '.join(profiles_off)}")
            else:
                findings.append("Windows Firewall active on all profiles")
            
            # Hash current firewall rules for drift detection
            success2, rules_stdout, _ = run_command(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], timeout=20
            )
            if success2 and rules_stdout:
                rules_hash = hashlib.sha256(rules_stdout.encode()).hexdigest()
                state = load_state()
                known_hash = state.get("known_good_firewall_rules_hash")
                
                if known_hash is None:
                    state["known_good_firewall_rules_hash"] = rules_hash
                    save_state(state)
                    findings.append("Windows Firewall rules baseline established")
                elif known_hash != rules_hash:
                    warnings.append("Windows Firewall rules have changed since last scan")
                    state["known_good_firewall_rules_hash"] = rules_hash
                    save_state(state)
                else:
                    findings.append("Windows Firewall rules unchanged")
        else:
            # Linux: Check UFW status
            success, stdout, stderr = run_command(["sudo", "-n", "ufw", "status", "numbered"])
            
            if not success or ("password" in stderr):
                try:
                    with open("/etc/ufw/ufw.conf") as f:
                        conf = f.read()
                    if "ENABLED=yes" in conf:
                        findings.append("UFW firewall is enabled (verified via config)")
                    else:
                        critical.append("UFW firewall is disabled in config!")
                except (PermissionError, FileNotFoundError):
                    warnings.append("Cannot verify firewall status: no sudo and config unreadable")
                return {
                    "category": "firewall",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            if "Status: active" not in stdout:
                critical.append("UFW firewall is not active!")
            else:
                findings.append("UFW firewall is active")
            
            rules_hash = hashlib.sha256(stdout.encode()).hexdigest()
            state = load_state()
            known_hash = state.get("known_good_firewall_rules_hash")
            
            if known_hash is None:
                state["known_good_firewall_rules_hash"] = rules_hash
                save_state(state)
                findings.append("UFW rules baseline established")
            elif known_hash != rules_hash:
                warnings.append("UFW firewall rules have changed since last scan")
                state["known_good_firewall_rules_hash"] = rules_hash
                save_state(state)
            else:
                findings.append("UFW firewall rules unchanged")
            
    except Exception as e:
        warnings.append(f"Firewall status check failed: {str(e)}")
    
    return {
        "category": "firewall",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_open_ports() -> Dict[str, Any]:
    """
    Scan for unexpected open ports using ss/netstat.
    Alert on any unexpected listeners.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        state = load_state()
        default_ports = DEFAULT_KNOWN_PORTS_WINDOWS if is_windows() else DEFAULT_KNOWN_PORTS
        known_ports = set(state.get("known_good_ports", default_ports))
        
        listening_ports = set()
        
        if is_windows():
            # Use netstat on Windows
            success, stdout, stderr = run_command(["netstat", "-an"], timeout=15)
            if not success:
                warnings.append("Cannot scan ports on Windows")
                return {
                    "category": "open_ports",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            for line in stdout.split('\n'):
                if 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr_port = parts[1]
                        if ':' in addr_port:
                            port_str = addr_port.split(':')[-1]
                            try:
                                port = int(port_str)
                                listening_ports.add(port)
                            except ValueError:
                                continue
        else:
            # Use ss to get listening ports (Linux)
            success, stdout, stderr = run_command(["ss", "-tuln"])
            if not success:
                success, stdout, stderr = run_command(["netstat", "-tuln"])
            
            if not success:
                warnings.append("Cannot scan ports: ss and netstat unavailable")
                return {
                    "category": "open_ports",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            for line in stdout.split('\n'):
                if 'LISTEN' in line or 'listening' in line.lower():
                    parts = line.split()
                    if len(parts) >= 4:
                        addr_port = parts[3] if 'LISTEN' in line else parts[0]
                        if ':' in addr_port:
                            port_str = addr_port.split(':')[-1]
                            try:
                                port = int(port_str)
                                listening_ports.add(port)
                            except ValueError:
                                continue
        
        # Check for unexpected ports
        unexpected_ports = listening_ports - known_ports
        
        if unexpected_ports:
            for port in sorted(unexpected_ports):
                warnings.append(f"Unexpected listening port: {port}")
        
        # Report known ports
        known_listening = listening_ports & known_ports
        if known_listening:
            findings.append(f"Known services listening on ports: {sorted(known_listening)}")
        
        if not unexpected_ports:
            findings.append("All listening ports are expected")
            
    except Exception as e:
        warnings.append(f"Port scan failed: {str(e)}")
    
    return {
        "category": "open_ports",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_ssl_certs(domains: List[str] = None) -> Dict[str, Any]:
    """
    Check SSL certificate expiry for given domains.
    Warn if < 30 days, alert if < 7 days.
    """
    if domains is None:
        domains = DEFAULT_DOMAINS
    
    findings = []
    warnings = []
    critical = []
    
    if not domains:
        findings.append("No domains configured for SSL monitoring")
        return {
            "category": "ssl_certs",
            "findings": findings,
            "warnings": warnings,
            "critical": critical
        }
    
    for domain in domains:
        try:
            # Connect and get certificate
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Parse expiry date
            not_after = cert['notAfter']
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            
            # Calculate days until expiry
            days_until_expiry = (expiry_date - datetime.now()).days
            
            if days_until_expiry < 0:
                critical.append(f"{domain}: SSL certificate EXPIRED {abs(days_until_expiry)} days ago!")
            elif days_until_expiry < 7:
                critical.append(f"{domain}: SSL certificate expires in {days_until_expiry} days!")
            elif days_until_expiry < 30:
                warnings.append(f"{domain}: SSL certificate expires in {days_until_expiry} days")
            else:
                findings.append(f"{domain}: SSL certificate valid ({days_until_expiry} days remaining)")
                
        except socket.timeout:
            warnings.append(f"{domain}: Connection timeout during SSL check")
        except socket.gaierror:
            warnings.append(f"{domain}: Domain name resolution failed")
        except Exception as e:
            warnings.append(f"{domain}: SSL check failed - {str(e)}")
    
    return {
        "category": "ssl_certs",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_failed_logins() -> Dict[str, Any]:
    """
    Check for failed login attempts.
    Windows: queries Security event log (Event ID 4625).
    Linux: checks auth.log / secure log.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        if is_windows():
            # Query Windows Security Event Log for failed logons (Event ID 4625)
            cmd = [
                "wevtutil", "qe", "Security",
                "/q:*[System[EventID=4625]]",
                "/c:200", "/rd:true", "/f:text"
            ]
            success, stdout, stderr = run_command(cmd, timeout=20)
            if not success:
                # May need elevated privileges
                findings.append("Windows failed login check requires elevated privileges")
                return {
                    "category": "failed_logins",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            # Count events
            failed_attempts = stdout.count("Event[")
            if failed_attempts == 0:
                # Alternative count method
                failed_attempts = stdout.lower().count("event id") if stdout else 0
            
            if failed_attempts > 50:
                critical.append(f"High number of failed Windows logon attempts: {failed_attempts} recent events")
            elif failed_attempts > 10:
                warnings.append(f"Elevated failed Windows logon attempts: {failed_attempts} recent events")
            else:
                findings.append(f"Failed Windows logon attempts normal: {failed_attempts} recent events")
        else:
            # Linux: Check auth.log
            auth_log_paths = ["/var/log/auth.log", "/var/log/secure"]
            auth_log = None
            
            for path in auth_log_paths:
                if os.path.exists(path):
                    auth_log = path
                    break
            
            if not auth_log:
                warnings.append("Cannot locate auth.log or secure log")
                return {
                    "category": "failed_logins",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            success, stdout, stderr = run_command(["sudo", "-n", "tail", "-n", "1000", auth_log])
            
            if not success:
                if "sudo" in stderr:
                    warnings.append("Cannot read auth.log: sudo access required")
                else:
                    warnings.append(f"Cannot read auth.log: {stderr}")
                return {
                    "category": "failed_logins",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            failed_attempts = 0
            for line in stdout.split('\n'):
                if 'Failed password' in line or 'Invalid user' in line:
                    failed_attempts += 1
            
            if failed_attempts > 50:
                critical.append(f"High number of failed login attempts: {failed_attempts} in recent logs")
            elif failed_attempts > 10:
                warnings.append(f"Elevated failed login attempts: {failed_attempts} in recent logs")
            else:
                findings.append(f"Failed login attempts normal: {failed_attempts} in recent logs")
            
    except Exception as e:
        warnings.append(f"Failed login check error: {str(e)}")
    
    return {
        "category": "failed_logins",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_suspicious_processes() -> Dict[str, Any]:
    """
    Look for unexpected processes or high-resource processes.
    Alert on: unknown processes, processes running as root that shouldn't be,
    any process using > 50% CPU or > 50% memory.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        # Known good processes that commonly run as root
        known_root_processes = {
            'systemd', 'kthreadd', 'rcu_gp', 'rcu_par_gp', 'migration', 
            'watchdog', 'ksoftirqd', 'systemd-resolve', 'systemd-network',
            'systemd-logind', 'dbus-daemon', 'NetworkManager', 'wpa_supplicant',
            'dhclient', 'sshd', 'cron', 'rsyslog', 'ufw', 'chronyd',
            'unattended-upgrades', 'packagekitd', 'systemd-journald',
            'systemd-udevd', 'systemd-timesyncd', 'irqbalance',
            # Kernel workers and threads (normal on Linux)
            'kworker', 'pool_workqueue', 'rcu_', 'writeback', 'ata_sff',
            'scsi_', 'md_', 'edac-poller', 'devfreq', 'mld', 'ipv6_addrconf',
            'khungtaskd', 'oom_reaper', 'kcompactd', 'kswapd', 'khugepaged',
            'crypto', 'kintegrityd', 'kblockd', 'blkcg_punt', 'tpm_',
            'netns', 'kauditd', 'inet_frag_wq', 'kdevtmpfs', 'mm_percpu',
            'slub_', 'acpi_', 'pm_wq', 'charger_', 'jbd2', 'ext4',
            'tailscaled', 'containerd', 'dockerd', 'n8n',
            'idle_inject', 'cpuhp', 'inet_frag', 'zswap', 'kstrp',
            'openclaw', 'node', 'tsx',
            'login', 'sd-pam', 'bash', 'sh', 'psimon', 'docker-proxy',
            'agetty', 'polkitd', 'multipathd', 'snapd', 'fwupd',
            'qemu-ga', 'fail2ban', 'clawdbot', 'openclaw'
        }
        
        if PSUTIL_AVAILABLE:
            # Use psutil for detailed process monitoring
            high_cpu_procs = []
            high_mem_procs = []
            suspicious_root_procs = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    
                    # Check for high CPU usage (skip self and guard_cli)
                    if proc_info['cpu_percent'] and proc_info['cpu_percent'] > 50:
                        if 'guard_cli' not in str(proc_info.get('cmdline', '')) and 'heartbeat_guard' not in str(proc_info.get('cmdline', '')):
                            high_cpu_procs.append(f"{proc_info['name']} (PID {proc_info['pid']}): {proc_info['cpu_percent']:.1f}% CPU")
                    
                    # Check for high memory usage
                    if proc_info['memory_percent'] and proc_info['memory_percent'] > 50:
                        high_mem_procs.append(f"{proc_info['name']} (PID {proc_info['pid']}): {proc_info['memory_percent']:.1f}% Memory")
                    
                    # Check for suspicious root processes
                    if proc_info['username'] == 'root':
                        proc_name = proc_info['name']
                        # Check if it's a known good root process
                        if not any(known in proc_name for known in known_root_processes):
                            suspicious_root_procs.append(f"{proc_name} (PID {proc_info['pid']}) running as root")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Report findings
            if high_cpu_procs:
                for proc in high_cpu_procs:
                    critical.append(f"High CPU process: {proc}")
            
            if high_mem_procs:
                for proc in high_mem_procs:
                    critical.append(f"High memory process: {proc}")
            
            if suspicious_root_procs:
                for proc in suspicious_root_procs:
                    warnings.append(f"Unexpected root process: {proc}")
            
            if not high_cpu_procs and not high_mem_procs and not suspicious_root_procs:
                findings.append("All processes appear normal")
        
        else:
            # Fallback to command-line tools
            
            # Use ps to check for high CPU processes
            success, stdout, stderr = run_command(["ps", "aux", "--sort=-%cpu"])
            if success:
                lines = stdout.strip().split('\n')[1:]  # Skip header
                high_cpu_found = False
                
                for line in lines[:10]:  # Check top 10 CPU processes
                    parts = line.split()
                    if len(parts) >= 11:
                        try:
                            cpu_percent = float(parts[2])
                            command = ' '.join(parts[10:])
                            if cpu_percent > 50 and 'guard_cli' not in command and 'heartbeat_guard' not in command:
                                user = parts[0]
                                pid = parts[1]
                                command_short = command[:50] + "..." if len(command) > 50 else command
                                critical.append(f"High CPU process: {command_short} (PID {pid}, {cpu_percent:.1f}% CPU)")
                                high_cpu_found = True
                        except ValueError:
                            continue
                
                if not high_cpu_found:
                    findings.append("No high CPU processes detected")
            else:
                warnings.append("Could not check process CPU usage")
            
            # Check for suspicious root processes (skip kernel threads with PID < 1000)
            success, stdout, stderr = run_command(["ps", "-eo", "pid,user,comm", "--no-headers"])
            if success:
                suspicious_count = 0
                for line in stdout.strip().split('\n'):
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == 'root':
                        try:
                            pid = int(parts[0])
                        except ValueError:
                            continue
                        if pid < 1000:
                            continue  # Skip kernel threads
                        proc_name = parts[2]
                        if not any(known in proc_name for known in known_root_processes):
                            suspicious_count += 1
                            if suspicious_count <= 5:  # Limit output
                                warnings.append(f"Unexpected root process: {proc_name} (PID {parts[0]})")
                
                if suspicious_count == 0:
                    findings.append("No suspicious root processes detected")
                elif suspicious_count > 5:
                    warnings.append(f"... and {suspicious_count - 5} more unexpected root processes")
            else:
                warnings.append("Could not check process users")
            
            findings.append("Process check completed (fallback mode)")
            
    except Exception as e:
        warnings.append(f"Process check failed: {str(e)}")
    
    return {
        "category": "processes",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_file_integrity() -> Dict[str, Any]:
    """
    Check if critical config files have been modified.
    Monitor critical configuration files for unexpected changes.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        state = load_state()
        file_integrity = state.get("file_integrity", {})
        
        current_integrity = {}
        critical_files = get_critical_files()
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    mtime = stat.st_mtime
                    size = stat.st_size
                    file_hash = compute_file_hash(file_path)
                    if not file_hash:
                        warnings.append(f"Unable to hash file: {file_path}")
                    
                    current_integrity[file_path] = {
                        "mtime": mtime,
                        "size": size,
                        "sha256": file_hash,
                        "last_checked": time.time()
                    }
                    
                    if file_path in file_integrity:
                        prev_hash = file_integrity[file_path].get("sha256")
                        if file_hash and prev_hash and file_hash != prev_hash:
                            warnings.append(f"Critical file hash mismatch: {file_path}")
                        else:
                            findings.append(f"File unchanged: {os.path.basename(file_path)}")
                    else:
                        findings.append(f"File baseline established: {os.path.basename(file_path)}")
                        
                except OSError as e:
                    warnings.append(f"Cannot check file {file_path}: {e}")
            else:
                warnings.append(f"Critical file missing: {file_path}")
        
        state["file_integrity"] = current_integrity
        save_state(state)
        
    except Exception as e:
        warnings.append(f"File integrity check failed: {str(e)}")
    
    return {
        "category": "file_integrity",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_credential_rotation() -> Dict[str, Any]:
    """
    Track when API keys and credentials were last rotated.
    Read from ~/clawd/data/credential-tracker.json
    Warn if any credential > 90 days old.
    Alert if any credential > 180 days old.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        creds = load_credentials()
        
        for cred in creds.get("credentials", []):
            name = cred.get("name", "Unknown")
            last_rotated_str = cred.get("last_rotated")
            
            if not last_rotated_str:
                critical.append(f"Credential has no rotation date: {name}")
                continue
            
            try:
                last_rotated = datetime.strptime(last_rotated_str, "%Y-%m-%d")
                days_old = (datetime.now() - last_rotated).days
                
                if days_old > 180:
                    critical.append(f"Credential very old ({days_old} days): {name}")
                elif days_old > 90:
                    warnings.append(f"Credential aging ({days_old} days): {name}")
                else:
                    findings.append(f"Credential fresh ({days_old} days): {name}")
                    
            except ValueError:
                warnings.append(f"Invalid rotation date for credential: {name}")
                
    except Exception as e:
        warnings.append(f"Credential rotation check failed: {str(e)}")
    
    return {
        "category": "credential_rotation",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_cve_updates() -> Dict[str, Any]:
    """
    Check if system has available security updates.
    Windows: checks Windows Update via PowerShell COM object.
    Linux: checks apt for upgradable packages.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        if is_windows():
            # Check Windows Update status via PowerShell
            ps_cmd = (
                "$s = New-Object -ComObject Microsoft.Update.Session; "
                "$u = $s.CreateUpdateSearcher(); "
                "try { $r = $u.Search('IsInstalled=0'); "
                "$total = $r.Updates.Count; "
                "$sec = ($r.Updates | Where-Object { $_.MsrcSeverity }).Count; "
                "Write-Output \"total=$total sec=$sec\" } "
                "catch { Write-Output 'error' }"
            )
            success, stdout, stderr = run_command(
                ["powershell", "-Command", ps_cmd], timeout=60
            )
            if success and stdout and "error" not in stdout.lower():
                parts = {}
                for token in stdout.strip().split():
                    if "=" in token:
                        k, v = token.split("=", 1)
                        parts[k] = v
                total = int(parts.get("total", 0))
                sec = int(parts.get("sec", 0))
                
                if sec > 0:
                    critical.append(f"Windows security updates available: {sec} critical")
                if total > sec:
                    warnings.append(f"Windows updates available: {total - sec} non-security")
                if total == 0:
                    findings.append("Windows is fully up to date")
            else:
                # Fallback: check last update date
                ps_cmd2 = (
                    "Get-HotFix | Sort-Object InstalledOn -Descending | "
                    "Select-Object -First 1 -ExpandProperty InstalledOn"
                )
                success2, stdout2, _ = run_command(
                    ["powershell", "-Command", ps_cmd2], timeout=20
                )
                if success2 and stdout2:
                    findings.append(f"Last Windows update installed: {stdout2.strip()}")
                else:
                    warnings.append("Cannot check Windows Update status")
        else:
            # Linux: Check apt for upgradable packages
            success, stdout, stderr = run_command(["apt", "list", "--upgradable"], timeout=30)
            
            if not success:
                warnings.append("Cannot check for package updates")
                return {
                    "category": "cve_updates",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            upgradable_lines = [line for line in stdout.split('\n') if '/' in line and 'upgradable' in line]
            security_updates = [line for line in upgradable_lines if 'security' in line.lower()]
            
            if security_updates:
                critical.append(f"Security updates available: {len(security_updates)} packages")
            elif upgradable_lines:
                warnings.append(f"Package updates available: {len(upgradable_lines)} packages")
            else:
                findings.append("System packages up to date")
            
    except Exception as e:
        warnings.append(f"CVE update check failed: {str(e)}")
    
    return {
        "category": "cve_updates", 
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_anomalies() -> Dict[str, Any]:
    """
    Detect anomalous behavior by comparing current metrics against baseline.
    Read baseline from ~/clawd/data/heartbeat-guard-baseline.json
    Track: API calls per hour, files written per hour, messages sent per hour
    Alert if current activity > 3x baseline average.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        baseline = load_baseline()
        
        if PSUTIL_AVAILABLE:
            # Use psutil for accurate metrics
            current_cpu = psutil.cpu_percent(interval=1)
            current_memory = psutil.virtual_memory().percent
            disk_path = 'C:\\' if is_windows() else '/'
            disk_usage = psutil.disk_usage(disk_path)
            current_disk = (disk_usage.used / disk_usage.total) * 100
            
            # Compare against baseline
            baseline_cpu = baseline.get("cpu_usage_avg", 15.0)
            baseline_memory = baseline.get("memory_usage_avg", 40.0)
            baseline_disk = baseline.get("disk_usage_avg", 60.0)
            
            if current_cpu > baseline_cpu * 3:
                warnings.append(f"CPU usage anomaly: {current_cpu:.1f}% (baseline: {baseline_cpu:.1f}%)")
            
            if current_memory > baseline_memory * 1.5:  # More conservative for memory
                warnings.append(f"Memory usage anomaly: {current_memory:.1f}% (baseline: {baseline_memory:.1f}%)")
            
            if current_disk > baseline_disk * 1.2:  # Even more conservative for disk
                warnings.append(f"Disk usage anomaly: {current_disk:.1f}% (baseline: {baseline_disk:.1f}%)")
            
            if not warnings:
                findings.append("System metrics within normal range")
        
        else:
            # Fallback to basic checks using command line tools
            
            # Check disk usage with df
            success, stdout, stderr = run_command(["df", "-h", "/"])
            if success:
                lines = stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 5:
                        usage_str = parts[4].rstrip('%')
                        try:
                            current_disk = float(usage_str)
                            baseline_disk = baseline.get("disk_usage_avg", 60.0)
                            
                            if current_disk > baseline_disk * 1.2:
                                warnings.append(f"Disk usage anomaly: {current_disk:.1f}% (baseline: {baseline_disk:.1f}%)")
                            else:
                                findings.append(f"Disk usage normal: {current_disk:.1f}%")
                        except ValueError:
                            warnings.append("Could not parse disk usage for anomaly detection")
            
            # Check load average for CPU anomaly detection
            success, stdout, stderr = run_command(["uptime"])
            if success and "load average:" in stdout:
                load_part = stdout.split("load average:")[1].strip()
                load_values = load_part.split(",")
                if load_values:
                    try:
                        load_1min = float(load_values[0].strip())
                        baseline_load = baseline.get("load_avg", 1.0)
                        
                        if load_1min > baseline_load * 3:
                            warnings.append(f"Load average anomaly: {load_1min:.2f} (baseline: {baseline_load:.2f})")
                        else:
                            findings.append(f"Load average normal: {load_1min:.2f}")
                    except ValueError:
                        warnings.append("Could not parse load average for anomaly detection")
            
            if not warnings:
                findings.append("System metrics appear normal (fallback mode)")
            
        # TODO: Add activity-based anomaly detection when activity logs are available
        # This would track API calls, file operations, messages, etc.
        
    except Exception as e:
        warnings.append(f"Anomaly detection failed: {str(e)}")
    
    return {
        "category": "anomalies",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_skill_safety() -> Dict[str, Any]:
    """
    Check OpenClaw skills for security issues using SkillScanner.
    For light mode: only check integrity
    For full mode: complete scan with pattern detection
    """
    findings = []
    warnings = []
    critical = []
    
    if not SKILL_SCANNER_AVAILABLE:
        warnings.append("Skill scanner module not available")
        return {
            "category": "skill_safety",
            "findings": findings,
            "warnings": warnings,
            "critical": critical
        }
    
    try:
        scanner = SkillScanner()
        
        # Check if baseline exists
        if not scanner.hashes_file.exists():
            warnings.append("No skill integrity baseline found - run --baseline")
            # Generate baseline on first run
            scanner.generate_baseline()
            findings.append("Generated skill integrity baseline")
        
        # Run integrity check (fast, suitable for all scans)
        integrity_result = scanner.check_integrity()
        
        if 'error' in integrity_result:
            warnings.append(f"Integrity check failed: {integrity_result['error']}")
        else:
            stats = integrity_result['stats']
            
            if stats['files_changed'] > 0:
                critical.append(f"🚨 {stats['files_changed']} skill files modified unexpectedly")
            
            if stats['files_added'] > 0:
                warnings.append(f"⚠️ {stats['files_added']} new skill files detected")
            
            if stats['files_removed'] > 0:
                warnings.append(f"⚠️ {stats['files_removed']} skill files removed")
            
            if stats['files_changed'] == 0 and stats['files_added'] == 0 and stats['files_removed'] == 0:
                findings.append(f"Skill integrity OK: {stats['files_checked']} files verified")
        
        # Check for alert file (indicates malicious skills found in recent scan)
        alert_file = Path('/tmp/heartbeat-guard-alert.txt')
        if alert_file.exists():
            try:
                mtime = alert_file.stat().st_mtime
                # Alert is recent (within last 24 hours)
                if time.time() - mtime < 86400:
                    with open(alert_file, 'r') as f:
                        alert_content = f.read().strip()
                    if "MALICIOUS SKILLS DETECTED" in alert_content:
                        critical.append("🚨 MALICIOUS skills detected in recent scan - check alert file")
                    elif "SUSPICIOUS" in alert_content:
                        warnings.append("⚠️ Suspicious skill patterns detected - review needed")
            except Exception:
                pass
    
    except Exception as e:
        warnings.append(f"Skill safety check failed: {str(e)}")
    
    return {
        "category": "skill_safety",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_sysmon_logs() -> Dict[str, Any]:
    """
    Check Sysmon (Windows) or auditd (Linux) logs for suspicious events.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        if is_windows():
            cmd = [
                "wevtutil",
                "qe",
                "Microsoft-Windows-Sysmon/Operational",
                "/c:100",
                "/rd:true",
                "/f:text"
            ]
            success, stdout, stderr = run_command(cmd, timeout=20)
            if not success or not stdout:
                warnings.append("Sysmon logs not available (Sysmon may not be installed)")
                return {
                    "category": "sysmon_logs",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            temp_path_pattern = re.compile(r"\\(Temp|AppData\\Local\\Temp)\\", re.IGNORECASE)
            system_dir_pattern = re.compile(r"C:\\Windows\\System32", re.IGNORECASE)
            dest_ip_pattern = re.compile(r"DestinationIp:\s*(\S+)", re.IGNORECASE)
            image_pattern = re.compile(r"Image:\s*(.+)", re.IGNORECASE)
            target_pattern = re.compile(r"TargetFilename:\s*(.+)", re.IGNORECASE)
            
            suspicious_events = 0
            for line in stdout.splitlines():
                image_match = image_pattern.search(line)
                if image_match:
                    image_path = image_match.group(1).strip()
                    if temp_path_pattern.search(image_path):
                        warnings.append(f"Sysmon: Process launched from temp path: {image_path}")
                        suspicious_events += 1
                
                target_match = target_pattern.search(line)
                if target_match:
                    target_path = target_match.group(1).strip()
                    if system_dir_pattern.search(target_path):
                        warnings.append(f"Sysmon: File created in system directory: {target_path}")
                        suspicious_events += 1
                
                dest_match = dest_ip_pattern.search(line)
                if dest_match:
                    dest_ip = dest_match.group(1).strip()
                    if dest_ip and dest_ip not in ("127.0.0.1", "::1"):
                        try:
                            ip_obj = ipaddress.ip_address(dest_ip)
                            if not ip_obj.is_private:
                                warnings.append(f"Sysmon: External network connection to {dest_ip}")
                                suspicious_events += 1
                        except ValueError:
                            pass
            
            if suspicious_events == 0:
                findings.append("Sysmon logs reviewed: no suspicious patterns detected")
        else:
            audit_log_paths = ["/var/log/audit/audit.log", "/var/log/syslog"]
            audit_log = None
            for path in audit_log_paths:
                if os.path.exists(path):
                    audit_log = path
                    break
            if not audit_log:
                warnings.append("auditd logs not found - consider installing auditd")
                return {
                    "category": "sysmon_logs",
                    "findings": findings,
                    "warnings": warnings,
                    "critical": critical
                }
            
            success, stdout, stderr = run_command(["sudo", "-n", "tail", "-n", "200", audit_log])
            if not success:
                warnings.append("Cannot read audit logs (sudo required)")
            else:
                if "/tmp/" in stdout or "EXECVE" in stdout:
                    warnings.append("auditd: Recent exec activity detected - review audit logs")
                else:
                    findings.append("auditd logs reviewed: no suspicious patterns detected")
    except Exception as e:
        warnings.append(f"Sysmon/audit log check failed: {str(e)}")
    
    return {
        "category": "sysmon_logs",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_command_audit() -> Dict[str, Any]:
    """
    Audit OpenClaw exec logs for suspicious commands and anomalies.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        log_dir = os.environ.get("HEARTBEAT_OPENCLAW_LOG_DIR") or os.environ.get("OPENCLAW_LOG_DIR")
        if not log_dir:
            log_dir = os.path.expanduser("~/.openclaw/logs")
        
        if is_windows():
            log_dir = os.path.expandvars(log_dir)
        
        if not os.path.exists(log_dir):
            warnings.append("OpenClaw log directory not found - command audit skipped")
            return {
                "category": "command_audit",
                "findings": findings,
                "warnings": warnings,
                "critical": critical
            }
        
        log_files = sorted(
            [os.path.join(log_dir, f) for f in os.listdir(log_dir)],
            key=lambda p: os.path.getmtime(p),
            reverse=True
        )
        log_files = [f for f in log_files if os.path.isfile(f)][:3]
        if not log_files:
            warnings.append("No OpenClaw log files found for audit")
            return {
                "category": "command_audit",
                "findings": findings,
                "warnings": warnings,
                "critical": critical
            }
        
        # Patterns that indicate genuinely suspicious activity
        suspicious_patterns = [
            re.compile(r"rm\s+-rf\s+/", re.IGNORECASE),          # Dangerous recursive delete from root
            re.compile(r"curl\s+.*\|\s*(ba)?sh", re.IGNORECASE), # Pipe-to-shell execution
            re.compile(r"wget\s+.*\|\s*(ba)?sh", re.IGNORECASE), # Pipe-to-shell execution
            re.compile(r"powershell\s+-enc", re.IGNORECASE),     # Encoded PowerShell commands
            re.compile(r"Invoke-Expression.*DownloadString", re.IGNORECASE),  # Remote script exec
            re.compile(r"base64\s+-d.*\|\s*(ba)?sh", re.IGNORECASE),  # Decode + execute
            re.compile(r"\.ssh/.*id_rsa", re.IGNORECASE),        # Private key access
            re.compile(r"mimikatz|lazagne|secretsdump", re.IGNORECASE),  # Known attack tools
        ]
        
        # Lines to ignore (normal OpenClaw operations)
        ignore_patterns = [
            re.compile(r"config\.write", re.IGNORECASE),
            re.compile(r"config-io", re.IGNORECASE),
            re.compile(r"heartbeat", re.IGNORECASE),
            re.compile(r"\"event\":\"(start|stop|restart)\"", re.IGNORECASE),
        ]
        
        parsed_commands = []
        for log_file in log_files:
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    for line in f.readlines()[-500:]:
                        if "exec" in line.lower() or "command" in line.lower():
                            parsed_commands.append(line.strip())
            except Exception:
                continue
        
        if not parsed_commands:
            findings.append("No exec commands found in recent logs")
        
        state = load_state()
        baseline_commands = set(state.get("command_audit_baseline", []))
        recent_hashes = set(state.get("command_audit_recent", []))
        audit_log_path = os.path.join(DATA_DIR, "command-audit.log")
        
        for cmd_line in parsed_commands:
            normalized = re.sub(r"\s+", " ", cmd_line).strip()
            
            # Skip normal OpenClaw operations
            if any(ip.search(normalized) for ip in ignore_patterns):
                continue
            
            cmd_hash = hashlib.sha256(normalized.encode()).hexdigest()
            if cmd_hash not in recent_hashes:
                with open(audit_log_path, 'a') as audit_f:
                    audit_f.write(f"{datetime.now().isoformat()} {normalized}\n")
                recent_hashes.add(cmd_hash)
            
            for pattern in suspicious_patterns:
                if pattern.search(normalized):
                    warnings.append(f"Suspicious command pattern detected: {normalized[:120]}")
                    break
        
        if not baseline_commands and parsed_commands:
            baseline_commands.update(parsed_commands)
            findings.append("Command audit baseline established")
        
        state["command_audit_baseline"] = list(baseline_commands)[:200]
        state["command_audit_recent"] = list(recent_hashes)[-200:]
        save_state(state)
        
        if not warnings and parsed_commands:
            findings.append("Command audit completed: no suspicious patterns found")
    except Exception as e:
        warnings.append(f"Command audit check failed: {str(e)}")
    
    return {
        "category": "command_audit",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_outbound_connections() -> Dict[str, Any]:
    """
    Monitor outbound established connections and flag unknown destinations.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        allowed = set(parse_env_list(os.environ.get("HEARTBEAT_ALLOWED_OUTBOUND")))
        connections = []
        
        if is_windows():
            ps_cmd = (
                "Get-NetTCPConnection -State Established | "
                "ForEach-Object { "
                "$p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "
                "\"$($_.RemoteAddress):$($_.RemotePort) $p\" }"
            )
            success, stdout, stderr = run_command(["powershell", "-Command", ps_cmd], timeout=20)
            if success and stdout:
                for line in stdout.splitlines():
                    parts = line.strip().split(None, 1)
                    if parts:
                        remote = parts[0]
                        proc_name = parts[1].strip() if len(parts) > 1 else None
                        connections.append((remote, proc_name))
            else:
                success, stdout, stderr = run_command(["netstat", "-b", "-n"], timeout=20)
                if success:
                    for line in stdout.splitlines():
                        if "ESTABLISHED" in line.upper():
                            parts = line.split()
                            if len(parts) >= 3:
                                remote = parts[2]
                                connections.append((remote, None))
                else:
                    warnings.append("Cannot list outbound connections on Windows")
        else:
            success, stdout, stderr = run_command(["ss", "-tunp"], timeout=15)
            if not success:
                success, stdout, stderr = run_command(["netstat", "-tnp"], timeout=15)
            if success:
                for line in stdout.splitlines():
                    if "ESTAB" in line or "ESTABLISHED" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            remote = parts[4]
                            connections.append((remote, None))
            else:
                warnings.append("Cannot list outbound connections (ss/netstat unavailable)")
        
        # Known good processes that are expected to make outbound connections
        known_good_processes = {
            "chrome", "firefox", "msedge", "msedgewebview2",  # Browsers
            "discord", "telegram", "signal",                   # Messaging
            "onedrive", "googledrivefs", "dropbox",           # Cloud sync
            "svchost", "msmpseng", "msmpeng", "mpdefendercoreservice",  # Windows services + Defender
            "tailscale-ipn", "tailscaled",                    # VPN/Tailscale
            "node", "claude", "cagent",                       # OpenClaw/AI
            "onenote", "outlook", "teams",                    # Office
            "wispr flow",                                     # Wispr
            "code", "cursor",                                 # Editors
            "steam", "epicgameslauncher",                     # Gaming
        }
        
        def is_allowed(remote_addr: str, proc_name: str = None) -> bool:
            if not remote_addr:
                return True
            host = remote_addr.split(':')[0]
            if host in ("127.0.0.1", "::1"):
                return True
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.is_private or ip_obj.is_loopback:
                    return True
            except ValueError:
                pass
            # Check if process is in known-good list
            if proc_name and proc_name.lower().strip() in known_good_processes:
                return True
            for entry in allowed:
                if not entry:
                    continue
                if "/" in entry:
                    try:
                        if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                            return True
                    except Exception:
                        pass
                if entry in remote_addr:
                    return True
            return False
        
        unexpected = set()
        for remote, proc in connections:
            if not is_allowed(remote, proc):
                # Deduplicate by IP:port
                key = remote.split()[0] if remote else remote
                if key not in unexpected:
                    unexpected.add(key)
                    proc_info = f" ({proc})" if proc else ""
                    warnings.append(f"Unexpected outbound connection: {key}{proc_info}")
        
        if connections and not unexpected:
            findings.append(f"Outbound connections normal: {len(connections)} established")
        elif not connections:
            findings.append("No established outbound connections detected")
    except Exception as e:
        warnings.append(f"Outbound connection check failed: {str(e)}")
    
    return {
        "category": "outbound_connections",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }


def check_tamper_detection() -> Dict[str, Any]:
    """
    Hash OpenClaw installation files and HeartbeatGuard source for tampering.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        state = load_state()
        baseline_hashes = state.get("tamper_hashes", {})
        baseline_files = set(state.get("tamper_files", []))
        current_hashes = {}
        current_files = set()
        
        # HeartbeatGuard self-integrity
        src_dir = Path(__file__).resolve().parent
        for py_file in src_dir.glob("*.py"):
            file_hash = compute_file_hash(str(py_file))
            current_hashes[str(py_file)] = file_hash
            current_files.add(str(py_file))
        
        # Locate OpenClaw installation
        openclaw_dir = None
        
        # Try common locations first (faster than npm command)
        common_paths = []
        if is_windows():
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                common_paths.append(os.path.join(appdata, "npm", "node_modules", "openclaw"))
            common_paths.append(os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "npm", "node_modules", "openclaw"))
        else:
            common_paths.extend([
                "/usr/lib/node_modules/openclaw",
                "/usr/local/lib/node_modules/openclaw",
                os.path.expanduser("~/.npm-global/lib/node_modules/openclaw"),
            ])
        
        for candidate in common_paths:
            if os.path.exists(candidate):
                openclaw_dir = candidate
                break
        
        # Fallback to npm root -g (use shell=True on Windows for .cmd files)
        if not openclaw_dir:
            try:
                npm_cmd = "npm root -g"
                result = subprocess.run(
                    npm_cmd, capture_output=True, text=True, timeout=15,
                    shell=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    candidate = os.path.join(result.stdout.strip(), "openclaw")
                    if os.path.exists(candidate):
                        openclaw_dir = candidate
            except Exception:
                pass
        
        if openclaw_dir:
            key_files = [
                os.path.join(openclaw_dir, "package.json"),
            ]
            key_files.extend(glob.glob(os.path.join(openclaw_dir, "**", "*.js"), recursive=True))
            if len(key_files) > 200:
                key_files = key_files[:200]
                warnings.append("OpenClaw file set large; hashing first 200 JS files")
            
            for file_path in key_files:
                if os.path.exists(file_path):
                    file_hash = compute_file_hash(file_path)
                    current_hashes[file_path] = file_hash
                    current_files.add(file_path)
        else:
            warnings.append("OpenClaw installation not found for tamper check")
        
        if not baseline_hashes:
            findings.append("Tamper baseline established")
        else:
            for file_path, current_hash in current_hashes.items():
                prev_hash = baseline_hashes.get(file_path)
                if prev_hash and current_hash and prev_hash != current_hash:
                    critical.append(f"Tamper detected: {file_path}")
            new_files = current_files - baseline_files
            if new_files:
                for new_file in sorted(list(new_files))[:10]:
                    warnings.append(f"Unexpected file detected: {new_file}")
        
        state["tamper_hashes"] = current_hashes
        state["tamper_files"] = list(current_files)
        save_state(state)
        
        if not warnings and not critical:
            findings.append("Tamper detection completed: no changes detected")
    except Exception as e:
        warnings.append(f"Tamper detection failed: {str(e)}")
    
    return {
        "category": "tamper_detection",
        "findings": findings,
        "warnings": warnings,
        "critical": critical
    }



# ---------------------------------------------------------------------------
# OpenClaw 2026.2.22 Security Checks
# These checks detect vulnerabilities patched in OpenClaw 2026.2.22 and flag
# misconfigurations introduced or newly visible in that release.
# ---------------------------------------------------------------------------

OPENCLAW_MIN_SAFE_VERSION = (2026, 2, 22)
OPENCLAW_MIN_SAFE_VERSION_STR = "2026.2.22"


def _find_openclaw_config_files() -> List[str]:
    """Return candidate paths for OpenClaw config/settings files."""
    candidates = []
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")

    if is_windows():
        bases = [
            os.path.join(appdata, "openclaw"),
            os.path.join(home, ".openclaw"),
            os.path.join(home, "AppData", "Roaming", "openclaw"),
        ]
    else:
        bases = [
            os.path.join(home, ".openclaw"),
            "/etc/openclaw",
            "/usr/local/etc/openclaw",
        ]

    config_names = [
        "config.json",
        "settings.json",
        "gateway.json",
        "openclaw.json",
        "openclaw-config.json",
    ]

    for base in bases:
        for name in config_names:
            path = os.path.join(base, name)
            if os.path.exists(path):
                candidates.append(path)

    return candidates


def _load_openclaw_configs() -> List[Dict[str, Any]]:
    """Load and parse all discoverable OpenClaw config files."""
    configs = []
    for path in _find_openclaw_config_files():
        try:
            with open(path, "r", errors="ignore") as f:
                data = json.load(f)
            data["__source__"] = path
            configs.append(data)
        except Exception:
            pass
    return configs


def _get_openclaw_installed_version() -> Optional[str]:
    """
    Attempt to read the installed OpenClaw version from package.json,
    falling back to `openclaw --version`.
    Returns a version string like '2026.2.22' or None.
    """
    # Try npm root
    common_paths = []
    if is_windows():
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            common_paths.append(os.path.join(appdata, "npm", "node_modules", "openclaw", "package.json"))
        common_paths.append(
            os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "npm", "node_modules", "openclaw", "package.json")
        )
    else:
        common_paths.extend([
            "/usr/lib/node_modules/openclaw/package.json",
            "/usr/local/lib/node_modules/openclaw/package.json",
            os.path.join(os.path.expanduser("~"), ".npm-global", "lib", "node_modules", "openclaw", "package.json"),
        ])

    for pkg_path in common_paths:
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r") as f:
                    pkg = json.load(f)
                return pkg.get("version")
            except Exception:
                pass

    # Fallback: npm root -g
    try:
        result = subprocess.run(
            "npm root -g", capture_output=True, text=True, timeout=15,
            shell=True, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            pkg_path = os.path.join(result.stdout.strip(), "openclaw", "package.json")
            if os.path.exists(pkg_path):
                with open(pkg_path, "r") as f:
                    pkg = json.load(f)
                return pkg.get("version")
    except Exception:
        pass

    # Fallback: CLI
    try:
        result = subprocess.run(
            ["openclaw", "--version"], capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            m = re.search(r"(\d{4}\.\d+\.\d+)", result.stdout.strip())
            if m:
                return m.group(1)
    except Exception:
        pass

    return None


def _parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parse a version string like '2026.2.22' into a tuple (2026, 2, 22)."""
    try:
        parts = re.findall(r"\d+", version_str)
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return None


def _version_below_min(version_str: str) -> bool:
    """Return True if the given version is below OPENCLAW_MIN_SAFE_VERSION."""
    parsed = _parse_version(version_str)
    if parsed is None:
        return True  # Unknown version is treated as potentially outdated
    return parsed < OPENCLAW_MIN_SAFE_VERSION


def _deep_search(obj: Any, key_path: str, default: Any = None) -> Any:
    """
    Search a nested dict/list for a dot-separated key path.
    e.g. _deep_search(cfg, 'gateway.controlUi.dangerouslyDisableDeviceAuth')
    """
    keys = key_path.split(".")
    current = obj
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
            if current is None:
                return default
        else:
            return default
    return current


def check_path_binary_shadowing() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.22 Check — PATH Binary Shadowing (HIGH)

    Detects if tools.exec.safeBins entries rely on PATH resolution without
    explicit safeBinTrustedDirs configured. When no trusted dirs are pinned,
    an attacker with write access to any PATH directory can shadow a listed
    binary with a malicious substitute.

    Requires: OpenClaw 2026.2.22+ (safeBinTrustedDirs feature introduced here)
    """
    findings = []
    warnings = []
    critical = []

    try:
        configs = _load_openclaw_configs()

        if not configs:
            findings.append(
                "PATH binary shadowing: No OpenClaw config found — check skipped"
            )
            return {"category": "path_binary_shadowing", "findings": findings,
                    "warnings": warnings, "critical": critical}

        for cfg in configs:
            source = cfg.get("__source__", "unknown config")
            safe_bins = _deep_search(cfg, "tools.exec.safeBins")
            trusted_dirs = _deep_search(cfg, "tools.exec.safeBinTrustedDirs")

            if safe_bins is None:
                # No safeBins configured — not applicable
                continue

            if isinstance(safe_bins, list) and len(safe_bins) > 0:
                if not trusted_dirs or (isinstance(trusted_dirs, list) and len(trusted_dirs) == 0):
                    warnings.append(
                        f"PATH binary shadowing risk in {source}: "
                        f"tools.exec.safeBins has {len(safe_bins)} entries but "
                        f"safeBinTrustedDirs is not set. Add explicit directory "
                        f"paths to prevent PATH-shadowing attacks (requires 2026.2.22+)."
                    )
                else:
                    findings.append(
                        f"PATH binary shadowing: safeBinTrustedDirs configured "
                        f"({len(trusted_dirs) if isinstance(trusted_dirs, list) else '?'} entries) — OK"
                    )

        if not warnings and not critical and configs:
            findings.append("PATH binary shadowing: No unsafe safeBins configuration detected")

    except Exception as e:
        warnings.append(f"PATH binary shadowing check failed: {str(e)}")

    return {
        "category": "path_binary_shadowing",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def check_dangerous_config_flags() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.22 Check — Dangerous Config Flags (CRITICAL)

    Detects if gateway.controlUi.dangerouslyDisableDeviceAuth=true.
    This flag bypasses device authentication for the control UI, exposing the
    gateway to unauthenticated control from any client on the network.
    """
    findings = []
    warnings = []
    critical = []

    try:
        configs = _load_openclaw_configs()

        if not configs:
            findings.append(
                "Dangerous config flags: No OpenClaw config found — check skipped"
            )
            return {"category": "dangerous_config_flags", "findings": findings,
                    "warnings": warnings, "critical": critical}

        for cfg in configs:
            source = cfg.get("__source__", "unknown config")

            # Check dangerouslyDisableDeviceAuth
            disable_auth = _deep_search(cfg, "gateway.controlUi.dangerouslyDisableDeviceAuth")
            if disable_auth is True:
                critical.append(
                    f"CRITICAL: gateway.controlUi.dangerouslyDisableDeviceAuth=true in {source}. "
                    f"Device authentication is DISABLED — the control UI is exposed to unauthenticated "
                    f"access. Remove this flag immediately."
                )
            else:
                findings.append(
                    f"Dangerous config flags: dangerouslyDisableDeviceAuth not set in {source} — OK"
                )

            # Also check for any other 'dangerously' prefixed flags
            for section_name, section_val in cfg.items():
                if section_name.startswith("__"):
                    continue
                if isinstance(section_val, dict):
                    for k, v in section_val.items():
                        if k.lower().startswith("dangerously") and v is True:
                            if k != "dangerouslyDisableDeviceAuth":  # already handled above
                                warnings.append(
                                    f"Dangerous flag '{section_name}.{k}=true' found in {source}. "
                                    f"Verify this is intentional."
                                )

        if not critical and not warnings and configs:
            findings.append("Dangerous config flags: No dangerous flags detected")

    except Exception as e:
        warnings.append(f"Dangerous config flags check failed: {str(e)}")

    return {
        "category": "dangerous_config_flags",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def check_insecure_ws_connections() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.22 Check — Insecure ws:// Remote Connections (HIGH)

    Detects non-loopback ws:// (unencrypted WebSocket) entries in gateway
    remote connection configs. Unencrypted WebSocket traffic can be intercepted
    or manipulated on the network, exposing agent commands, responses, and
    authentication tokens.

    Loopback addresses (127.x.x.x, ::1, localhost) are exempt.
    """
    findings = []
    warnings = []
    critical = []

    _loopback_re = re.compile(r"ws://(?:127\.\d+\.\d+\.\d+|::1|localhost)[:/]", re.IGNORECASE)
    _insecure_ws_re = re.compile(r'ws://([^"\'}\s]+)', re.IGNORECASE)

    try:
        configs = _load_openclaw_configs()

        if not configs:
            findings.append(
                "Insecure ws:// connections: No OpenClaw config found — check skipped"
            )
            return {"category": "insecure_ws_connections", "findings": findings,
                    "warnings": warnings, "critical": critical}

        for cfg in configs:
            source = cfg.get("__source__", "unknown config")
            raw_str = json.dumps(cfg)

            for match in _insecure_ws_re.finditer(raw_str):
                full_url = "ws://" + match.group(1)
                if not _loopback_re.match(full_url):
                    warnings.append(
                        f"Insecure ws:// remote connection in {source}: '{full_url}'. "
                        f"Use wss:// (TLS) for non-loopback gateway remotes to prevent "
                        f"traffic interception."
                    )

        if not warnings and not critical and configs:
            findings.append(
                "Insecure ws:// connections: No non-loopback unencrypted WebSocket "
                "connections detected — OK"
            )

    except Exception as e:
        warnings.append(f"Insecure ws:// connection check failed: {str(e)}")

    return {
        "category": "insecure_ws_connections",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def check_open_group_policies() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.22 Check — Open Group Policies with Runtime/FS Tools (HIGH)

    Detects groups that have exec or file-system tools enabled but have not
    configured any sandboxing restrictions. Without a sandbox, any agent in
    the group can run arbitrary commands or read/write arbitrary files.

    Looks for groups where:
    - tools.exec is enabled OR tools.fs / tools.files is enabled
    - AND no sandbox / allowlist / denylist / safeBins restrictions are set
    """
    findings = []
    warnings = []
    critical = []

    _exec_tool_keys = {"exec", "shell", "run", "command"}
    _fs_tool_keys = {"fs", "files", "file", "filesystem", "write", "read"}
    _sandbox_keys = {"sandbox", "safeBins", "safeBinTrustedDirs", "allowlist",
                     "denylist", "pathAllowlist", "pathDenylist", "securityLevel"}

    def _tools_enabled(tools_obj: Any, key_set: set) -> bool:
        if not isinstance(tools_obj, dict):
            return False
        for k, v in tools_obj.items():
            if k.lower() in key_set:
                if v is True or (isinstance(v, dict) and v.get("enabled", True)):
                    return True
        return False

    def _sandbox_configured(tools_obj: Any) -> bool:
        if not isinstance(tools_obj, dict):
            return False
        for k in tools_obj.keys():
            if k.lower() in _sandbox_keys:
                v = tools_obj[k]
                if v and v is not False:
                    return True
        return False

    try:
        configs = _load_openclaw_configs()

        if not configs:
            findings.append(
                "Open group policies: No OpenClaw config found — check skipped"
            )
            return {"category": "open_group_policies", "findings": findings,
                    "warnings": warnings, "critical": critical}

        flagged = 0
        for cfg in configs:
            source = cfg.get("__source__", "unknown config")
            groups = cfg.get("groups") or cfg.get("group") or []

            if isinstance(groups, dict):
                groups = [groups]

            for group in groups:
                if not isinstance(group, dict):
                    continue

                group_name = group.get("name") or group.get("id") or "unnamed"
                tools = group.get("tools") or {}

                has_exec = _tools_enabled(tools, _exec_tool_keys)
                has_fs = _tools_enabled(tools, _fs_tool_keys)
                has_sandbox = _sandbox_configured(tools)

                if (has_exec or has_fs) and not has_sandbox:
                    tool_types = []
                    if has_exec:
                        tool_types.append("exec")
                    if has_fs:
                        tool_types.append("filesystem")
                    warnings.append(
                        f"Open group policy in {source}, group '{group_name}': "
                        f"{'/'.join(tool_types)} tools enabled with no sandbox "
                        f"restrictions. Set safeBins or pathAllowlist to limit exposure."
                    )
                    flagged += 1
                elif has_exec or has_fs:
                    findings.append(
                        f"Group '{group_name}' has {'/'.join(['exec' if has_exec else '', 'fs' if has_fs else '']).strip('/')} "
                        f"tools with sandbox restrictions — OK"
                    )

        if flagged == 0 and configs:
            findings.append(
                "Open group policies: No unsandboxed groups with runtime/fs tools detected — OK"
            )

    except Exception as e:
        warnings.append(f"Open group policies check failed: {str(e)}")

    return {
        "category": "open_group_policies",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def check_openclaw_version_gate() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.22 Check — Version Gate + Downstream Vulnerability Flags (MEDIUM)

    Flags any OpenClaw install below 2026.2.22 as MEDIUM risk.

    Unpatched vulnerabilities in versions prior to 2026.2.22:
    - Exec environment injection (HOME / ZDOTDIR / SHELLOPTS / PS4 blocking)
    - Shell line-continuation bypass (trailing backslash in exec commands)
    - Symlink escape in webhook transforms
    - Credential leakage via config serialization in debug mode
    - IPv4/IPv6 dual-stack rate limit bypass (dual-bind gateway ports)
    """
    findings = []
    warnings = []
    critical = []

    try:
        version = _get_openclaw_installed_version()

        if version is None:
            warnings.append(
                "OpenClaw version gate: Cannot determine installed OpenClaw version. "
                f"Recommended minimum is {OPENCLAW_MIN_SAFE_VERSION_STR}. "
                "Ensure OpenClaw is installed and accessible."
            )
            return {"category": "openclaw_version_gate", "findings": findings,
                    "warnings": warnings, "critical": critical}

        if _version_below_min(version):
            base_msg = (
                f"OpenClaw version {version} is below the recommended minimum "
                f"{OPENCLAW_MIN_SAFE_VERSION_STR}."
            )
            # Version gate — exec env injection + shell bypass + symlink escape
            warnings.append(
                f"{base_msg} "
                f"UNPATCHED: Exec environment injection vulnerabilities (HOME/ZDOTDIR/"
                f"SHELLOPTS/PS4 variable blocking, shell line-continuation bypass, "
                f"symlink escape in webhook transforms). "
                f"Update to {OPENCLAW_MIN_SAFE_VERSION_STR}+ immediately."
            )
            # Credential leakage
            warnings.append(
                f"Credential leakage risk (version {version} < {OPENCLAW_MIN_SAFE_VERSION_STR}): "
                f"Debug-mode config serialization may expose API keys and tokens in logs. "
                f"Avoid running gateway with debug logging enabled until updated."
            )
            # IPv4/IPv6 rate limit bypass
            warnings.append(
                f"IPv4/IPv6 rate limit bypass risk (version {version} < {OPENCLAW_MIN_SAFE_VERSION_STR}): "
                f"Dual-stack gateway ports may allow rate limits to be bypassed by switching "
                f"between IPv4 and IPv6 source addresses. Update to patch this."
            )
        else:
            findings.append(
                f"OpenClaw version {version} meets or exceeds the recommended "
                f"minimum {OPENCLAW_MIN_SAFE_VERSION_STR} — OK"
            )
            findings.append(
                f"Exec env injection protections (HOME/ZDOTDIR/SHELLOPTS/PS4), "
                f"shell line-continuation bypass fix, and symlink escape patch "
                f"are present in this version."
            )
            findings.append(
                f"Credential leakage via debug serialization: patched in {version}."
            )
            findings.append(
                f"IPv4/IPv6 rate limit bypass: patched in {version}."
            )

    except Exception as e:
        warnings.append(f"OpenClaw version gate check failed: {str(e)}")

    return {
        "category": "openclaw_version_gate",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }



# ---------------------------------------------------------------------------
# OpenClaw 2026.2.23 Security Checks
# These checks detect vulnerabilities patched in OpenClaw 2026.2.23 and flag
# misconfigurations introduced or newly visible in that release.
# ---------------------------------------------------------------------------

OPENCLAW_MIN_SAFE_VERSION_223 = (2026, 2, 23)
OPENCLAW_MIN_SAFE_VERSION_STR_223 = "2026.2.23"


def check_ssrf_legacy_key() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.23 Check — SSRF Legacy Config Key (CRITICAL)

    Detects stale ``browser.ssrfPolicy.allowPrivateNetwork: true`` — the old
    key that was renamed to ``browser.ssrfPolicy.dangerouslyAllowPrivateNetwork``
    in OpenClaw 2026.2.23 as part of the SSRF hardening pass.

    If a user ran `openclaw doctor --fix` the key will have been migrated.
    If not, the SSRF private-network allow is silently NOT applied by OpenClaw
    (the new key is what the runtime reads), so the user believes private-network
    browsing is permitted but the protection gate is actually closed — or vice
    versa depending on their intent.

    Either way this is a misconfiguration that needs human attention.
    Runs in: light + full scan.
    """
    findings = []
    warnings = []
    critical = []

    try:
        configs = _load_openclaw_configs()

        if not configs:
            findings.append(
                "SSRF legacy key: No OpenClaw config found — check skipped"
            )
            return {
                "category": "ssrf_legacy_key",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        for cfg in configs:
            source = cfg.get("__source__", "unknown config")
            legacy_val = _deep_search(cfg, "browser.ssrfPolicy.allowPrivateNetwork")

            if legacy_val is not None:
                # The old key still exists — it's ignored by 2026.2.23+ runtime
                if legacy_val is True:
                    critical.append(
                        f"CRITICAL: Stale SSRF key 'browser.ssrfPolicy.allowPrivateNetwork=true' "
                        f"found in {source}. This key was renamed to "
                        f"'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork' in OpenClaw 2026.2.23. "
                        f"The legacy key is IGNORED by the runtime — SSRF private-network access "
                        f"is NOT active even though your config says it is. "
                        f"Run 'openclaw doctor --fix' to migrate the key."
                    )
                else:
                    # false / null — less dangerous but still stale
                    warnings.append(
                        f"Stale SSRF key 'browser.ssrfPolicy.allowPrivateNetwork={legacy_val}' "
                        f"found in {source}. Renamed to "
                        f"'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork' in 2026.2.23. "
                        f"Run 'openclaw doctor --fix' to clean up your config."
                    )
            else:
                # Check the new key is present if desired
                new_val = _deep_search(cfg, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork")
                if new_val is True:
                    findings.append(
                        f"SSRF legacy key: New key 'dangerouslyAllowPrivateNetwork=true' "
                        f"correctly set in {source} — OK (private-network browsing explicitly allowed)"
                    )
                else:
                    findings.append(
                        f"SSRF legacy key: No legacy SSRF key found in {source} — OK"
                    )

        if not critical and not warnings and configs:
            findings.append(
                "SSRF legacy key: No stale 'allowPrivateNetwork' key detected — OK"
            )

    except Exception as e:
        warnings.append(f"SSRF legacy key check failed: {str(e)}")

    return {
        "category": "ssrf_legacy_key",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def check_hsts_missing_for_public_gateway() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.23 Check — HSTS Missing for Public Gateway (MEDIUM)

    If ``gateway.bind`` is NOT a loopback address (i.e. the gateway is
    public-facing) AND HTTPS appears to be in use (port 443, or 'https' in
    the bind/listen config) AND
    ``gateway.http.securityHeaders.strictTransportSecurity`` is not configured,
    flag it as a MEDIUM finding.

    Strict-Transport-Security (HSTS) is a new optional hardening header added
    in OpenClaw 2026.2.23 that prevents browsers and clients from downgrading
    TLS connections to plain HTTP.

    Runs in: full scan only.
    """
    findings = []
    warnings = []
    critical = []

    _loopback_hosts = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

    def _is_public_bind(bind_str: str) -> bool:
        """Return True if bind address suggests a public/non-loopback deployment."""
        if not bind_str or not isinstance(bind_str, str):
            return False
        host = bind_str.split(":")[0].strip().lower()
        return host not in _loopback_hosts

    def _https_in_use(cfg: Dict) -> bool:
        """Heuristic: HTTPS is in use if port 443, tls/ssl config, or 'https' in listen."""
        tls = _deep_search(cfg, "gateway.tls") or _deep_search(cfg, "gateway.ssl")
        if tls:
            return True
        port = _deep_search(cfg, "gateway.port") or _deep_search(cfg, "gateway.http.port")
        if port and str(port) == "443":
            return True
        listen = _deep_search(cfg, "gateway.listen") or ""
        if "https" in str(listen).lower():
            return True
        return False

    try:
        configs = _load_openclaw_configs()

        if not configs:
            findings.append(
                "HSTS check: No OpenClaw config found — check skipped"
            )
            return {
                "category": "hsts_missing_for_public_gateway",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        for cfg in configs:
            source = cfg.get("__source__", "unknown config")
            bind_addr = (
                _deep_search(cfg, "gateway.bind")
                or _deep_search(cfg, "gateway.host")
                or ""
            )

            is_public = _is_public_bind(str(bind_addr))
            https_active = _https_in_use(cfg)
            hsts_val = _deep_search(
                cfg, "gateway.http.securityHeaders.strictTransportSecurity"
            )

            if is_public and https_active and not hsts_val:
                warnings.append(
                    f"HSTS not configured for public-facing HTTPS gateway in {source}. "
                    f"gateway.bind='{bind_addr}' appears non-loopback and HTTPS is in use, "
                    f"but 'gateway.http.securityHeaders.strictTransportSecurity' is not set. "
                    f"Add HSTS header (introduced in OpenClaw 2026.2.23) to prevent TLS "
                    f"downgrade attacks: set 'max-age=31536000; includeSubDomains'."
                )
            elif is_public and https_active and hsts_val:
                findings.append(
                    f"HSTS configured for public gateway in {source} — OK (value: '{hsts_val}')"
                )
            elif not is_public:
                findings.append(
                    f"HSTS check: Gateway is loopback/private in {source} — HSTS not required"
                )
            else:
                findings.append(
                    f"HSTS check: HTTPS not detected in {source} — HSTS not applicable"
                )

        if not warnings and not critical and configs:
            findings.append(
                "HSTS check: No public HTTPS gateways missing HSTS detected — OK"
            )

    except Exception as e:
        warnings.append(f"HSTS missing check failed: {str(e)}")

    return {
        "category": "hsts_missing_for_public_gateway",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def check_openclaw_version_gate_223() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.23 Version Gate (MEDIUM)

    Bumps the version gate: flags installs below 2026.2.23 for two issues
    introduced or confirmed in that release:

    1. **SSRF policy default change** — The key ``browser.ssrfPolicy.allowPrivateNetwork``
       was renamed to ``browser.ssrfPolicy.dangerouslyAllowPrivateNetwork``. Users on
       older installs who relied on the legacy key have SSRF protection silently broken.

    2. **Config snapshot redaction bypass** — In versions prior to 2026.2.23, debug logs
       could expose ``env.*`` and ``skills.env.*`` config keys (e.g. API keys, tokens)
       in plaintext. OpenClaw 2026.2.23 adds automatic redaction of these key families
       from all log/snapshot outputs.

    Runs in: light + full scan.
    """
    findings = []
    warnings = []
    critical = []

    try:
        version = _get_openclaw_installed_version()

        if version is None:
            warnings.append(
                f"OpenClaw 2026.2.23 version gate: Cannot determine installed version. "
                f"Recommended minimum is {OPENCLAW_MIN_SAFE_VERSION_STR_223}. "
                "Ensure OpenClaw is installed and accessible via PATH or npm."
            )
            return {
                "category": "openclaw_version_gate_223",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        parsed = _parse_version(version)
        below_223 = (parsed is None) or (parsed < OPENCLAW_MIN_SAFE_VERSION_223)

        if below_223:
            base_msg = (
                f"OpenClaw version {version} is below the recommended minimum "
                f"{OPENCLAW_MIN_SAFE_VERSION_STR_223}."
            )
            # SSRF policy default change
            warnings.append(
                f"{base_msg} "
                f"SSRF POLICY CHANGE: 'browser.ssrfPolicy.allowPrivateNetwork' was renamed "
                f"to 'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork' in 2026.2.23. "
                f"Your SSRF private-network policy may be silently inactive. "
                f"Run 'openclaw doctor --fix' after upgrading."
            )
            # Config snapshot redaction bypass
            warnings.append(
                f"CONFIG REDACTION BYPASS (version {version} < {OPENCLAW_MIN_SAFE_VERSION_STR_223}): "
                f"env.* and skills.env.* config keys (API keys, tokens, secrets) may be "
                f"exposed in plaintext in debug logs and config snapshots. "
                f"Avoid running the gateway in debug/verbose mode until you upgrade to "
                f"{OPENCLAW_MIN_SAFE_VERSION_STR_223}+."
            )
        else:
            findings.append(
                f"OpenClaw version {version} meets or exceeds the recommended "
                f"minimum {OPENCLAW_MIN_SAFE_VERSION_STR_223} — OK"
            )
            findings.append(
                f"SSRF policy key migration (dangerouslyAllowPrivateNetwork): "
                f"present in this version."
            )
            findings.append(
                f"Config snapshot redaction for env.*/skills.env.* keys: "
                f"active in this version."
            )

    except Exception as e:
        warnings.append(f"OpenClaw 2026.2.23 version gate check failed: {str(e)}")

    return {
        "category": "openclaw_version_gate_223",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }



# ---------------------------------------------------------------------------
# OpenClaw 2026.2.26 Security Checks
# These checks detect vulnerabilities patched in OpenClaw 2026.2.26 and flag
# misconfigurations introduced or newly visible in that release.
# ---------------------------------------------------------------------------

OPENCLAW_MIN_SAFE_VERSION_226 = (2026, 2, 26)
OPENCLAW_MIN_SAFE_VERSION_STR_226 = "2026.2.26"


def _has_telegram_channel(configs: List[Dict[str, Any]]) -> bool:
    """Return True if any OpenClaw config has a Telegram channel configured."""
    for cfg in configs:
        # Check 'channels' key (list or dict)
        channels = cfg.get("channels") or []
        if isinstance(channels, list):
            for ch in channels:
                if isinstance(ch, dict):
                    if "telegram" in ch.get("type", "").lower():
                        return True
        elif isinstance(channels, dict):
            for key, ch in channels.items():
                if "telegram" in str(key).lower():
                    return True
                if isinstance(ch, dict) and "telegram" in ch.get("type", "").lower():
                    return True

        # Check top-level telegram / telegramBot / bot key
        for top_key in ("telegram", "telegramBot", "bot"):
            val = cfg.get(top_key)
            if isinstance(val, dict) and val:
                # Has a non-empty telegram block
                return True

        # Broad JSON scan — catches any nested telegram token/chat references
        raw = json.dumps(cfg)
        if re.search(r'"type"\s*:\s*"telegram"', raw, re.IGNORECASE):
            return True

    return False


def check_telegram_401_retry_risk() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.26 Check — Telegram Bot Deletion Risk (CRITICAL)

    OpenClaw 2026.2.26 fixed unbounded 401 retries on Telegram's ``sendChatAction``
    endpoint.  On earlier versions, every failed sendChatAction call retries
    indefinitely without back-off.  Telegram's abuse enforcement will permanently
    delete the bot token when it detects this hammering behaviour.

    Flags CRITICAL when:
      - Installed OpenClaw version < 2026.2.26   AND
      - A Telegram channel is present in any OpenClaw config file

    If version >= 2026.2.26 the check passes (fix is present).
    If no Telegram channel is configured the risk does not apply.
    """
    findings = []
    warnings = []
    critical = []

    try:
        version = _get_openclaw_installed_version()
        configs = _load_openclaw_configs()
        telegram_configured = _has_telegram_channel(configs)

        if version is None:
            # Cannot determine version — warn conservatively if telegram found
            if telegram_configured:
                warnings.append(
                    "Telegram 401 retry risk: Cannot determine OpenClaw version but "
                    "a Telegram channel is configured. Versions before 2026.2.26 have "
                    "unbounded 401 retries that can trigger bot deletion. Verify your "
                    "installed version and upgrade to 2026.2.26+ if needed. "
                    "Run: openclaw gateway update"
                )
            else:
                findings.append(
                    "Telegram 401 retry risk: OpenClaw version unknown and no Telegram "
                    "channel detected — check skipped"
                )
            return {
                "category": "telegram_401_retry_risk",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        parsed = _parse_version(version)
        below_226 = (parsed is None) or (parsed < OPENCLAW_MIN_SAFE_VERSION_226)

        if below_226 and telegram_configured:
            critical.append(
                "Telegram bot deletion risk: OpenClaw versions before 2026.2.26 have "
                "unbounded 401 retries on Telegram API calls. This can trigger Telegram "
                "abuse enforcement and permanent bot deletion. Upgrade to 2026.2.26+ "
                "immediately or disable the Telegram channel until upgraded. "
                "Run: openclaw gateway update"
            )
        elif below_226 and not telegram_configured:
            findings.append(
                f"Telegram 401 retry risk: OpenClaw {version} is below 2026.2.26 but "
                f"no Telegram channel detected — risk does not apply"
            )
        else:
            # version >= 2026.2.26
            findings.append(
                f"Telegram 401 retry risk: OpenClaw {version} >= 2026.2.26 — "
                f"unbounded retry bug is patched"
            )
            if telegram_configured:
                findings.append("Telegram channel is configured and safe on this version")

    except Exception as e:
        warnings.append(f"Telegram 401 retry risk check failed: {str(e)}")

    return {
        "category": "telegram_401_retry_risk",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def _find_openclaw_log_files() -> List[str]:
    """Return candidate OpenClaw log file paths, most-specific first."""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    candidates = []

    # Environment override (highest priority)
    env_log_dir = (
        os.environ.get("HEARTBEAT_OPENCLAW_LOG_DIR")
        or os.environ.get("OPENCLAW_LOG_DIR")
    )
    if env_log_dir:
        log_dir = os.path.expandvars(env_log_dir)
        candidates.extend(glob.glob(os.path.join(log_dir, "*.log")))
        candidates.extend(glob.glob(os.path.join(log_dir, "gateway*.log")))
        candidates.extend(glob.glob(os.path.join(log_dir, "openclaw*.log")))

    # Standard locations
    search_dirs: List[str] = []
    if is_windows():
        search_dirs = [
            os.path.join(home, ".openclaw", "logs"),
            os.path.join(appdata, "openclaw", "logs"),
            os.path.join(localappdata, "openclaw", "logs"),
            os.path.join(appdata, "npm", "node_modules", "openclaw", "logs"),
        ]
    else:
        search_dirs = [
            os.path.join(home, ".openclaw", "logs"),
            "/var/log/openclaw",
            "/usr/local/var/log/openclaw",
        ]

    for d in search_dirs:
        if os.path.isdir(d):
            for pattern in ("*.log", "gateway*.log", "openclaw*.log"):
                candidates.extend(glob.glob(os.path.join(d, pattern)))

    # Deduplicate, keep existing files only, sort newest first
    seen: set = set()
    result: List[str] = []
    for p in candidates:
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            result.append(p)

    result.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return result


def check_gateway_restart_loop() -> Dict[str, Any]:
    """
    OpenClaw 2026.2.26 Check — Gateway Restart Loop Detector (HIGH)

    Parses OpenClaw log files for gateway start/restart events within the last
    10 minutes.  Three or more restarts in that window is a strong indicator of
    a crash loop that will eventually cause a full service outage.

    Outcomes:
      - 3+ restarts in last 10 min  → HIGH
      - 0-2 restarts                → PASS
      - Log file not found          → INFO (Cannot check restart history)
    """
    findings = []
    warnings = []
    critical = []

    WINDOW_SECONDS = 600       # 10-minute sliding window
    RESTART_THRESHOLD = 3      # alert at this many restarts

    # Patterns that indicate a gateway start/restart event
    _restart_patterns = [
        re.compile(r'"event"\s*:\s*"(start|restart|gateway[_-]start)"', re.IGNORECASE),
        re.compile(r'\bgateway\b.{0,30}\b(start(?:ed|ing)?|restart(?:ed|ing)?)\b', re.IGNORECASE),
        re.compile(r'\b(start(?:ed|ing)?|restart(?:ed|ing)?)\b.{0,30}\bgateway\b', re.IGNORECASE),
        re.compile(r'\bOpenClaw gateway (started|restarted|starting)\b', re.IGNORECASE),
    ]

    # Patterns to extract ISO-8601 or common timestamp from a log line
    _ts_patterns = [
        # ISO 8601 with optional ms/tz  e.g. 2026-02-26T14:05:23.456Z
        re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
        # Bracketed  [2026-02-26 14:05:23]
        re.compile(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]'),
        # Plain      2026-02-26 14:05:23
        re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'),
    ]

    def _extract_timestamp(line: str) -> Optional[datetime]:
        for pat in _ts_patterns:
            m = pat.search(line)
            if m:
                ts_str = m.group(1).replace("T", " ")
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        return datetime.strptime(ts_str, fmt)
                    except ValueError:
                        pass
        return None

    try:
        log_files = _find_openclaw_log_files()

        if not log_files:
            findings.append(
                "Cannot check restart history — log file not found. "
                "Set OPENCLAW_LOG_DIR to point to your OpenClaw log directory."
            )
            return {
                "category": "gateway_restart_loop",
                "findings": findings,
                "warnings": warnings,
                "critical": critical,
            }

        cutoff = datetime.now() - timedelta(seconds=WINDOW_SECONDS)
        recent_restarts: List[str] = []  # timestamps as strings for reporting

        for log_file in log_files[:5]:   # check up to 5 most-recent log files
            try:
                with open(log_file, "r", errors="ignore") as fh:
                    lines = fh.readlines()

                # Only scan recent tail — 2000 lines max per file
                for line in lines[-2000:]:
                    line = line.rstrip()
                    if not any(pat.search(line) for pat in _restart_patterns):
                        continue
                    ts = _extract_timestamp(line)
                    if ts is None:
                        # No timestamp extractable — count it as recent if file is recent
                        file_mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
                        if file_mtime >= cutoff:
                            recent_restarts.append(f"(no timestamp — in {os.path.basename(log_file)})")
                    elif ts >= cutoff:
                        recent_restarts.append(ts.strftime("%H:%M:%S"))

            except Exception:
                continue

        n = len(recent_restarts)

        if n >= RESTART_THRESHOLD:
            warnings.append(
                f"Gateway restart loop detected: {n} restarts in the last "
                f"{WINDOW_SECONDS // 60} minutes. This indicates a crash loop that "
                f"may cause service outage. Check logs for root cause: look for config "
                f"errors, port conflicts, or plugin crashes. "
                f"Run: openclaw gateway status"
            )
        elif n > 0:
            findings.append(
                f"Gateway restart activity: {n} restart event(s) in last "
                f"{WINDOW_SECONDS // 60} minutes (below threshold of {RESTART_THRESHOLD})"
            )
        else:
            findings.append(
                f"Gateway restart loop: No restart events detected in last "
                f"{WINDOW_SECONDS // 60} minutes — OK"
            )

    except Exception as e:
        warnings.append(f"Gateway restart loop check failed: {str(e)}")

    return {
        "category": "gateway_restart_loop",
        "findings": findings,
        "warnings": warnings,
        "critical": critical,
    }


def generate_security_report(scan_results: List[Dict[str, Any]]) -> str:
    """
    Generate a Telegram-formatted security report from scan results.
    Format with emoji severity levels:
    🟢 All clear
    🟡 Warning (needs attention soon)
    🔴 Critical (needs immediate attention)
    """
    total_critical = sum(len(result.get("critical", [])) for result in scan_results)
    total_warnings = sum(len(result.get("warnings", [])) for result in scan_results)
    total_findings = sum(len(result.get("findings", [])) for result in scan_results)
    
    # Determine overall status
    if total_critical > 0:
        status_emoji = "🔴"
        status = "CRITICAL ISSUES DETECTED"
    elif total_warnings > 0:
        status_emoji = "🟡"
        status = "WARNINGS DETECTED"
    else:
        status_emoji = "🟢"
        status = "ALL CLEAR"
    
    report = f"🛡️ **HeartbeatGuard Security Report**\n"
    report += f"{status_emoji} {status}\n"
    report += f"📊 {total_findings} findings, {total_warnings} warnings, {total_critical} critical\n\n"
    
    # Add details for warnings and critical issues
    for result in scan_results:
        category = result.get("category", "unknown").replace("_", " ").title()
        
        critical_items = result.get("critical", [])
        warning_items = result.get("warnings", [])
        
        if critical_items or warning_items:
            report += f"**{category}:**\n"
            
            for item in critical_items:
                report += f"🔴 {item}\n"
            
            for item in warning_items:
                report += f"🟡 {item}\n"
            
            report += "\n"
    
    # Add summary of normal findings if everything is OK
    if total_critical == 0 and total_warnings == 0:
        report += "**All Systems Normal:**\n"
        for result in scan_results:
            category = result.get("category", "unknown").replace("_", " ").title()
            findings = result.get("findings", [])
            if findings:
                report += f"✅ {category}: {len(findings)} checks passed\n"
    
    return report


def run_security_scan(level: str = 'light') -> Dict[str, Any]:
    """
    Run a security scan.
    level='light' — quick checks suitable for every heartbeat (~5 seconds)
    level='full' — comprehensive scan for scheduled reviews (~30 seconds)
    Returns dict with findings, warnings, and critical alerts.
    """
    ensure_data_files()
    
    start_time = time.time()
    scan_results = []
    
    try:
        # Always run these checks
        scan_results.append(check_system_health())
        scan_results.append(check_firewall_status())
        scan_results.append(check_open_ports())
        
        if level == 'light':
            # Light scan - skip expensive checks
            scan_results.append(check_credential_rotation())
            scan_results.append(check_command_audit())
            scan_results.append(check_skill_safety())  # Quick integrity check only
            # 2026.2.22: Always check for critical config misconfigurations in light mode
            scan_results.append(check_dangerous_config_flags())
            scan_results.append(check_insecure_ws_connections())
            scan_results.append(check_openclaw_version_gate())
            # 2026.2.23: SSRF legacy key and version gate run in light mode
            scan_results.append(check_ssrf_legacy_key())
            scan_results.append(check_openclaw_version_gate_223())
            # 2026.2.26: Telegram 401 retry risk and gateway restart loop
            scan_results.append(check_telegram_401_retry_risk())
            scan_results.append(check_gateway_restart_loop())
            # Channel / session hygiene checks
            if CHECKS_SUBPACKAGE_AVAILABLE:
                scan_results.append(check_dm_policy_verify())
                scan_results.append(check_acp_session_lifecycle())
                # 2026.3.2: Config validation and SecretRef audit
                scan_results.append(check_config_validate())
                scan_results.append(check_secret_ref_audit())

        elif level == 'full':
            # Full scan - all checks
            scan_results.append(check_ssl_certs())
            scan_results.append(check_failed_logins())
            scan_results.append(check_suspicious_processes())
            scan_results.append(check_file_integrity())
            scan_results.append(check_credential_rotation())
            scan_results.append(check_cve_updates())
            scan_results.append(check_skill_safety())  # Full skill security scan
            scan_results.append(check_anomalies())
            scan_results.append(check_sysmon_logs())
            scan_results.append(check_command_audit())
            scan_results.append(check_outbound_connections())
            scan_results.append(check_tamper_detection())
            # 2026.2.22: New security checks
            scan_results.append(check_path_binary_shadowing())
            scan_results.append(check_dangerous_config_flags())
            scan_results.append(check_insecure_ws_connections())
            scan_results.append(check_open_group_policies())
            scan_results.append(check_openclaw_version_gate())
            # 2026.2.23: New security checks
            scan_results.append(check_ssrf_legacy_key())
            scan_results.append(check_hsts_missing_for_public_gateway())
            scan_results.append(check_openclaw_version_gate_223())
            # 2026.2.26: Telegram 401 retry risk and gateway restart loop
            scan_results.append(check_telegram_401_retry_risk())
            scan_results.append(check_gateway_restart_loop())
            # Channel / session hygiene checks
            if CHECKS_SUBPACKAGE_AVAILABLE:
                scan_results.append(check_dm_policy_verify())
                scan_results.append(check_acp_session_lifecycle())
                # 2026.3.2: Config validation and SecretRef audit
                scan_results.append(check_config_validate())
                scan_results.append(check_secret_ref_audit())
        
        # Update scan timestamps
        state = load_state()
        timestamp = datetime.now().isoformat()
        
        if level == 'light':
            state["last_light_scan"] = timestamp
        else:
            state["last_full_scan"] = timestamp
            
        save_state(state)
        
        scan_duration = time.time() - start_time
        
        return {
            "scan_level": level,
            "scan_duration": scan_duration,
            "timestamp": timestamp,
            "results": scan_results,
            "summary": generate_security_report(scan_results)
        }
        
    except Exception as e:
        return {
            "scan_level": level,
            "scan_duration": time.time() - start_time,
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "results": scan_results,
            "summary": f"🔴 Security scan failed: {str(e)}"
        }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="HeartbeatGuard Security Monitor")
    parser.add_argument("--level", choices=["light", "full"], default="light",
                        help="Scan level (light for heartbeats, full for comprehensive)")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    
    args = parser.parse_args()
    
    result = run_security_scan(args.level)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result["summary"])
        if "error" in result:
            print(f"\nError: {result['error']}")
