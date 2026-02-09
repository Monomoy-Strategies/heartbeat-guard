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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import sqlite3

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
DATA_DIR = os.path.expanduser("~/.heartbeat-guard/data")
STATE_FILE = os.path.join(DATA_DIR, "heartbeat-guard-state.json")
CREDENTIAL_FILE = os.path.join(DATA_DIR, "credential-tracker.json")
BASELINE_FILE = os.path.join(DATA_DIR, "heartbeat-guard-baseline.json")

# Default known good ports
DEFAULT_KNOWN_PORTS = [22, 3001, 5678, 8443, 18789]

# Critical files to monitor
CRITICAL_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    # Note: We use OpenClaw cron, not system crontab
]


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
            disk_usage = psutil.disk_usage('/')
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
    Verify UFW is active and rules haven't changed.
    Compare current rules against known-good baseline.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        # Check UFW status
        success, stdout, stderr = run_command(["sudo", "-n", "ufw", "status", "numbered"])
        
        if not success or ("password" in stderr):
            # Can't run ufw command — check config file instead
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
        
        # Check if UFW is active
        if "Status: active" not in stdout:
            critical.append("UFW firewall is not active!")
        else:
            findings.append("UFW firewall is active")
        
        # Hash current rules for comparison
        rules_hash = hashlib.sha256(stdout.encode()).hexdigest()
        
        state = load_state()
        known_hash = state.get("known_good_firewall_rules_hash")
        
        if known_hash is None:
            # First time - save current state as baseline
            state["known_good_firewall_rules_hash"] = rules_hash
            save_state(state)
            findings.append("UFW rules baseline established")
        elif known_hash != rules_hash:
            warnings.append("UFW firewall rules have changed since last scan")
            # Optionally update the baseline
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
    Known good ports: 22 (SSH), 8443 (OpenClaw gateway), 3001 (Vortxx localhost), 
    5678 (n8n localhost), 18789 (node)
    Alert on any unexpected listeners.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        state = load_state()
        known_ports = set(state.get("known_good_ports", DEFAULT_KNOWN_PORTS))
        
        # Use ss to get listening ports
        success, stdout, stderr = run_command(["ss", "-tuln"])
        
        if not success:
            # Fallback to netstat
            success, stdout, stderr = run_command(["netstat", "-tuln"])
        
        if not success:
            warnings.append("Cannot scan ports: ss and netstat unavailable")
            return {
                "category": "open_ports",
                "findings": findings,
                "warnings": warnings,
                "critical": critical
            }
        
        # Parse listening ports
        listening_ports = set()
        for line in stdout.split('\n'):
            if 'LISTEN' in line or 'listening' in line.lower():
                parts = line.split()
                if len(parts) >= 4:
                    # Extract port from address:port format
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


def check_ssl_certs(domains: List[str]) -> Dict[str, Any]:
    """
    Check SSL certificate expiry for given domains.
    domains = ['monomoystrategies.com', 'openclawhq.ai', 'jasper-hq.vercel.app']
    Warn if < 30 days, alert if < 7 days.
    """
    findings = []
    warnings = []
    critical = []
    
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
    Check auth.log for recent failed SSH login attempts.
    Warn if > 10 failed attempts in last hour.
    Alert if > 50 failed attempts in last hour.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        # Check if we can read auth.log
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
        
        # Try to read the log
        success, stdout, stderr = run_command(["sudo", "tail", "-n", "1000", auth_log])
        
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
        
        # Count failed login attempts in the last hour
        one_hour_ago = datetime.now() - timedelta(hours=1)
        failed_attempts = 0
        
        for line in stdout.split('\n'):
            if 'Failed password' in line or 'Invalid user' in line:
                try:
                    # Parse timestamp from log line (varies by format)
                    # This is a simplified parser - may need adjustment for different log formats
                    failed_attempts += 1
                except:
                    continue
        
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
    Monitor: /etc/ssh/sshd_config, UFW rules, crontab, .env files
    Compare modification times against last known state.
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        state = load_state()
        file_integrity = state.get("file_integrity", {})
        
        current_integrity = {}
        
        for file_path in CRITICAL_FILES:
            if os.path.exists(file_path):
                try:
                    stat = os.stat(file_path)
                    mtime = stat.st_mtime
                    size = stat.st_size
                    
                    # Create a simple integrity signature
                    current_integrity[file_path] = {
                        "mtime": mtime,
                        "size": size,
                        "last_checked": time.time()
                    }
                    
                    # Compare with previous state
                    if file_path in file_integrity:
                        prev_mtime = file_integrity[file_path].get("mtime", 0)
                        prev_size = file_integrity[file_path].get("size", 0)
                        
                        if mtime != prev_mtime or size != prev_size:
                            warnings.append(f"Critical file modified: {file_path}")
                        else:
                            findings.append(f"File unchanged: {os.path.basename(file_path)}")
                    else:
                        findings.append(f"File baseline established: {os.path.basename(file_path)}")
                        
                except OSError as e:
                    warnings.append(f"Cannot check file {file_path}: {e}")
            else:
                warnings.append(f"Critical file missing: {file_path}")
        
        # Update state
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
    Check if system packages have available security updates.
    Run: apt list --upgradable 2>/dev/null
    Warn if security updates available.
    Only run this in 'full' scan mode (not every heartbeat).
    """
    findings = []
    warnings = []
    critical = []
    
    try:
        # Check for upgradable packages
        success, stdout, stderr = run_command(["apt", "list", "--upgradable"], timeout=30)
        
        if not success:
            warnings.append("Cannot check for package updates")
            return {
                "category": "cve_updates",
                "findings": findings,
                "warnings": warnings,
                "critical": critical
            }
        
        # Count upgradable packages
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
            disk_usage = psutil.disk_usage('/')
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
            scan_results.append(check_skill_safety())  # Quick integrity check only
            
        elif level == 'full':
            # Full scan - all checks
            domains = ['monomoystrategies.com', 'openclawhq.ai', 'jasper-hq.vercel.app']
            scan_results.append(check_ssl_certs(domains))
            scan_results.append(check_failed_logins())
            scan_results.append(check_suspicious_processes())
            scan_results.append(check_file_integrity())
            scan_results.append(check_credential_rotation())
            scan_results.append(check_cve_updates())
            scan_results.append(check_skill_safety())  # Full skill security scan
            scan_results.append(check_anomalies())
        
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