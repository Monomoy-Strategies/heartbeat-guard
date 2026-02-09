#!/usr/bin/env python3
"""
HeartbeatGuard CLI - Command Line Interface for Security Monitoring

Usage:
    # Quick scan (suitable for heartbeat)
    heartbeat-guard --light

    # Full scan
    heartbeat-guard --full

    # Check specific area
    heartbeat-guard --check firewall
    heartbeat-guard --check ports
    heartbeat-guard --check ssl
    heartbeat-guard --check logins
    heartbeat-guard --check creds

    # Show last scan results
    heartbeat-guard --status

    # Generate report for integration
    heartbeat-guard --report

Copyright (c) 2026 Monomoy Strategies LLC
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import HeartbeatGuard functions
from .scanner import (
    run_security_scan,
    check_system_health,
    check_firewall_status,
    check_open_ports,
    check_ssl_certs,
    check_failed_logins,
    check_suspicious_processes,
    check_file_integrity,
    check_credential_rotation,
    check_cve_updates,
    check_anomalies,
    generate_security_report,
    load_state,
    ensure_data_files
)

# Import security hooks for logging
try:
    from hooks.security_hook import (
        log_security_scan,
        log_security_alert,
        get_security_history,
        get_security_stats
    )
    HOOKS_AVAILABLE = True
except ImportError:
    HOOKS_AVAILABLE = False
    print("Warning: Security hooks not available - logging disabled")


def run_individual_check(check_type: str, **kwargs):
    """Run an individual security check."""
    check_functions = {
        'health': check_system_health,
        'firewall': check_firewall_status,
        'ports': check_open_ports,
        'ssl': lambda: check_ssl_certs(kwargs.get('domains', ['monomoystrategies.com', 'openclawhq.ai', 'jasper-hq.vercel.app'])),
        'logins': check_failed_logins,
        'processes': check_suspicious_processes,
        'files': check_file_integrity,
        'creds': check_credential_rotation,
        'updates': check_cve_updates,
        'anomalies': check_anomalies
    }
    
    if check_type not in check_functions:
        print(f"Error: Unknown check type '{check_type}'")
        print(f"Available checks: {', '.join(check_functions.keys())}")
        return None
    
    print(f"Running {check_type} check...")
    result = check_functions[check_type]()
    
    return result


def print_check_result(result, json_output=False):
    """Print the result of a security check."""
    if json_output:
        print(json.dumps(result, indent=2))
        return
    
    category = result.get('category', 'unknown').replace('_', ' ').title()
    
    print(f"\n🔍 {category} Check Results:")
    print("=" * 50)
    
    # Print critical issues
    critical = result.get('critical', [])
    if critical:
        print("\n🔴 CRITICAL ISSUES:")
        for item in critical:
            print(f"  • {item}")
    
    # Print warnings
    warnings = result.get('warnings', [])
    if warnings:
        print("\n🟡 WARNINGS:")
        for item in warnings:
            print(f"  • {item}")
    
    # Print normal findings
    findings = result.get('findings', [])
    if findings:
        print("\n🟢 NORMAL:")
        for item in findings:
            print(f"  • {item}")
    
    if not critical and not warnings and not findings:
        print("  No results")


def show_status():
    """Show status of last scans and current state."""
    ensure_data_files()
    state = load_state()
    
    print("🛡️ HeartbeatGuard Status")
    print("=" * 50)
    
    # Last scan times
    last_light = state.get('last_light_scan')
    last_full = state.get('last_full_scan')
    
    if last_light:
        print(f"Last light scan: {last_light}")
    else:
        print("Last light scan: Never")
    
    if last_full:
        print(f"Last full scan:  {last_full}")
    else:
        print("Last full scan:  Never")
    
    # Known good ports
    known_ports = state.get('known_good_ports', [])
    print(f"Known good ports: {known_ports}")
    
    # Firewall rules hash
    fw_hash = state.get('known_good_firewall_rules_hash')
    if fw_hash:
        print(f"Firewall baseline: {fw_hash[:12]}...")
    else:
        print("Firewall baseline: Not established")
    
    # File integrity count
    file_integrity = state.get('file_integrity', {})
    print(f"Files monitored: {len(file_integrity)}")
    
    # Show recent security history if hooks available
    if HOOKS_AVAILABLE:
        print("\n📊 Recent Security Activity (Last 7 days):")
        try:
            stats = get_security_stats(7)
            print(f"  • Scans performed: {stats.get('scans_performed', 0)}")
            print(f"  • Alerts raised: {stats.get('alerts_raised', 0)}")
            print(f"  • Actions taken: {stats.get('actions_taken', 0)}")
            
            if stats.get('avg_scan_duration', 0) > 0:
                print(f"  • Avg scan duration: {stats.get('avg_scan_duration', 0):.1f}s")
                
        except Exception as e:
            print(f"  Error getting stats: {e}")


def show_report():
    """Generate and show a security report."""
    print("🛡️ Generating Security Report...")
    
    # Run a light scan to get current status
    result = run_security_scan('light')
    
    if 'error' in result:
        print(f"❌ Error generating report: {result['error']}")
        return
    
    print("\n" + result['summary'])
    
    # Log the scan if hooks are available
    if HOOKS_AVAILABLE:
        try:
            log_security_scan(result['scan_level'], result)
            print(f"\n📝 Scan logged to analytics database")
        except Exception as e:
            print(f"\n⚠️  Failed to log scan: {e}")


def show_history(days=7):
    """Show security history."""
    if not HOOKS_AVAILABLE:
        print("❌ Security history not available - hooks not loaded")
        return
    
    print(f"🕒 Security History (Last {days} days)")
    print("=" * 50)
    
    try:
        history = get_security_history(days)
        
        if not history:
            print("No security events found")
            return
        
        for event in history[:20]:  # Show last 20 events
            timestamp = event.get('timestamp', 'Unknown')
            event_type = event.get('event_type', 'unknown')
            content = event.get('content', 'No content')
            status = event.get('status', 'unknown')
            
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%m-%d %H:%M')
            except:
                time_str = timestamp[:16] if len(timestamp) > 16 else timestamp
            
            # Choose emoji based on event type and status
            if event_type == 'notification':
                if 'critical' in status:
                    emoji = "🔴"
                elif 'warning' in status:
                    emoji = "🟡"
                else:
                    emoji = "🟢"
            else:
                emoji = "🔧"
            
            print(f"{emoji} {time_str} | {content}")
            
    except Exception as e:
        print(f"❌ Error getting security history: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="HeartbeatGuard Security Monitoring CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --light                    # Quick security scan
  %(prog)s --full                     # Comprehensive security scan  
  %(prog)s --check firewall           # Check firewall status only
  %(prog)s --check ssl --domains example.com,test.org  # Check specific domains
  %(prog)s --status                   # Show current status
  %(prog)s --report                   # Generate security report
  %(prog)s --history --days 14        # Show 14 days of security history
  %(prog)s --full --json              # Full scan with JSON output
        """
    )
    
    # Scan options
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('--light', action='store_true',
                           help='Run light security scan (quick checks for heartbeat)')
    scan_group.add_argument('--full', action='store_true', 
                           help='Run full security scan (comprehensive)')
    
    # Individual check options
    parser.add_argument('--check', choices=[
        'health', 'firewall', 'ports', 'ssl', 'logins', 
        'processes', 'files', 'creds', 'updates', 'anomalies'
    ], help='Run specific security check')
    
    # SSL check domains
    parser.add_argument('--domains', type=str,
                       help='Comma-separated list of domains for SSL check')
    
    # Status and reporting
    parser.add_argument('--status', action='store_true',
                       help='Show HeartbeatGuard status')
    parser.add_argument('--report', action='store_true',
                       help='Generate security report')
    parser.add_argument('--history', action='store_true',
                       help='Show security history')
    parser.add_argument('--days', type=int, default=7,
                       help='Days of history to show (default: 7)')
    
    # Output format
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress non-error output')
    
    args = parser.parse_args()
    
    # Ensure data files exist
    ensure_data_files()
    
    try:
        if args.light:
            if not args.quiet:
                print("🚀 Running light security scan...")
            result = run_security_scan('light')
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(result['summary'])
                if not args.quiet:
                    print(f"\n⏱️  Scan completed in {result.get('scan_duration', 0):.1f}s")
            
            # Log the scan
            if HOOKS_AVAILABLE and 'error' not in result:
                try:
                    log_security_scan(result['scan_level'], result)
                except Exception as e:
                    if not args.quiet:
                        print(f"Warning: Failed to log scan: {e}")
        
        elif args.full:
            if not args.quiet:
                print("🔍 Running full security scan...")
            result = run_security_scan('full')
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(result['summary'])
                if not args.quiet:
                    print(f"\n⏱️  Scan completed in {result.get('scan_duration', 0):.1f}s")
            
            # Log the scan
            if HOOKS_AVAILABLE and 'error' not in result:
                try:
                    log_security_scan(result['scan_level'], result)
                except Exception as e:
                    if not args.quiet:
                        print(f"Warning: Failed to log scan: {e}")
        
        elif args.check:
            # Parse domains if provided
            domains = None
            if args.domains:
                domains = [d.strip() for d in args.domains.split(',')]
            
            result = run_individual_check(args.check, domains=domains)
            
            if result:
                print_check_result(result, args.json)
            else:
                sys.exit(1)
        
        elif args.status:
            show_status()
        
        elif args.report:
            show_report()
        
        elif args.history:
            show_history(args.days)
        
        else:
            # Default to light scan
            if not args.quiet:
                print("🚀 Running default light security scan...")
            result = run_security_scan('light')
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(result['summary'])
                if not args.quiet:
                    print(f"\n⏱️  Scan completed in {result.get('scan_duration', 0):.1f}s")
            
            # Log the scan
            if HOOKS_AVAILABLE and 'error' not in result:
                try:
                    log_security_scan(result['scan_level'], result)
                except Exception as e:
                    if not args.quiet:
                        print(f"Warning: Failed to log scan: {e}")
    
    except KeyboardInterrupt:
        if not args.quiet:
            print("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()