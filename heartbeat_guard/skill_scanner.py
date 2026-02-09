#!/usr/bin/env python3
"""
HeartbeatGuard Skill Code Safety Scanner
========================================

Monitors locally installed OpenClaw skills for malicious patterns, 
integrity violations, and security issues.

Copyright (c) 2026 Monomoy Strategies LLC
Version: 1.0.0
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set


class SkillScanner:
    """Main skill security scanner class."""
    
    def __init__(self, custom_dirs=None):
        # Default OpenClaw skill directories
        self.skill_dirs = custom_dirs or [
            Path.home() / ".npm-global" / "lib" / "node_modules" / "openclaw" / "skills",
            Path.home() / ".openclaw" / "skills",
            Path("/opt/openclaw/skills"),
            Path("/usr/local/openclaw/skills")
        ]
        self.data_dir = Path.home() / ".heartbeat-guard" / "data"
        self.hashes_file = self.data_dir / "skill-hashes.json"
        self.whitelist_file = self.data_dir / "skill-whitelist.json"
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Suspicious patterns for different file types
        self.js_patterns = {
            'network_calls': [
                r'fetch\s*\(',
                r'XMLHttpRequest',
                r'axios\.',
                r'\.get\s*\(',
                r'\.post\s*\(',
                r'http\.request',
                r'https\.request',
            ],
            'credential_harvesting': [
                r'process\.env\.',
                r'\.env',
                r'getenv\s*\(',
                r'process\.env\[',
                r'fs\.readFileSync.*\.env',
                r'fs\.readFile.*\.env',
            ],
            'file_access': [
                r'\.ssh/',
                r'/etc/passwd',
                r'/etc/shadow',
                r'\.config/',
                r'wallet\.',
                r'\.wallet',
                r'fs\.readFileSync',
                r'fs\.readFile',
                r'fs\.writeFile',
            ],
            'obfuscation': [
                r'atob\s*\(',
                r'btoa\s*\(',
                r'Buffer\.from.*base64',
                r'\.toString\s*\(\s*[\'"]base64[\'"]',
            ],
            'exec_patterns': [
                r'eval\s*\(',
                r'Function\s*\(',
                r'exec\s*\(',
                r'spawn\s*\(',
                r'child_process',
            ]
        }
        
        self.python_patterns = {
            'network_calls': [
                r'requests\.',
                r'urllib\.',
                r'http\.client',
                r'httplib',
                r'socket\.',
            ],
            'credential_harvesting': [
                r'os\.environ',
                r'getenv\s*\(',
                r'\.env',
                r'configparser',
                r'open.*\.env',
            ],
            'file_access': [
                r'\.ssh/',
                r'/etc/passwd',
                r'/etc/shadow',
                r'\.config/',
                r'wallet\.',
                r'\.wallet',
                r'open\s*\(',
                r'pathlib',
            ],
            'obfuscation': [
                r'base64\.',
                r'codecs\.',
                r'decode.*base64',
                r'encode.*base64',
            ],
            'exec_patterns': [
                r'eval\s*\(',
                r'exec\s*\(',
                r'subprocess\.',
                r'os\.system',
                r'os\.popen',
                r'shell\s*=\s*True',
            ]
        }
        
        self.shell_patterns = {
            'network_calls': [
                r'curl\s+',
                r'wget\s+',
                r'nc\s+',
                r'netcat\s+',
            ],
            'credential_harvesting': [
                r'\$\w*[Pp][Aa][Ss][Ss]\w*',
                r'\$\w*[Tt][Oo][Kk][Ee][Nn]\w*',
                r'\$\w*[Kk][Ee][Yy]\w*',
                r'\.env',
            ],
            'file_access': [
                r'\.ssh/',
                r'/etc/passwd',
                r'/etc/shadow',
                r'\.config/',
                r'wallet\.',
                r'\.wallet',
            ],
            'exec_patterns': [
                r'\|\s*sh',
                r'\|\s*bash',
                r'eval\s+',
                r'`.*`',
                r'\$\(',
            ]
        }
        
        # Crypto wallet patterns
        self.wallet_patterns = [
            r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',  # Bitcoin
            r'0x[a-fA-F0-9]{40}',                # Ethereum
            r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}', # Litecoin
        ]
        
        # Known malicious packages/imports
        self.malicious_patterns = [
            r'colorama',
            r'discord\.py',
            r'python-bitcoinlib',
            r'web3',
            r'bitcoinlib',
            r'cryptostealer',
        ]
        
        # Load whitelist
        self.whitelist = self._load_whitelist()
    
    def _load_whitelist(self) -> Dict:
        """Load skill whitelist configuration."""
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def _get_all_skills(self) -> List[Path]:
        """Get list of all installed skills."""
        skills = []
        for skill_dir in self.skill_dirs:
            if skill_dir.exists():
                for item in skill_dir.iterdir():
                    if item.is_dir() and not item.name.startswith('.'):
                        skills.append(item)
        return sorted(skills)
    
    def _scan_file_content(self, file_path: Path, skill_name: str) -> Dict:
        """Scan individual file for suspicious patterns."""
        findings = {
            'network_calls': [],
            'credential_harvesting': [],
            'file_access': [],
            'obfuscation': [],
            'exec_patterns': [],
            'wallet_addresses': [],
            'malicious_imports': []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return findings
        
        # Determine file type and patterns to use
        suffix = file_path.suffix.lower()
        if suffix == '.js':
            patterns = self.js_patterns
        elif suffix == '.py':
            patterns = self.python_patterns
        elif suffix in ['.sh', '.bash']:
            patterns = self.shell_patterns
        else:
            return findings
        
        # Check for suspicious patterns
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    finding = {
                        'pattern': pattern,
                        'match': match.group(),
                        'line': line_num,
                        'file': str(file_path)
                    }
                    findings[category].append(finding)
        
        # Check for wallet addresses
        for pattern in self.wallet_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                finding = {
                    'address': match.group(),
                    'line': line_num,
                    'file': str(file_path)
                }
                findings['wallet_addresses'].append(finding)
        
        # Check for malicious imports/packages
        for pattern in self.malicious_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                finding = {
                    'import': match.group(),
                    'line': line_num,
                    'file': str(file_path)
                }
                findings['malicious_imports'].append(finding)
        
        return findings
    
    def _get_file_permissions(self, file_path: Path) -> str:
        """Get file permissions as octal string."""
        try:
            mode = file_path.stat().st_mode
            return oct(stat.S_IMODE(mode))
        except Exception:
            return "unknown"
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def _scan_skill_directory(self, skill_path: Path) -> Dict:
        """Scan a single skill directory."""
        skill_name = skill_path.name
        result = {
            'name': skill_name,
            'path': str(skill_path),
            'files': [],
            'findings': {
                'network_calls': [],
                'credential_harvesting': [],
                'file_access': [],
                'obfuscation': [],
                'exec_patterns': [],
                'wallet_addresses': [],
                'malicious_imports': []
            },
            'total_size': 0,
            'file_count': 0,
            'permissions_issues': []
        }
        
        # Recursively scan all files
        for root, dirs, files in os.walk(skill_path):
            for file_name in files:
                file_path = Path(root) / file_name
                file_size = file_path.stat().st_size if file_path.exists() else 0
                permissions = self._get_file_permissions(file_path)
                file_hash = self._calculate_file_hash(file_path)
                
                file_info = {
                    'name': file_name,
                    'path': str(file_path),
                    'size': file_size,
                    'permissions': permissions,
                    'hash': file_hash
                }
                
                result['files'].append(file_info)
                result['total_size'] += file_size
                result['file_count'] += 1
                
                # Check for overly permissive files
                if permissions.endswith('77') or permissions.endswith('66'):
                    result['permissions_issues'].append({
                        'file': str(file_path),
                        'permissions': permissions,
                        'issue': 'overly_permissive'
                    })
                
                # Scan file content for suspicious patterns
                if file_path.suffix.lower() in ['.js', '.py', '.sh', '.bash', '.md']:
                    file_findings = self._scan_file_content(file_path, skill_name)
                    
                    # Merge findings
                    for category, findings_list in file_findings.items():
                        result['findings'][category].extend(findings_list)
        
        return result
    
    def _apply_whitelist_filters(self, skill_data: Dict) -> None:
        """Apply whitelist filters to remove known-good patterns."""
        skill_name = skill_data['name']
        if skill_name not in self.whitelist:
            return
        
        whitelist_config = self.whitelist[skill_name]
        findings = skill_data['findings']
        
        # Filter network calls by allowed domains
        if 'allowed_domains' in whitelist_config:
            allowed_domains = whitelist_config['allowed_domains']
            filtered_calls = []
            for call in findings['network_calls']:
                is_whitelisted = any(domain in call['match'] for domain in allowed_domains)
                if not is_whitelisted:
                    filtered_calls.append(call)
            findings['network_calls'] = filtered_calls
        
        # Filter environment variables
        if 'allowed_env_vars' in whitelist_config:
            allowed_vars = whitelist_config['allowed_env_vars']
            if '*' in allowed_vars:
                findings['credential_harvesting'] = []
            else:
                filtered_creds = []
                for cred in findings['credential_harvesting']:
                    is_whitelisted = any(var in cred['match'] for var in allowed_vars)
                    if not is_whitelisted:
                        filtered_creds.append(cred)
                findings['credential_harvesting'] = filtered_creds
    
    def _calculate_risk_score(self, skill_data: Dict) -> int:
        """Calculate risk score (0-100) based on findings."""
        score = 0
        findings = skill_data['findings']
        
        # Weight different types of findings
        weights = {
            'malicious_imports': 40,
            'wallet_addresses': 35,
            'credential_harvesting': 25,
            'exec_patterns': 20,
            'obfuscation': 15,
            'file_access': 10,
            'network_calls': 5
        }
        
        for category, weight in weights.items():
            finding_count = len(findings[category])
            if finding_count > 0:
                # Logarithmic scaling to prevent single category domination
                category_score = min(weight * (1 + finding_count * 0.3), weight * 2)
                score += category_score
        
        # Add points for permission issues
        score += len(skill_data['permissions_issues']) * 5
        
        return min(int(score), 100)
    
    def _get_verdict(self, risk_score: int) -> str:
        """Get verdict based on risk score."""
        if risk_score >= 75:
            return "🚫 MALICIOUS"
        elif risk_score >= 50:
            return "⚠️ SUSPICIOUS"
        else:
            return "✅ CLEAN"
    
    def scan_all_skills(self, specific_skill: Optional[str] = None) -> Dict:
        """Scan all skills or a specific skill."""
        skills = self._get_all_skills()
        
        if specific_skill:
            skills = [s for s in skills if s.name == specific_skill]
            if not skills:
                return {'error': f'Skill "{specific_skill}" not found'}
        
        results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'skills_scanned': len(skills),
            'skills': {}
        }
        
        for skill_path in skills:
            skill_data = self._scan_skill_directory(skill_path)
            self._apply_whitelist_filters(skill_data)
            
            risk_score = self._calculate_risk_score(skill_data)
            verdict = self._get_verdict(risk_score)
            
            skill_data['risk_score'] = risk_score
            skill_data['verdict'] = verdict
            
            results['skills'][skill_path.name] = skill_data
        
        return results
    
    def generate_baseline(self) -> Dict:
        """Generate integrity baseline of all skill files."""
        skills = self._get_all_skills()
        baseline = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'skills': {}
        }
        
        for skill_path in skills:
            skill_hashes = {}
            for root, dirs, files in os.walk(skill_path):
                for file_name in files:
                    file_path = Path(root) / file_name
                    relative_path = file_path.relative_to(skill_path)
                    file_hash = self._calculate_file_hash(file_path)
                    skill_hashes[str(relative_path)] = file_hash
            
            baseline['skills'][skill_path.name] = skill_hashes
        
        # Save baseline
        with open(self.hashes_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        return baseline
    
    def check_integrity(self) -> Dict:
        """Check file integrity against baseline."""
        if not self.hashes_file.exists():
            return {'error': 'No baseline found. Run --baseline first.'}
        
        try:
            with open(self.hashes_file, 'r') as f:
                baseline = json.load(f)
        except json.JSONDecodeError:
            return {'error': 'Corrupted baseline file'}
        
        skills = self._get_all_skills()
        current_time = datetime.now(timezone.utc).isoformat()
        
        integrity_report = {
            'timestamp': current_time,
            'baseline_timestamp': baseline.get('timestamp', 'unknown'),
            'changes': {
                'modified': [],
                'added': [],
                'removed': []
            },
            'stats': {
                'files_checked': 0,
                'files_changed': 0,
                'files_added': 0,
                'files_removed': 0
            }
        }
        
        # Check each skill
        for skill_path in skills:
            skill_name = skill_path.name
            baseline_hashes = baseline['skills'].get(skill_name, {})
            current_hashes = {}
            
            # Get current hashes
            for root, dirs, files in os.walk(skill_path):
                for file_name in files:
                    file_path = Path(root) / file_name
                    relative_path = file_path.relative_to(skill_path)
                    file_hash = self._calculate_file_hash(file_path)
                    current_hashes[str(relative_path)] = file_hash
            
            # Compare with baseline
            all_files = set(baseline_hashes.keys()) | set(current_hashes.keys())
            
            for file_path in all_files:
                integrity_report['stats']['files_checked'] += 1
                
                if file_path in baseline_hashes and file_path in current_hashes:
                    # File exists in both - check if modified
                    if baseline_hashes[file_path] != current_hashes[file_path]:
                        integrity_report['changes']['modified'].append({
                            'skill': skill_name,
                            'file': file_path,
                            'old_hash': baseline_hashes[file_path],
                            'new_hash': current_hashes[file_path]
                        })
                        integrity_report['stats']['files_changed'] += 1
                
                elif file_path not in baseline_hashes:
                    # New file
                    integrity_report['changes']['added'].append({
                        'skill': skill_name,
                        'file': file_path,
                        'hash': current_hashes[file_path]
                    })
                    integrity_report['stats']['files_added'] += 1
                
                elif file_path not in current_hashes:
                    # Removed file
                    integrity_report['changes']['removed'].append({
                        'skill': skill_name,
                        'file': file_path,
                        'hash': baseline_hashes[file_path]
                    })
                    integrity_report['stats']['files_removed'] += 1
        
        return integrity_report
    
    def format_scan_report(self, scan_results: Dict) -> str:
        """Format scan results into human-readable report."""
        if 'error' in scan_results:
            return f"❌ Error: {scan_results['error']}"
        
        timestamp = scan_results['timestamp']
        skills = scan_results['skills']
        
        # Count verdicts
        clean_count = sum(1 for s in skills.values() if "CLEAN" in s['verdict'])
        suspicious_count = sum(1 for s in skills.values() if "SUSPICIOUS" in s['verdict'])
        malicious_count = sum(1 for s in skills.values() if "MALICIOUS" in s['verdict'])
        
        report = [
            "🛡️ SKILL SAFETY SCAN — " + timestamp.split('T')[0] + " " + timestamp.split('T')[1][:5] + " UTC",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"Skills scanned: {len(skills)}",
            f"✅ Clean: {clean_count} | ⚠️ Suspicious: {suspicious_count} | 🚫 Malicious: {malicious_count}",
            ""
        ]
        
        # List each skill
        for skill_name, skill_data in skills.items():
            verdict = skill_data['verdict']
            score = skill_data['risk_score']
            report.append(f"📦 {skill_name} — {verdict} (score: {score}/100)")
            
            # Show key findings
            findings = skill_data['findings']
            for category, findings_list in findings.items():
                if findings_list and category in ['network_calls', 'credential_harvesting', 'malicious_imports']:
                    for finding in findings_list[:2]:  # Show first 2
                        if category == 'network_calls':
                            report.append(f"  → Outbound API calls to {finding['match']}")
                        elif category == 'credential_harvesting':
                            report.append(f"  → Reads environment variable {finding['match']}")
                        elif category == 'malicious_imports':
                            report.append(f"  → Suspicious import: {finding['import']}")
        
        return '\n'.join(report)
    
    def format_integrity_report(self, integrity_results: Dict) -> str:
        """Format integrity check results."""
        if 'error' in integrity_results:
            return f"❌ Error: {integrity_results['error']}"
        
        stats = integrity_results['stats']
        changes = integrity_results['changes']
        
        report = [
            f"Integrity: {stats['files_checked']} files checked, "
            f"{stats['files_changed']} changed, "
            f"{stats['files_added']} new, "
            f"{stats['files_removed']} removed"
        ]
        
        if stats['files_changed'] > 0:
            report.append(f"\n⚠️ Modified files ({stats['files_changed']}):")
            for change in changes['modified'][:5]:  # Show first 5
                report.append(f"  → {change['skill']}/{change['file']}")
        
        if stats['files_added'] > 0:
            report.append(f"\n➕ New files ({stats['files_added']}):")
            for change in changes['added'][:5]:  # Show first 5
                report.append(f"  → {change['skill']}/{change['file']}")
        
        if stats['files_removed'] > 0:
            report.append(f"\n➖ Removed files ({stats['files_removed']}):")
            for change in changes['removed'][:5]:  # Show first 5
                report.append(f"  → {change['skill']}/{change['file']}")
        
        return '\n'.join(report)
    
    def write_alert_if_malicious(self, scan_results: Dict) -> None:
        """Write alert file if malicious skills found."""
        if 'error' in scan_results:
            return
        
        malicious_skills = []
        for skill_name, skill_data in scan_results['skills'].items():
            if "MALICIOUS" in skill_data['verdict']:
                malicious_skills.append({
                    'name': skill_name,
                    'score': skill_data['risk_score'],
                    'findings': skill_data['findings']
                })
        
        if malicious_skills:
            alert_file = Path('/tmp/heartbeat-guard-alert.txt')
            alert_content = [
                f"🚨 MALICIOUS SKILLS DETECTED - {datetime.now(timezone.utc).isoformat()}",
                f"Found {len(malicious_skills)} malicious skill(s):",
                ""
            ]
            
            for skill in malicious_skills:
                alert_content.append(f"📦 {skill['name']} (score: {skill['score']}/100)")
                findings = skill['findings']
                if findings['malicious_imports']:
                    alert_content.append(f"  → Malicious imports: {len(findings['malicious_imports'])}")
                if findings['wallet_addresses']:
                    alert_content.append(f"  → Wallet addresses: {len(findings['wallet_addresses'])}")
                if findings['credential_harvesting']:
                    alert_content.append(f"  → Credential harvesting: {len(findings['credential_harvesting'])}")
                alert_content.append("")
            
            with open(alert_file, 'w') as f:
                f.write('\n'.join(alert_content))


def check_skill_safety() -> Dict:
    """
    HeartbeatGuard integration function.
    Returns light integrity check results.
    """
    scanner = SkillScanner()
    return scanner.check_integrity()


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description='HeartbeatGuard Skill Code Safety Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 skill_scanner.py --scan                    # Full scan all skills
  python3 skill_scanner.py --scan --skill firecrawl  # Scan specific skill
  python3 skill_scanner.py --baseline                # Generate hash baseline
  python3 skill_scanner.py --integrity               # Check integrity
  python3 skill_scanner.py --light                   # Quick integrity check
  python3 skill_scanner.py --scan --json             # JSON output
        """
    )
    
    parser.add_argument('--scan', action='store_true',
                      help='Perform full security scan')
    parser.add_argument('--skill', type=str,
                      help='Scan specific skill only')
    parser.add_argument('--baseline', action='store_true',
                      help='Generate/update integrity baseline')
    parser.add_argument('--integrity', action='store_true',
                      help='Check file integrity against baseline')
    parser.add_argument('--light', action='store_true',
                      help='Quick integrity check only (for heartbeat)')
    parser.add_argument('--json', action='store_true',
                      help='Output results as JSON')
    
    args = parser.parse_args()
    
    if not any([args.scan, args.baseline, args.integrity, args.light]):
        parser.print_help()
        return 1
    
    scanner = SkillScanner()
    
    try:
        if args.baseline:
            result = scanner.generate_baseline()
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"✅ Baseline generated with {len(result['skills'])} skills")
                print(f"📁 Saved to: {scanner.hashes_file}")
        
        elif args.integrity or args.light:
            result = scanner.check_integrity()
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(scanner.format_integrity_report(result))
        
        elif args.scan:
            result = scanner.scan_all_skills(args.skill)
            
            # Write alert if malicious skills found
            scanner.write_alert_if_malicious(result)
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                report = scanner.format_scan_report(result)
                print(report)
                
                # Also show integrity if baseline exists
                if scanner.hashes_file.exists():
                    integrity_result = scanner.check_integrity()
                    print("\n" + scanner.format_integrity_report(integrity_result))
    
    except KeyboardInterrupt:
        print("\n❌ Interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())