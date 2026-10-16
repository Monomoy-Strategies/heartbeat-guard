# HeartbeatGuard 

![HeartbeatGuard Logo](https://heartbeatguard.com/images/logo-hero.png)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenClaw Compatible](https://img.shields.io/badge/OpenClaw-2026.3.24%2B-orange.svg)](https://openclaw.com)
[![Built by Monomoy Strategies](https://img.shields.io/badge/Built%20by-Monomoy%20Strategies-red.svg)](https://monomoystrategies.com)

**Your AI Agent's Security Watchdog** 🛡️

HeartbeatGuard is a comprehensive security monitoring system designed specifically for AI agents running on OpenClaw. It provides real-time threat detection, system health monitoring, and automated security reporting to keep your AI infrastructure secure.

## 🚀 Features

HeartbeatGuard performs **35 core security checks**:

1. **💻 System Health Monitoring** - CPU, memory, disk, and load tracking
2. **🔥 Firewall Status Monitoring** - Real-time firewall rule analysis and breach detection
3. **🔍 Port Scanning & Analysis** - Monitors open ports and detects unauthorized services  
4. **🔐 SSL Certificate Health** - Tracks certificate expiration and validation
5. **🚨 Failed Login Detection** - Identifies brute force attacks and suspicious login attempts
6. **⚡ Process Monitoring** - Detects suspicious and unauthorized processes
7. **📁 File Integrity Checking** - Monitors critical files for unauthorized changes
8. **🔑 Credential Rotation Tracking** - Ensures security credentials are properly rotated
9. **🛡️ CVE & Vulnerability Scanning** - Checks for known vulnerabilities and security patches
10. **📊 Anomaly Detection** - AI-powered behavioral analysis for threat identification
11. **🔍 Skill Code Safety Scanning** - Monitors OpenClaw skills for malicious code patterns
12. **🧾 Sysmon / Audit Log Review** - Detects suspicious process and file events
13. **🧯 Command Audit** - Scans OpenClaw exec logs for risky commands
14. **🌐 Outbound Connection Monitoring** - Flags unexpected external connections
15. **🛡️ Tamper Detection** - Hashes HeartbeatGuard/OpenClaw files for drift

### 🆕 OpenClaw 2026.2.22 Security Checks (v1.2.0+)

16. **🔀 PATH Binary Shadowing** — Detects `safeBins` entries without `safeBinTrustedDirs`, enabling PATH-hijack attacks (HIGH)
17. **⚠️ Dangerous Config Flags** — Detects `dangerouslyDisableDeviceAuth=true` and other dangerous gateway flags (CRITICAL)
18. **🔓 Insecure ws:// Remote Connections** — Flags non-loopback unencrypted WebSocket gateway remotes (HIGH)
19. **👥 Open Group Policies** — Detects groups with exec/filesystem tools enabled but no sandbox restrictions (HIGH)
20. **🔢 OpenClaw Version Gate** — Flags installs below 2026.2.22 due to unpatched exec env injection, shell bypass, and symlink escape vulnerabilities (MEDIUM)
21. **🔑 Credential Leakage in Config** — Warns when pre-2026.2.22 debug serialization may expose API keys in logs (MEDIUM)
22. **⚡ IPv4/IPv6 Rate Limit Bypass** — Flags dual-stack gateway configs on pre-2026.2.22 installs vulnerable to rate limit evasion (MEDIUM)

### 🆕 OpenClaw 2026.2.23 Security Checks (v1.3.0+)

23. **🚫 SSRF Legacy Key Detection** — Detects stale `browser.ssrfPolicy.allowPrivateNetwork: true` (renamed to `dangerouslyAllowPrivateNetwork` in 2026.2.23); users who haven't run `openclaw doctor --fix` have silently broken SSRF protection (CRITICAL)
24. **🔒 HSTS Missing for Public Gateway** — Flags public-facing HTTPS gateways where `gateway.http.securityHeaders.strictTransportSecurity` is not configured; new optional hardening added in 2026.2.23 (MEDIUM)
25. **🔢 OpenClaw 2026.2.23 Version Gate** — Flags installs below 2026.2.23 for the SSRF policy default change and the config snapshot redaction bypass (env.*/skills.env.* keys exposed in pre-2026.2.23 debug logs) (MEDIUM)

### 🆕 OpenClaw 2026.2.26 Security Checks (v1.4.0+)

26. **📡 Telegram 401 Retry Risk** — Detects unpatched OpenClaw installs with Telegram channels vulnerable to unbounded 401 retries that trigger bot deletion (CRITICAL)
27. **🔄 Gateway Restart Loop Detector** — Parses logs for crash-loop patterns (>2 restarts in 10 min window) (HIGH)

### 🆕 OpenClaw 2026.3.2 Security Checks (v1.5.0+)

28. **✅ Config Validate** — Runs `openclaw config validate --json` and surfaces errors/warnings before gateway failures (CRITICAL)
29. **🔐 SecretRef Audit** — Audits all 64 SecretRef targets; flags unresolved refs on active surfaces (CRITICAL)

### 🆕 OpenClaw 2026.3.23 + 2026.3.24 Security Checks (v1.6.0+)

30. **📦 Media Sandbox Escape Detection** — Detects the mediaUrl/fileUrl alias bypass (CVE patched in 2026.3.24 #54034) that allows outbound actions to read files outside media root. Scans plugins for bypass patterns. (CRITICAL)
31. **🔒 CSP Integrity Verification** — Verifies gateway Control UI has SHA-256 inline script hashes (added in 2026.3.23). Without CSP hash-pinning, injected scripts execute freely. (HIGH)
32. **🆔 Channel ID Injection Detection** — Scans for prototype pollution (__proto__), control characters, and path traversal in channel IDs. Hardened in 2026.3.23. (CRITICAL)
33. **⏱️ Long-Running Session Monitor** — Detects agent sessions exceeding configurable thresholds (>6h WARN, >12h HIGH, >24h CRITICAL). OpenClaw 2026.3.24 raised default timeout from 600s to 48h. (CRITICAL)
34. **🗂️ Cache-Trace Credential Audit** — Scans JSONL cache-trace files for plaintext API keys/tokens leaked by pre-2026.3.23 installs. (CRITICAL)
35. **🔗 ClawHub Supply Chain Monitor** — Audits installed plugins for source verification, file integrity, and stale plugins.allow entries. ClawHub became the default source in 2026.3.23. (HIGH)

## 📦 Installation

### Quick Install (Recommended)

```bash
pip install heartbeat-guard
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/Monomoy-Strategies/heartbeat-guard.git
cd heartbeat-guard
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

## 🔧 Quick Start

### Command Line Interface

```bash
# Quick security scan (suitable for heartbeats)
heartbeat-guard --light

# Full comprehensive scan
heartbeat-guard --full

# Check specific security areas
heartbeat-guard --check firewall
heartbeat-guard --check ports
heartbeat-guard --check ssl
heartbeat-guard --check logins
heartbeat-guard --check creds
heartbeat-guard --check sysmon
heartbeat-guard --check audit
heartbeat-guard --check outbound
heartbeat-guard --check tamper

# New in v1.6.0 — OpenClaw 2026.3.23/3.24 checks
heartbeat-guard --check media-sandbox
heartbeat-guard --check csp
heartbeat-guard --check channel-ids
heartbeat-guard --check long-sessions
heartbeat-guard --check cache-trace
heartbeat-guard --check supply-chain

# Show current security status
heartbeat-guard --status

# Generate detailed security report
heartbeat-guard --report
```

### Python API

```python
from heartbeat_guard import HeartbeatGuard, run_security_scan

# Initialize HeartbeatGuard
guard = HeartbeatGuard()

# Run a quick security scan
results = run_security_scan(light_mode=True)

# Print security status
for check, status in results.items():
    print(f"{check}: {'✅ PASS' if status['status'] == 'ok' else '❌ FAIL'}")
    
# Run skill code scanning
from heartbeat_guard import SkillScanner
scanner = SkillScanner()
scan_results = scanner.scan_all_skills()
```

## ⚙️ Configuration

HeartbeatGuard uses a simple JSON configuration system:

```json
{
  "monitoring": {
    "enabled_checks": ["firewall", "ports", "ssl", "logins", "processes"],
    "scan_interval": 300,
    "alert_threshold": "medium"
  },
  "notifications": {
    "telegram_enabled": true,
    "email_enabled": false
  },
  "skill_scanner": {
    "scan_directories": ["~/.openclaw/skills", "/opt/openclaw/skills"],
    "malware_patterns": ["eval(", "exec(", "__import__"],
    "whitelist_files": []
  }
}
```

Configuration file location: `~/clawd/data/heartbeat-guard-config.json`

## 📋 OpenClaw Version Compatibility

| OpenClaw Version | HeartbeatGuard Support | Notes |
|-----------------|----------------------|-------|
| **2026.3.24+** | ✅ Full (all 35 checks) | **Recommended** — Media sandbox fix, 48h timeout, gateway restart sentinel |
| **2026.3.23** | ✅ Full (34 checks) | CSP hardening, channel ID validation, ClawHub-first, cache-trace redaction |
| **2026.3.2** | ✅ Good (29 checks) | Config validate, SecretRef audit |
| **2026.2.26** | ✅ Good (27 checks) | Telegram 401 fix, restart loop fix |
| **2026.2.23** | ⚠️ Partial (25 checks) | SSRF key migration, config snapshot redaction |
| **2026.2.22** | ⚠️ Partial (22 checks) | Exec env injection, shell bypass patches |
| < 2026.2.22 | ❌ Limited (15 checks) | Multiple unpatched vulnerabilities — update immediately |

> **⚠️ Recommendation:** Run OpenClaw **2026.3.24 or later**. This version closes the media sandbox escape (CVE #54034), includes CSP hardening, and channel ID injection protection. Pre-2026.3.23 installs are actively leaking credentials to cache-trace files.

## 🤖 Built for OpenClaw

HeartbeatGuard was designed from the ground up for OpenClaw AI agents:

- **Heartbeat Integration**: Lightweight scans perfect for periodic heartbeat checks
- **Agent-Aware**: Understands OpenClaw's file structure and security model
- **Skill Monitoring**: Specialized scanning for OpenClaw skill packages
- **Minimal Overhead**: Optimized for continuous monitoring without impacting agent performance

### Integration with OpenClaw Heartbeats

Add to your `HEARTBEAT.md`:

```markdown
## Security Monitoring
- Run HeartbeatGuard light scan every 4 heartbeats
- Check for critical alerts in `~/clawd/data/heartbeat-guard-state.json`
- Alert immediately if any HIGH severity issues found
```

## 📊 Security Dashboard

HeartbeatGuard maintains a real-time security state file at:
`~/clawd/data/heartbeat-guard-state.json`

This can be integrated with your monitoring dashboards or automation systems.

## 🛡️ Security Reports

Generate comprehensive security reports:

```bash
# Daily security summary
heartbeat-guard --report --daily

# Weekly trend analysis  
heartbeat-guard --report --weekly

# Export to JSON for automation
heartbeat-guard --report --json > security-report.json
```

## 🔍 Skill Code Safety

HeartbeatGuard includes specialized scanning for OpenClaw skills:

```bash
# Scan all installed skills
heartbeat-guard --scan-skills

# Scan specific skill directory
heartbeat-guard --scan-skills --path /path/to/skill

# Check for malicious patterns
heartbeat-guard --skill-security-audit
```

## 📚 Documentation

- **Website**: [https://heartbeatguard.com](https://heartbeatguard.com)
- **Documentation**: [https://heartbeatguard.com/docs](https://heartbeatguard.com/docs)
- **API Reference**: [https://heartbeatguard.com/api](https://heartbeatguard.com/api)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏢 About Monomoy Strategies

HeartbeatGuard is developed and maintained by [Monomoy Strategies](https://monomoystrategies.com), specialists in AI infrastructure and security solutions.

For enterprise support and custom implementations, contact us at bsifflard@monomoystrategies.com

---

**Keep your AI agents secure with HeartbeatGuard** 🛡️✨