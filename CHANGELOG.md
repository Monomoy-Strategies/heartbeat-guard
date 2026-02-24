# Changelog

All notable changes to HeartbeatGuard are documented in this file.

## [1.3.0] — 2026-02-24

### Added — 3 new security checks for OpenClaw 2026.2.23

#### `check_ssrf_legacy_key()` — CRITICAL · Light + Full scan
Detects stale `browser.ssrfPolicy.allowPrivateNetwork: true` in OpenClaw config files.
This key was **renamed** to `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` in
OpenClaw 2026.2.23. Users who have not run `openclaw doctor --fix` after upgrading will
still have the old key in their config — the runtime silently ignores it, meaning SSRF
private-network access controls are NOT enforced even though the config appears to
enable them. Flagged as CRITICAL when the legacy key is `true`.

#### `check_hsts_missing_for_public_gateway()` — MEDIUM · Full scan only
Checks whether public-facing HTTPS gateways have
`gateway.http.securityHeaders.strictTransportSecurity` configured. HSTS is a new
optional hardening header introduced in OpenClaw 2026.2.23 that prevents browsers and
HTTP clients from downgrading TLS connections to plain HTTP. Loopback/private bind
addresses are exempt. Flags MEDIUM when a public HTTPS gateway has no HSTS value.

#### `check_openclaw_version_gate_223()` — MEDIUM · Light + Full scan
Bumps the version gate to 2026.2.23. Flags installs below this release for two issues:

1. **SSRF policy default change** — `browser.ssrfPolicy.allowPrivateNetwork` renamed;
   SSRF protection silently inactive on unpatched installs.
2. **Config snapshot redaction bypass** — `env.*` and `skills.env.*` config keys
   (API keys, tokens, secrets) exposed in plaintext in debug logs and config snapshots
   on pre-2026.2.23 installs.

### Changed
- Total check count updated from **22 → 25**
- `__version__` bumped to `1.3.0`
- README compatibility table updated; recommended minimum is now OpenClaw 2026.2.23+
- OpenClaw badge updated to `2026.2.23+`

---

## [1.2.0] — 2026-02-22

### Added — 7 new security checks for OpenClaw 2026.2.22

- `check_path_binary_shadowing()` — HIGH: Detects safeBins without safeBinTrustedDirs
- `check_dangerous_config_flags()` — CRITICAL: Detects dangerouslyDisableDeviceAuth=true
- `check_insecure_ws_connections()` — HIGH: Flags non-loopback ws:// gateway remotes
- `check_open_group_policies()` — HIGH: Groups with exec/fs tools and no sandbox
- `check_openclaw_version_gate()` — MEDIUM: Flags installs below 2026.2.22
- `check_command_audit()` — Audits OpenClaw exec logs for suspicious commands
- `check_outbound_connections()` — Monitors unexpected external connections

### Changed
- Total check count updated from 15 → 22
- Windows Firewall and Sysmon support improved

---

## [1.1.0] — 2026-02-09

### Added
- Initial release with 15 core security checks
- System health, firewall, ports, SSL, failed logins, process monitoring
- File integrity, credential rotation, CVE updates, anomaly detection
- Skill code safety scanning, Sysmon/audit log review, tamper detection

---

*HeartbeatGuard is developed by [Monomoy Strategies](https://monomoystrategies.com)*
