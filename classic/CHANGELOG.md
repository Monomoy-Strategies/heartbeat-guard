# Changelog

All notable changes to HeartbeatGuard are documented in this file.

## [1.6.0] - 2026-03-26

### Added — 6 new security checks for OpenClaw 2026.3.23 + 2026.3.24

#### `check_media_sandbox_verify()` — CRITICAL · Light + Full scan
Detects the mediaUrl/fileUrl alias bypass (CVE patched in OpenClaw 2026.3.24 #54034) that
allowed outbound tool and message actions to escape media-root restrictions. Checks OpenClaw
version, audits workspaceOnly/mediaRoot policy, and scans installed plugins for bypass patterns.
Flagged as CRITICAL on pre-2026.3.24 installs.

#### `check_csp_integrity()` — HIGH · Full scan only
Verifies the gateway's Content Security Policy includes SHA-256 hashed inline scripts,
as introduced in OpenClaw 2026.3.23. Checks index.html for CSP meta tags and verifies
live gateway headers. Without CSP hash-pinning, injected inline scripts execute freely
in the Control UI.

#### `check_channel_id_injection()` — CRITICAL · Light + Full scan
Scans OpenClaw config for channel IDs containing control characters, prototype pollution
patterns (__proto__, constructor), path traversal sequences, or excessive length. These
patterns can bypass auth, corrupt JavaScript runtime state, or inject data into audit paths.
Hardened in OpenClaw 2026.3.23.

#### `check_long_session_monitor()` — CRITICAL · Light + Full scan
Monitors for agent sessions running beyond configurable thresholds (default: >6h WARN,
>12h HIGH, >24h CRITICAL). OpenClaw 2026.3.24 raised the default agent timeout from
600s to 48 hours — compromised agents now have a much larger persistence window.
Also checks process table for long-running openclaw processes.

#### `check_cache_trace_audit()` — CRITICAL · Full scan only
Scans cache-trace JSONL files for leaked credentials from pre-2026.3.23 OpenClaw installs.
The 2026.3.23 release strips credential fields from trace output, but existing files may
still contain plaintext API keys and tokens. Checks file permissions and scans for known
credential patterns.

#### `check_clawhub_supply_chain()` — HIGH · Full scan only
Monitors the supply chain trust boundary introduced when OpenClaw 2026.3.23 made ClawHub
the default plugin source. Audits installed plugins for source verification, file integrity
(hash checks against install manifest), unknown origins, and stale plugins.allow entries.

### Changed
- Total check count updated from **29 → 35**
- `__version__` bumped to `1.6.0`
- Light scan adds 3 new checks: media sandbox, channel ID injection, long session monitor
- Full scan adds all 6 new checks
- CLI `--check` supports: `media-sandbox`, `csp`, `channel-ids`, `long-sessions`, `cache-trace`, `supply-chain`
- hbg-scan: 3 new threat signatures (SIG-006 media sandbox, SIG-007 before_dispatch hook, SIG-008 prototype pollution)
- hbg-scan: New CHECK-5b (Hook & Dispatch Interception) detection category
- hbg-scan signatures.json updated to v1.1.0

### Compatibility
- Optimized for OpenClaw 2026.3.23 and 2026.3.24
- All checks gracefully handle older installs (version-aware, no false positives)
- Version matrix: full support on 2026.3.24+, partial on 2026.3.23+, basic on 2026.3.2+

---

## [1.5.0] - 2026-03-03

### Added
- `config_validate`: Runs `openclaw config validate --json` (new in OpenClaw 2026.3.2) and surfaces config errors/warnings before they cause gateway failures. CRITICAL for errors, MEDIUM for warnings.
- `secret_ref_audit`: Audits all SecretRef usage in OpenClaw config. Flags unresolved refs on active surfaces as CRITICAL. Covers all 64 credential targets expanded in OpenClaw 2026.3.2.

### Compatibility
- Optimized for OpenClaw 2026.3.2+
- Both checks gracefully handle pre-2026.3.2 installs (returns INFO, not false positives)

### Changed
- Total check count updated from **27 → 29**
- `__version__` bumped to `1.5.0`
- Both new checks run in **light AND full** scan modes (catch issues early)

---

## [1.4.0] — 2026-02-27

### Added — 2 new security checks for OpenClaw 2026.2.26

#### `check_telegram_401_retry_risk()` — CRITICAL · Light + Full scan
Detects OpenClaw installs below 2026.2.26 that have a Telegram channel configured.
OpenClaw 2026.2.26 fixed unbounded 401 retries on Telegram's `sendChatAction` endpoint.
On unpatched versions, every failed call retries without back-off, which triggers
Telegram's abuse enforcement and results in **permanent bot deletion**. Flagged as
CRITICAL when version < 2026.2.26 AND a Telegram channel is present in config.

#### `check_gateway_restart_loop()` — HIGH · Light + Full scan
Parses OpenClaw log files for gateway start/restart events within a 10-minute sliding
window. Three or more restarts in that window is a strong indicator of a crash loop
that can cause full service outage. Returns HIGH with restart count when threshold is
exceeded, INFO if log files are not found, and PASS if 0-2 restarts detected.

### Changed
- Total check count updated from **25 → 27**
- `__version__` bumped to `1.4.0`
- Both new checks run in **light AND full** scan modes (immediate detection is critical)

---

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
