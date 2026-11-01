# WebsiteAccessibilityMonitor: User Guide

[Русская версия](USER_GUIDE_RU.md)

## What Changed in 2.1

- Diagnostics no longer call any timeout a block. A `*_BLOCK` status is set only with an extra signal: the direct path fails while the same URL works through the configured proxy. It remains a technical hypothesis, not legal proof.
- The system DNS is compared with DoH for A and AAAA. Disjoint answers are marked `dns_anomaly` but are not treated as blocking by themselves: CDNs and geo-distributed DNS often return different addresses legitimately.
- TCP/TLS checks use the scheme and port of the original URL, try the available IPv4/IPv6 addresses and have a real async timeout.
- SOCKS4/SOCKS5 and HTTP proxies work through `proxy_url`. The direct client never uses the system proxy, which keeps the route comparison honest.
- `HEAD` falls back to `GET` on 405/501 without spending a retry. Temporary HTTP 408/425/429/500-504 are retried.
- The response body is read only up to a set limit; the number of concurrent checks is limited.
- The old `websites` list and `website_groups` work together. Invalid URLs and headers are skipped, and a damaged `config.json` is no longer overwritten.
- History keeps a day of data with regard to the interval, the log keeps subfolders, CSV has diagnostic fields, notifications check the webhook's HTTP response.
- `SiteMonitor` and `SiteMonitorLite` share one full-screen ratatui interface instead of two copies of manual drawing: sites are added and removed in the app, settings are validated while editing, and save or notification errors go to Events without breaking the screen.
- Stub detection no longer fires on ordinary pages with words like "blocked" and no longer misses a stub when the body limit cuts a UTF-8 character.
- IPv6 literal addresses (`http://[::1]:8080/`) are checked correctly, the system DNS is bound by the request timeout, and the Telegram token and webhook URLs stay out of error texts.
- Expected-text check, slow-response threshold, TLS certificate and domain registration expiry, maintenance windows.
- Permanent `--watch` background mode for systemd and the console, a Windows service and Prometheus metrics.

## What Is Checked Besides Availability

| Check | How it works | Status |
|---|---|---|
| Expected text | The response must contain a given string (case-insensitive); up to 1 MB of body is read. Set with `T` in the site list or the `expect_text` field | `CONTENT_MISMATCH`, a failure |
| Slow response | Response longer than `slow_threshold_ms` (3000 ms by default, `0` turns it off). Per site: the `slow_threshold_ms` field | `SLOW`, a warning |
| Certificate | The expiry date comes from the certificate received in a normal HTTPS request | `CERT_EXPIRING`, `cert_warn_days` before expiry (14 by default) |
| Domain | Registration expiry through RDAP (registry address from the IANA list), for zones without RDAP (`.ru`, `.рф`, `.su`) through WHOIS. Cached for 12 hours | `DOMAIN_EXPIRING`, `domain_warn_days` before expiry (30 by default) |
| Maintenance windows | During the set time checks run, but failures send no notifications and do not spoil uptime | `ОБСЛУЖИВАНИЕ` in the interface, `maintenance: true` in JSON |

Warnings (`WARN`, `SLOW`, `CERT_EXPIRING`, `DOMAIN_EXPIRING`) mean the site is available: no failure notifications are sent. All dates are visible in site details (`Enter`), the certificate date also in its own column of the Sites table.

## Headless Mode

A one-shot check for a scheduler, CI or PowerShell:

```powershell
.\target\release\website_accessibility_monitor.exe --json https://example.com https://example.net
```

Without URLs the command reads `config.json` from the current folder. The scheme is optional: `example.com` is checked as `https://example.com/`. Exit code `0` means all targets are `OK`/`WARN`, `2` means some are down, `1` is a startup error such as an invalid URL. `--config PATH` selects another config file.

On Windows `Start.bat` and `StartLite.bat` are also available. On first start `config.json` is created next to the executable.

## Background Mode, Service and Metrics

`--watch` checks sites continuously without an interface: on schedule, with notifications, uptime history, log and CSV, as in `SiteMonitor`. Changes to `config.json` are picked up without a restart. Events go to the console (or a file through `--log-file`), `--quiet` hides clean cycle summaries. Stop with `Ctrl+C` or `SIGTERM`; uptime history is saved.

```powershell
.\target\release\website_accessibility_monitor.exe --watch --config C:\WAM\config.json --metrics 127.0.0.1:9898
```

Relative paths from the settings (history, log, CSV) are resolved from the folder that holds `config.json`.

**Windows service.** From a console run as administrator:

```powershell
.\target\release\website_accessibility_monitor.exe --install-service --config C:\WAM\config.json --metrics 127.0.0.1:9898
```

The `WebsiteAccessibilityMonitor` service starts at once and then automatically with Windows. Its event log is `wam-service.log` next to `config.json` (or the `--log-file` path). Remove it with `--uninstall-service`.

**Linux (systemd).** A ready unit with install notes is [deploy/wam.service](../deploy/wam.service); read events with `journalctl -u wam -f`.

**Prometheus.** With `--metrics ADDR`, `http://ADDR/metrics` serves:

| Metric | Meaning |
|---|---|
| `wam_up` | 1 site available (OK or warning), 0 not |
| `wam_status{status="..."}` | Current diagnostic status |
| `wam_maintenance` | 1 if the check fell into a maintenance window |
| `wam_response_time_seconds` | Response time |
| `wam_http_status_code` | HTTP code |
| `wam_content_match` | 1/0, whether the expected text was found |
| `wam_cert_expiry_timestamp_seconds` | Certificate expiry (Unix time) |
| `wam_domain_expiry_timestamp_seconds` | Domain registration expiry (Unix time) |
| `wam_uptime_ratio` | Share of successful checks over 24 hours |
| `wam_checks_total{result="ok\|failed"}` | Check counter since start |
| `wam_last_check_timestamp_seconds`, `wam_last_cycle_*` | Time of the last check and cycle |

All site metrics carry `url` and `group` labels. Sample alert rules: [deploy/prometheus-alerts.yml](../deploy/prometheus-alerts.yml). `/health` answers `ok` for liveness probes. With only a port (`--metrics 9898`) it listens on `127.0.0.1`; expose the port only behind a firewall, because labels show site addresses.

## Config Format

```json
{
  "monitor_settings": {
    "interval": 60,
    "timeout": 8,
    "retries_max": 2,
    "valid_status_codes": [200, 201, 202, 204, 301, 302, 307, 308],
    "warn_status_codes": [401, 403, 407, 408, 425, 429],
    "sorted": "status",
    "ping_enabled": true,
    "uptime_enabled": true,
    "use_head_first": false,
    "proxy_url": "socks5h://127.0.0.1:1080",
    "doh_server": "https://cloudflare-dns.com/dns-query",
    "max_concurrency": 32,
    "response_body_limit_kb": 64,
    "diagnostics_enabled": true,
    "slow_threshold_ms": 3000,
    "cert_warn_days": 14,
    "domain_check_enabled": true,
    "domain_warn_days": 30
  },
  "websites": [
    "https://example.com",
    "http://example.net:8080/health",
    { "url": "https://shop.example.com", "expect_text": "Корзина", "slow_threshold_ms": 1500 }
  ],
  "website_groups": [
    {
      "name": "API",
      "interval": 30,
      "sites": [
        {
          "url": "https://api.example.com/health",
          "headers": { "Authorization": "Bearer TOKEN" }
        }
      ]
    }
  ],
  "Monitor": {
    "logging_enabled": true,
    "log_file_path": "logs/monitor.log",
    "log_max_size_mb": 10,
    "log_rotate_daily": true
  },
  "csv_export": {
    "enabled": false,
    "file_path": "results.csv"
  },
  "webhooks": {
    "enabled": false,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "discord_webhook_url": "",
    "slack_webhook_url": "",
    "notify_on_down": true,
    "notify_on_recovery": true,
    "min_failures_before_alert": 3
  },
  "uptime_history_path": "uptime_history.json",
  "maintenance_windows": [
    { "name": "Ночные бэкапы", "days": ["пн", "ср", "пт"], "start": "02:00", "end": "02:30" },
    { "name": "Релиз API", "start": "23:30", "end": "00:30", "targets": ["api.example.com", "API"] }
  ]
}
```

A site in `websites` and in group `sites` is a string or an object with `url`, `headers`, `expect_text` and `slow_threshold_ms`. Sites without extra fields are saved back as strings.

In a maintenance window `days` are weekdays (`mon`..`sun` or `пн`..`вс`, empty means every day), `start`/`end` are local `HH:MM`; a window across midnight belongs to its starting day. `targets` are parts of an address or a group name, empty means all sites.

Leave `proxy_url` empty if you do not need a control route. For SOCKS with name resolution on the proxy side use the `socks5h://` scheme, which matters most when local DNS is unavailable or rewritten. Credentials go into the URL, for example `socks5h://user:password@127.0.0.1:1080`. Secrets in headers and webhook settings are stored in plain JSON: restrict access to the file and keep it out of Git.

## Diagnostic Statuses

| Status | Meaning |
|---|---|
| `OK` / `WARN` | The direct HTTP request got an allowed or warning code |
| `SLOW` / `CERT_EXPIRING` / `DOMAIN_EXPIRING` | The site is available but slower than the threshold, or the certificate or domain expires soon |
| `CONTENT_MISMATCH` | The server answered with an allowed code, but the expected text is missing |
| `HTTP_ERROR` | The code is neither allowed nor a warning |
| `DNS_ERROR` | System DNS gave no address; blocking is not confirmed |
| `DNS_BLOCK` | System DNS gave no address, DoH did, and the URL works through the proxy |
| `TCP_TIMEOUT` / `TCP_RESET` | TCP error on the URL's real port without enough evidence of the cause |
| `TCP_BLOCK` | Direct TCP fails, but the URL works through the proxy |
| `TLS_ERROR` / `SSL_ERROR` | The TLS handshake failed; the certificate, server, antivirus or network may be the cause |
| `TLS_BLOCK` | The direct TLS failure is confirmed by successful access through the proxy |
| `HTTP_STUB` | HTTP 451 or signs of a stub in the limited body fragment |
| `HTTP_BLOCK` | The stub or HTTP failure is absent on the proxy control route |
| `HTTP_TIMEOUT` | TCP/TLS work, but HTTP did not finish; overload or throttling is possible |

## Measurement Limits

One computer sees only its own network, DNS and route. Without an independent control point you cannot reliably tell blocking from a site, routing, CDN, antivirus or corporate filter failure. DoH shows the availability of one DoH server and an alternative DNS answer, not proof of interference. The app does not get around blocks automatically and does not implement ECH/QUIC; the proxy is used only for the explicitly configured control check and webhook notifications.

## Development

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --bins
```

CI (`.github/workflows/rust.yml`) runs these checks on Windows and Linux.

## Project Layout

| Path | Purpose |
|---|---|
| `src/main.rs` | `website_accessibility_monitor` binary: headless check (`--json`), `--watch`, Windows service, `--metrics` |
| `src/bin/sitemonitor.rs`, `src/bin/sitemonitor_lite.rs` | `SiteMonitor` and `SiteMonitorLite` binaries (TUI) |
| `src/tui/` | ratatui interface |
| `src/monitor.rs`, `src/network.rs`, `src/notice.rs`, `src/expiry.rs` | Checks, diagnostics, stubs, certificate and domain dates |
| `src/config.rs`, `src/model.rs`, `src/storage.rs` | `config.json` format and saving, history, log, CSV |
| `src/daemon.rs`, `src/service.rs`, `src/metrics.rs`, `src/webhooks.rs` | Background mode, Windows service, Prometheus, notifications |
| `deploy/` | systemd unit and sample Prometheus alert rules |
| `Start.bat`, `StartLite.bat` | Launch the TUI on Windows (they build the release binary with cargo if missing) |

`config.json`, `uptime_history.json` and `results.csv` are local data and are in `.gitignore`.
