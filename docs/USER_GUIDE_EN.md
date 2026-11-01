# WebsiteAccessibilityMonitor User Guide

[Русская версия](USER_GUIDE_RU.md)

The program interface is in Russian. English names for its screens and options are given below.

## First Run

1. Build the program: `cargo build --release`.
2. Run `Start.bat` or `target/release/SiteMonitor.exe`.
3. `config.json` with the default site list appears next to the executable.
4. A few seconds later the table fills with the results of the first check.

If the console is too small, some sites are hidden and a line under the table shows how many. Scroll with the arrow keys or enlarge the window. The uptime timeline appears when the window has at least 28 rows.

## Reading the Table

| Column | Meaning |
|---|---|
| Статус (Status) | check result |
| Сайт (Site) | address from the configuration |
| IP | address returned by DNS |
| Код (Code) | HTTP status code |
| Метод (Method) | HEAD or GET |
| Повт (Retries) | how many retries were needed |
| мс (ms) | response time, coloured by speed |

General options are above the table. Below it are availability as a percentage, the current sort order, key hints and the time until the next check.

## In-App Settings

Press `O`. The up and down arrows pick a row, the left and right arrows change a value, and `Enter` opens text input. Press `O` again to save to `config.json`, or `Esc` to leave without saving.

The settings screen covers:

- interval, timeout and number of retries;
- ping, uptime collection and the fast HEAD method;
- logging, CSV export and their file paths;
- webhooks: Telegram token and chat, Discord and Slack addresses, failure threshold, down and recovery alerts;
- proxy: address, username, password;
- the DNS-over-HTTPS server.

## The config.json File

The file sits next to the executable. After editing it by hand, press `R`.

### monitor_settings

| Field | Default | Meaning |
|---|---|---|
| `interval` | `60` | seconds between checks |
| `timeout` | `5` | connection timeout in seconds |
| `retries_max` | `2` | number of retries |
| `valid_status_codes` | 200, 201, 202, 204, 300, 301, 302, 303, 307, 308 | codes treated as success |
| `warn_status_codes` | 401, 403, 429 | codes shown as a warning |
| `sorted` | `status` | initial sort order |
| `ping_enabled` | `true` | ping hosts |
| `uptime_enabled` | `false` | collect daily uptime |
| `use_head_first` | `true` | start with HEAD |
| `proxy_url`, `proxy_username`, `proxy_password` | empty | proxy |
| `doh_server` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS server |

### Sites and Groups

`websites` is a plain list of addresses. `website_groups` defines groups with their own interval and headers:

```json
"website_groups": [
  {
    "name": "API",
    "interval": 30,
    "sites": [
      { "url": "https://example.com/health", "headers": { "Accept": "application/json" } }
    ]
  }
]
```

### Alerts

The `webhooks` block:

| Field | Meaning |
|---|---|
| `enabled` | master switch |
| `telegram_bot_token`, `telegram_chat_id` | Telegram bot and chat |
| `discord_webhook_url`, `slack_webhook_url` | webhook addresses |
| `notify_on_down`, `notify_on_recovery` | what to report |
| `min_failures_before_alert` | failures in a row before an alert, 3 by default |

Tokens and the proxy password are stored in `config.json` as plain text, so do not publish this file.

### Logs, Export, Colours

- `Monitor`: `logging_enabled`, `log_file_path`, `log_max_size_mb`, `log_rotate_daily`.
- `csv_export`: `enabled`, `file_path`.
- `uptime_history_path`: the uptime history file.
- `color_theme`: colours for statuses and headers, using names such as `Green` or `Cyan`.

## FAQ

**Ping does not work.** ICMP is implemented for Windows only. Other systems check HTTP and DNS only.

**A site opens in a browser but the program reports an error.** Some servers reject HEAD. The program tries GET on its own, and if the returned code is fine for you, add it to `valid_status_codes`.

**A site shows a warning status.** Its response code is in `warn_status_codes`. That usually means protection against automated requests, not an outage.
