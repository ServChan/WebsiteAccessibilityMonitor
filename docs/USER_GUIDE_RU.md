# WebsiteAccessibilityMonitor (wam): руководство

[English version](USER_GUIDE_EN.md)

## Что проверяется помимо доступности

| Проверка | Как работает | Статус |
|---|---|---|
| Ожидаемый текст | Ответ должен содержать заданную строку (без учёта регистра); читается до 1 МБ тела. Задаётся клавишей `T` в списке сайтов или полем `expect_text` | `CONTENT_MISMATCH` — сбой |
| Медленный ответ | Ответ дольше `slow_threshold_ms` (по умолчанию 3000 мс, `0` — выкл.). Для отдельного сайта — поле `slow_threshold_ms` | `SLOW` — предупреждение |
| Сертификат | Дата окончания берётся из сертификата, полученного при обычном HTTPS-запросе | `CERT_EXPIRING` за `cert_warn_days` дней (по умолчанию 14) |
| Домен | Дата окончания регистрации через RDAP (адрес реестра из списка IANA), для зон без RDAP (`.ru`, `.рф`, `.su`) — через WHOIS. Кешируется на 12 часов | `DOMAIN_EXPIRING` за `domain_warn_days` дней (по умолчанию 30) |
| Окна обслуживания | В заданное время проверки идут, но сбои не вызывают уведомлений и не портят аптайм | `ОБСЛУЖИВАНИЕ` в интерфейсе, `maintenance: true` в JSON |

Предупреждения (`WARN`, `SLOW`, `CERT_EXPIRING`, `DOMAIN_EXPIRING`) означают, что сайт доступен: уведомления о сбое по ним не отправляются. Все сроки видны в подробностях сайта (`Enter`), срок сертификата — ещё и в отдельном столбце таблицы «Сайты».

## Headless-режим

Одноразовая проверка для планировщика, CI или PowerShell:

```powershell
.\target\release\wam.exe --json https://example.com https://example.net
```

Цели из `config.json` в текущей папке проверяет `wam --once`. Схему можно не указывать: `example.com` проверяется как `https://example.com/`. Код завершения `0` означает, что все цели имеют статус `OK`/`WARN`; `2` — что есть недоступные цели; `1` — ошибка запуска (например, некорректный URL). Параметр `--config PATH` задаёт другой файл конфигурации.

Интерфейс запускается командой `wam` без параметров; при первом запуске рядом с программой создаётся `config.json`.

## Фоновый режим, служба и метрики

`--watch` проверяет сайты постоянно, без интерфейса: по расписанию, с уведомлениями, историей аптайма, журналом и CSV, как в интерфейсе. Изменения в `config.json` подхватываются автоматически, без перезапуска. События пишутся в консоль (или в файл через `--log-file`), `--quiet` скрывает итоги циклов без сбоев. Остановка — `Ctrl+C` или `SIGTERM`, история аптайма при этом сохраняется.

```powershell
.\target\release\wam.exe --watch --config C:\WAM\config.json --metrics 127.0.0.1:9898
```

Относительные пути из настроек (история, журнал, CSV) считаются от папки, где лежит `config.json`.

**Служба Windows.** Из консоли, запущенной от имени администратора:

```powershell
.\target\release\wam.exe --install-service --config C:\WAM\config.json --metrics 127.0.0.1:9898
```

Служба `WebsiteAccessibilityMonitor` запускается сразу и затем автоматически вместе с Windows. Журнал событий — `wam-service.log` рядом с `config.json` (или путь из `--log-file`). Удаление: `--uninstall-service`.

**Linux (systemd).** Готовый юнит с инструкцией по установке — [deploy/wam.service](../deploy/wam.service); события читаются через `journalctl -u wam -f`.

**Prometheus.** С `--metrics АДРЕС` по адресу `http://АДРЕС/metrics` отдаются:

| Метрика | Значение |
|---|---|
| `wam_up` | 1 — сайт доступен (OK или предупреждение), 0 — нет |
| `wam_status{status="..."}` | Текущий диагностический статус |
| `wam_maintenance` | 1 — проверка пришлась на окно обслуживания |
| `wam_response_time_seconds` | Время ответа |
| `wam_http_status_code` | HTTP-код |
| `wam_content_match` | 1/0 — найден ли ожидаемый текст |
| `wam_cert_expiry_timestamp_seconds` | Окончание сертификата (Unix time) |
| `wam_domain_expiry_timestamp_seconds` | Окончание регистрации домена (Unix time) |
| `wam_uptime_ratio` | Доля успешных проверок за 24 часа |
| `wam_checks_total{result="ok\|failed"}` | Счётчик проверок с момента запуска |
| `wam_last_check_timestamp_seconds`, `wam_last_cycle_*` | Время последней проверки и цикла |

Все метрики сайтов имеют метки `url` и `group`. Пример правил алертов — [deploy/prometheus-alerts.yml](../deploy/prometheus-alerts.yml). `/health` отвечает `ok` для проверок живости. Если указать только порт (`--metrics 9898`), слушается `127.0.0.1`; открывать порт наружу стоит только за файрволом: в метках видны адреса сайтов.

## Актуальный формат config.json

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
  "logging": {
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

Сайт в `websites` и в `sites` групп задаётся строкой или объектом с полями `url`, `headers`, `expect_text`, `slow_threshold_ms`. Сайты без дополнительных полей программа сохраняет обратно строками.

В окне обслуживания `days` — дни недели (`mon`..`sun` или `пн`..`вс`, пусто — каждый день), `start`/`end` — местное время `ЧЧ:ММ`; окно через полночь относится к дню начала. `targets` — части адреса или имени группы, пусто — все сайты.

`proxy_url` оставьте пустым, если контрольный маршрут не нужен. Для SOCKS с разрешением имени на стороне прокси используйте схему `socks5h://`; это особенно важно, когда локальный DNS недоступен или подменён. Секреты в заголовках и webhook-настройках хранятся в обычном JSON — ограничьте доступ к файлу и не добавляйте его в Git.

## Статусы диагностики

| Статус | Значение |
|---|---|
| `OK` / `WARN` | Прямой HTTP-запрос получил разрешённый или предупреждающий код |
| `SLOW` / `CERT_EXPIRING` / `DOMAIN_EXPIRING` | Сайт доступен, но отвечает медленнее порога или скоро истекает сертификат либо домен |
| `CONTENT_MISMATCH` | Сервер ответил допустимым кодом, но в ответе нет ожидаемого текста |
| `HTTP_ERROR` | Код ответа не входит ни в разрешённые, ни в предупреждающие |
| `DNS_ERROR` | Системный DNS не дал адрес; блокировка не подтверждена |
| `DNS_BLOCK` | Системный DNS не дал адрес, DoH дал адреса, а URL доступен через прокси |
| `TCP_TIMEOUT` / `TCP_RESET` | Ошибка TCP на фактическом порту URL без достаточного подтверждения причины |
| `TCP_BLOCK` | TCP прямого пути не работает, но URL доступен через прокси |
| `TLS_ERROR` / `SSL_ERROR` | TLS-рукопожатие не прошло; возможны сертификат, сервер, антивирус или сеть |
| `TLS_BLOCK` | Сбой TLS прямого пути подтверждён успешным доступом через прокси |
| `HTTP_STUB` | Получен HTTP 451 или в ограниченном фрагменте тела найдены признаки заглушки |
| `HTTP_BLOCK` | Заглушка/HTTP-сбой отсутствует на контрольном прокси-маршруте |
| `HTTP_TIMEOUT` | TCP/TLS работают, но HTTP не завершился; возможны перегрузка или троттлинг |

## Ограничения измерений

Один компьютер видит только свою сеть, DNS и маршрут. Без независимой контрольной точки нельзя надёжно отличить блокировку от сбоя сайта, маршрутизации, CDN, антивируса или корпоративного фильтра. DoH показывает доступность конкретного DoH-сервера и альтернативный DNS-ответ, но не является доказательством вмешательства. Программа не обходит блокировки автоматически и не реализует ECH/QUIC; прокси используется только для явно настроенной контрольной проверки и webhook-уведомлений.

## Разработка

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --bins
```

CI (`.github/workflows/rust.yml`) выполняет эти проверки на Windows и Linux.

## Структура проекта

| Путь | Назначение |
|---|---|
| `src/main.rs` | Бинарь `wam`: выбор режима, одноразовая проверка, `--watch`, служба Windows, `--metrics` |
| `src/tui/` | Интерфейс на ratatui |
| `src/monitor.rs`, `src/network.rs`, `src/notice.rs`, `src/expiry.rs` | Проверки, диагностика, заглушки, сроки сертификатов и доменов |
| `src/config.rs`, `src/model.rs`, `src/storage.rs` | Формат и сохранение `config.json`, история, журнал, CSV |
| `src/daemon.rs`, `src/service.rs`, `src/metrics.rs`, `src/webhooks.rs` | Фоновый режим, служба Windows, Prometheus, уведомления |
| `deploy/` | Юнит systemd и пример правил алертов Prometheus |

`config.json`, `uptime_history.json` и `results.csv` — локальные данные, они в `.gitignore`.

