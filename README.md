# WebsiteAccessibilityMonitor (WAM)

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen?style=flat-square)](README.md)
[![Language](https://img.shields.io/badge/Rust-2024%20%7C%201.80+-blue?style=flat-square&logo=rust)](README.md)
[![Runtime](https://img.shields.io/badge/Async-Tokio%20%7C%20Reqwest-orange?style=flat-square)](README.md)
[![Version](https://img.shields.io/badge/Version-2.0.0-purple?style=flat-square)](README.md)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

High-throughput asynchronous website uptime, HTTP response time, and unprivileged ICMP accessibility monitoring daemon in Rust.

## Русский

### Что это

`WebsiteAccessibilityMonitor (WAM)` — высокопроизводительный сервис непрерывного мониторинга доступности веб-сайтов и серверов на языке Rust. Программа выполняет параллельную проверку сотен хостов в секунду по протоколам HTTP/HTTPS и ICMP-пинг без необходимости запуска от имени администратора на Windows.

### Ключевые возможности

- **Параллельный опрос сотен ресурсов**: Асинхронный конвейер на базе `Tokio` и пула соединений `Reqwest`.
- **ICMP Ping без Root/Admin**: Использование нативного Windows `IcmpSendEcho` API для отправки ICMP эхо-запросов без raw socket привилегий.
- **Детальная метрика производительности**: Фиксация DNS lookup time, TCP connect time, TLS handshake, TTFB и общего времени ответа.
- **Оповещения в реальном времени**: Мгновенная отправка алертов о падениях и восстановлении сайтов в Telegram-боты и вебхуки.
- **Логирование и отчёты**: Экспорт структурированных отчётов в JSON и CSV с подсчётом процента аптайма (SLA 99.9%).

### Параметры конфигурации (`config.json`)

```json
{
  "check_interval_seconds": 30,
  "timeout_seconds": 5,
  "retry_count": 2,
  "telegram_alerts": {
    "enabled": true,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  },
  "targets": [
    {
      "name": "PortalSHVK Main",
      "url": "https://порталшвк.рф",
      "expected_status": 200,
      "ping_enabled": true
    }
  ]
}
```

### Сборка и запуск

```bash
cargo build --release
```
Для быстрого запуска на Windows доступны готовые скрипты [`Start.bat`](file:///E:/Coding/WebsiteAccessibilityMonitor/Start.bat) и [`StartLite.bat`](file:///E:/Coding/WebsiteAccessibilityMonitor/StartLite.bat).

---

## English

### What It Is

`WebsiteAccessibilityMonitor (WAM)` is an ultra-fast, asynchronous Rust daemon designed for continuous uptime monitoring, HTTP latency profiling, and unprivileged ICMP accessibility checks.

### Key Features

- **Concurrent Multi-Target Polling**: Tokio-powered async pipeline polling hundreds of endpoints per second.
- **Unprivileged Windows ICMP Ping**: Direct integration with Windows `IcmpSendEcho` API requiring zero administrator privileges.
- **Latency Breakdown**: Measures DNS resolution, TCP handshake, TLS negotiation, TTFB, and full payload download duration.
- **Instant Incident Telemetry**: Dispatches failure alerts and recovery banners to Telegram channels and custom HTTP webhooks.
- **Audit Logging**: Generates JSON and CSV uptime SLA telemetry logs.

### Build and Running

```bash
cargo build --release
```
Run using `Start.bat` or `./target/release/website_accessibility_monitor`.

## Credits

Developed by LTS_Server. Licensed under MIT.
