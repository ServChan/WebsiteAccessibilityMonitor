# WebsiteAccessibilityMonitor (WAM)

[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen?style=flat-square)](README.md)
[![Language](https://img.shields.io/badge/Rust-2024%20%7C%201.80+-blue?style=flat-square&logo=rust)](README.md)
[![Runtime](https://img.shields.io/badge/Async-Tokio%20%7C%20Reqwest-orange?style=flat-square)](README.md)
[![Version](https://img.shields.io/badge/Version-2.0.0-purple?style=flat-square)](README.md)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

Ultra-fast asynchronous website uptime, HTTP latency, and ICMP accessibility monitoring daemon in Rust.

## Русский

### Что это

`WebsiteAccessibilityMonitor (WAM)` — высокопроизводительная утилита на Rust для непрерывного мониторинга доступности веб-сайтов и серверов через параллельные HTTP(S) запросы и ICMP-пинг (без необходимости прав администратора на Windows).

### Ключевые возможности

- параллельная проверка сотен хостов в секунду благодаря асинхронному рантайму Tokio;
- расчёт времени отклика (TTFB, latency), HTTP статус-кодов и процента аптайма;
- отправка мгновенных оповещений о сбоях в Telegram и вебхуки;
- экспорт статистики и логов в JSON и CSV.

### Особенности

- минимальное потребление системных ресурсов (<15 МБ RAM);
- поддержка сжатия gzip/brotli/deflate при проверках;
- готовые скрипты быстрого запуска для Windows (`Start.bat`, `StartLite.bat`).

### Использование

```bash
cargo run --release
```

---

## English

### What It Is

`WebsiteAccessibilityMonitor (WAM)` is an ultra-fast, asynchronous Rust daemon monitoring website uptime, HTTP response latency, and ICMP connectivity.

### Key Features

- concurrent polling of hundreds of target URLs powered by Tokio and Reqwest;
- precise latency metrics (TTFB, connection time), HTTP error status tracking, and uptime SLA percentiles;
- instant downtime notifications via Telegram bots and custom HTTP webhooks;
- structured JSON/CSV logging and audit trail export.

### Features

- minimal footprint with less than 15 MB RAM utilization;
- automatic support for Brotli, Gzip, and Deflate compression handshakes;
- convenient Windows launch scripts (`Start.bat`, `StartLite.bat`).

### Usage

```bash
cargo run --release
```

## Credits

Developed by LTS_Server. Licensed under MIT.
