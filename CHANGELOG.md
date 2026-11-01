# Changelog

## 2.2.0 — 2026-11

- **Одна программа / One program:** `SiteMonitor`, `SiteMonitorLite` и `website_accessibility_monitor` объединены в `wam`: без параметров открывается интерфейс, `--lite` включает компактный вид, `--once` проверяет цели из `config.json` один раз. `Start.bat` и `StartLite.bat` удалены. / The three programs are merged into `wam`: no arguments open the interface, `--lite` selects the compact view, `--once` runs a single check of the `config.json` targets. The `.bat` launchers are gone.
- **Настройки / Settings:** раздел `Monitor` переименован в `logging`, цвет `banner` в `accent`, неиспользуемый цвет `header` убран; старые ключи читаются. История аптайма включена по умолчанию, в новом `config.json` три примера сайтов вместо двенадцати. / `Monitor` is now `logging`, the `banner` colour is `accent`, the unused `header` colour is removed; old keys are still read. Uptime history is on by default, a new `config.json` has three sample sites instead of twelve.
- **Пустой список / Empty list:** можно удалить последний сайт, настройки без сайтов больше не подменяются списком по умолчанию, интерфейс подсказывает, как добавить первый. / The last site can be removed, a config with no sites is no longer replaced with the default list, and the interface shows how to add the first one.
- **Данные рядом с настройками / Data next to the config:** с `--config` интерфейс хранит историю, журнал и CSV рядом с указанным файлом, как и `--watch`. / With `--config` the interface keeps history, log and CSV next to that file, as `--watch` does.
## 2.1.0 — 2026-10

- **Порт на Rust завершён / Rust port finished:** общий интерфейс ratatui, фоновый режим `--watch`, служба Windows, метрики Prometheus. / Shared ratatui interface, `--watch` background mode, Windows service, Prometheus metrics.
- **Диагностика / Diagnostics:** блокировка определяется только при подтверждении через прокси, сравнение с DoH, проверка текста, сроков сертификата и домена, окна обслуживания. / Blocking is reported only when confirmed through a proxy, DoH comparison, expected-text, certificate and domain expiry checks, maintenance windows.
- **Прокси / Proxy:** логин и пароль теперь задаются в `proxy_url`, отдельных полей `proxy_username` и `proxy_password` больше нет. / Credentials now go into `proxy_url`; the separate `proxy_username` and `proxy_password` fields are gone.
- **CI:** сборка .NET заменена проверками Rust на Windows и Linux. / The .NET build is replaced with Rust checks on Windows and Linux.

## 2.0.0 — 2026-06

- **Переход на Rust / Rewrite in Rust:** программа переписана с C# на Rust, исправлены сбои разметки при изменении размера окна, добавлено окно настроек. / The program moved from C# to Rust, layout bugs on resize were fixed, and an in-app settings screen was added.
- **Таблица / Table:** прокрутка результатов. / Scrollable results.
- **Сеть / Network:** авторизация на прокси. / Proxy authentication.
- **Уведомления / Alerts:** вебхуки Telegram, Discord и Slack. / Telegram, Discord and Slack webhooks.

## 2026-03

- **Монитор / Monitor:** расширены конфигурация, интерфейс, вебхуки и журналирование. / Extended configuration, interface, webhooks and logging.

## 2025-08

- **Настройки / Settings:** расширенные настройки и улучшенный мониторинг сайтов. / Extended settings and improved site monitoring.
- **Сборка / Build:** добавлены файл проекта и сборка в GitHub Actions. / Added the project file and a GitHub Actions build.

## 1.3.0 — 2025-03-28

- **Выпуск / Release:** сборки для x64 и x86 и переносимая версия. / x64 and x86 builds and a portable version.

## 1.2.8 — 2025-03-27

- **Первый выпуск / First release:** первая опубликованная версия на C#. / First published version in C#.
