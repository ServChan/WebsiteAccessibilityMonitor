use std::collections::HashMap;

use chrono::{
    DateTime, Datelike, Duration as ChronoDuration, NaiveDateTime, NaiveTime, Utc, Weekday,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitorSettings {
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_retries_max")]
    pub retries_max: u32,
    #[serde(default = "default_valid_status_codes")]
    pub valid_status_codes: Vec<u16>,
    #[serde(default = "default_warn_status_codes")]
    pub warn_status_codes: Vec<u16>,
    #[serde(default = "default_sorted")]
    pub sorted: String,
    #[serde(default = "default_ping_enabled")]
    pub ping_enabled: bool,
    #[serde(default = "default_true")]
    pub uptime_enabled: bool,
    #[serde(default = "default_use_head_first")]
    pub use_head_first: bool,
    #[serde(default)]
    pub proxy_url: String,
    #[serde(default = "default_doh_server")]
    pub doh_server: String,
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    #[serde(default = "default_response_body_limit_kb")]
    pub response_body_limit_kb: usize,
    #[serde(default = "default_diagnostics_enabled")]
    pub diagnostics_enabled: bool,
    /// Responses slower than this become `SLOW` (still available). `0` disables the check.
    #[serde(default = "default_slow_threshold_ms")]
    pub slow_threshold_ms: u64,
    /// HTTPS certificates expiring within this many days become `CERT_EXPIRING`. `0` disables.
    #[serde(default = "default_cert_warn_days")]
    pub cert_warn_days: u32,
    /// Look up domain registration expiry via RDAP/WHOIS (cached for 12 hours).
    #[serde(default = "default_true")]
    pub domain_check_enabled: bool,
    #[serde(default = "default_domain_warn_days")]
    pub domain_warn_days: u32,
}

pub const fn default_interval() -> u64 {
    60
}
const fn default_timeout() -> u64 {
    8
}
const fn default_retries_max() -> u32 {
    2
}
fn default_valid_status_codes() -> Vec<u16> {
    vec![
        200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304, 305, 307, 308,
    ]
}
fn default_warn_status_codes() -> Vec<u16> {
    vec![401, 403, 407, 408, 425, 429]
}
fn default_sorted() -> String {
    "status".into()
}
const fn default_ping_enabled() -> bool {
    true
}
const fn default_use_head_first() -> bool {
    false
}
fn default_doh_server() -> String {
    "https://cloudflare-dns.com/dns-query".into()
}
const fn default_max_concurrency() -> usize {
    32
}
const fn default_response_body_limit_kb() -> usize {
    64
}
const fn default_diagnostics_enabled() -> bool {
    true
}
const fn default_slow_threshold_ms() -> u64 {
    3_000
}
const fn default_cert_warn_days() -> u32 {
    14
}
const fn default_domain_warn_days() -> u32 {
    30
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            interval: default_interval(),
            timeout: default_timeout(),
            retries_max: default_retries_max(),
            valid_status_codes: default_valid_status_codes(),
            warn_status_codes: default_warn_status_codes(),
            sorted: default_sorted(),
            ping_enabled: default_ping_enabled(),
            uptime_enabled: true,
            use_head_first: default_use_head_first(),
            proxy_url: String::new(),
            doh_server: default_doh_server(),
            max_concurrency: default_max_concurrency(),
            response_body_limit_kb: default_response_body_limit_kb(),
            diagnostics_enabled: default_diagnostics_enabled(),
            slow_threshold_ms: default_slow_threshold_ms(),
            cert_warn_days: default_cert_warn_days(),
            domain_check_enabled: true,
            domain_warn_days: default_domain_warn_days(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoggingSettings {
    #[serde(default)]
    pub logging_enabled: bool,
    #[serde(default = "default_log_file_path")]
    pub log_file_path: String,
    #[serde(default = "default_log_max_size_mb")]
    pub log_max_size_mb: u64,
    #[serde(default = "default_true")]
    pub log_rotate_daily: bool,
}

fn default_log_file_path() -> String {
    "monitor.log".into()
}
const fn default_log_max_size_mb() -> u64 {
    10
}
const fn default_true() -> bool {
    true
}

impl Default for LoggingSettings {
    fn default() -> Self {
        Self {
            logging_enabled: false,
            log_file_path: default_log_file_path(),
            log_max_size_mb: default_log_max_size_mb(),
            log_rotate_daily: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default)]
    pub discord_webhook_url: String,
    #[serde(default)]
    pub slack_webhook_url: String,
    #[serde(default = "default_true")]
    pub notify_on_down: bool,
    #[serde(default = "default_true")]
    pub notify_on_recovery: bool,
    #[serde(default = "default_min_failures_before_alert")]
    pub min_failures_before_alert: u32,
}

const fn default_min_failures_before_alert() -> u32 {
    3
}

impl Default for WebhookSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            discord_webhook_url: String::new(),
            slack_webhook_url: String::new(),
            notify_on_down: true,
            notify_on_recovery: true,
            min_failures_before_alert: default_min_failures_before_alert(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebsiteGroup {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default)]
    pub sites: Vec<WebsiteEntry>,
}

/// One monitored URL. In config.json it is either a plain string or an object with
/// per-site options; entries without options are written back as plain strings.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(from = "WebsiteEntryRepr", into = "WebsiteEntryRepr")]
pub struct WebsiteEntry {
    pub url: String,
    pub headers: HashMap<String, String>,
    /// The response body must contain this text (case-insensitive). Empty: no check.
    pub expect_text: String,
    /// Overrides `monitor_settings.slow_threshold_ms` for this site.
    pub slow_threshold_ms: Option<u64>,
}

impl WebsiteEntry {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }
}

impl From<&str> for WebsiteEntry {
    fn from(url: &str) -> Self {
        Self::new(url)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum WebsiteEntryRepr {
    Url(String),
    Full {
        url: String,
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        headers: HashMap<String, String>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        expect_text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slow_threshold_ms: Option<u64>,
    },
}

impl From<WebsiteEntryRepr> for WebsiteEntry {
    fn from(repr: WebsiteEntryRepr) -> Self {
        match repr {
            WebsiteEntryRepr::Url(url) => Self::new(url),
            WebsiteEntryRepr::Full {
                url,
                headers,
                expect_text,
                slow_threshold_ms,
            } => Self {
                url,
                headers,
                expect_text,
                slow_threshold_ms,
            },
        }
    }
}

impl From<WebsiteEntry> for WebsiteEntryRepr {
    fn from(entry: WebsiteEntry) -> Self {
        if entry.headers.is_empty()
            && entry.expect_text.is_empty()
            && entry.slow_threshold_ms.is_none()
        {
            Self::Url(entry.url)
        } else {
            Self::Full {
                url: entry.url,
                headers: entry.headers,
                expect_text: entry.expect_text,
                slow_threshold_ms: entry.slow_threshold_ms,
            }
        }
    }
}

/// A recurring local-time window during which failures are expected: checks still run,
/// but alerts are suppressed and the samples are excluded from uptime.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MaintenanceWindow {
    #[serde(default)]
    pub name: String,
    /// `mon`..`sun` or `пн`..`вс`; empty means every day. A window that crosses midnight
    /// belongs to the day it starts on.
    #[serde(default)]
    pub days: Vec<String>,
    /// `HH:MM`, local time.
    pub start: String,
    pub end: String,
    /// Substrings of a URL or group name; empty means every site.
    #[serde(default)]
    pub targets: Vec<String>,
}

pub fn parse_weekday(value: &str) -> Option<Weekday> {
    Some(match value.trim().to_lowercase().as_str() {
        "mon" | "monday" | "пн" | "понедельник" => Weekday::Mon,
        "tue" | "tuesday" | "вт" | "вторник" => Weekday::Tue,
        "wed" | "wednesday" | "ср" | "среда" => Weekday::Wed,
        "thu" | "thursday" | "чт" | "четверг" => Weekday::Thu,
        "fri" | "friday" | "пт" | "пятница" => Weekday::Fri,
        "sat" | "saturday" | "сб" | "суббота" => Weekday::Sat,
        "sun" | "sunday" | "вс" | "воскресенье" => Weekday::Sun,
        _ => return None,
    })
}

pub fn parse_clock(value: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(value.trim(), "%H:%M").ok()
}

impl MaintenanceWindow {
    fn runs_on(&self, day: Weekday) -> bool {
        self.days.is_empty()
            || self
                .days
                .iter()
                .any(|value| parse_weekday(value) == Some(day))
    }

    pub fn applies_to(&self, url: &str, group: &str) -> bool {
        self.targets.is_empty()
            || self.targets.iter().any(|needle| {
                let needle = needle.trim().to_lowercase();
                !needle.is_empty()
                    && (url.to_lowercase().contains(&needle)
                        || group.to_lowercase().contains(&needle))
            })
    }

    /// Whether `now` (local wall-clock time) falls inside the window.
    pub fn is_active(&self, now: NaiveDateTime) -> bool {
        let (Some(start), Some(end)) = (parse_clock(&self.start), parse_clock(&self.end)) else {
            return false;
        };
        let time = now.time();
        let today = now.date().weekday();
        let yesterday = (now.date() - ChronoDuration::days(1)).weekday();
        match start.cmp(&end) {
            std::cmp::Ordering::Less => self.runs_on(today) && time >= start && time < end,
            std::cmp::Ordering::Greater => {
                (self.runs_on(today) && time >= start) || (self.runs_on(yesterday) && time < end)
            }
            std::cmp::Ordering::Equal => self.runs_on(today),
        }
    }

    pub fn label(&self) -> String {
        let span = format!("{}–{}", self.start.trim(), self.end.trim());
        if self.name.trim().is_empty() {
            span
        } else {
            format!("{} ({span})", self.name.trim())
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ColorTheme {
    #[serde(default = "default_color_ok")]
    pub ok: String,
    #[serde(default = "default_color_warn")]
    pub warn: String,
    #[serde(default = "default_color_error")]
    pub error: String,
    #[serde(default = "default_color_accent", alias = "banner")]
    pub accent: String,
    #[serde(default = "default_color_ok")]
    pub fast_ms: String,
    #[serde(default = "default_color_warn")]
    pub medium_ms: String,
    #[serde(default = "default_color_error")]
    pub slow_ms: String,
}

fn default_color_ok() -> String {
    "Green".into()
}
fn default_color_warn() -> String {
    "Yellow".into()
}
fn default_color_error() -> String {
    "Red".into()
}
fn default_color_accent() -> String {
    "Cyan".into()
}

impl Default for ColorTheme {
    fn default() -> Self {
        Self {
            ok: default_color_ok(),
            warn: default_color_warn(),
            error: default_color_error(),
            accent: default_color_accent(),
            fast_ms: default_color_ok(),
            medium_ms: default_color_warn(),
            slow_ms: default_color_error(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CsvExportSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_csv_file_path")]
    pub file_path: String,
}

fn default_csv_file_path() -> String {
    "results.csv".into()
}

impl Default for CsvExportSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            file_path: default_csv_file_path(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub monitor_settings: MonitorSettings,
    #[serde(default)]
    pub websites: Vec<WebsiteEntry>,
    #[serde(default)]
    pub website_groups: Vec<WebsiteGroup>,
    /// `Monitor` is the key used by 2.1 and earlier.
    #[serde(default, alias = "Monitor")]
    pub logging: LoggingSettings,
    #[serde(default)]
    pub webhooks: WebhookSettings,
    #[serde(default)]
    pub color_theme: ColorTheme,
    #[serde(default)]
    pub csv_export: CsvExportSettings,
    #[serde(default = "default_uptime_history_path")]
    pub uptime_history_path: String,
    #[serde(default)]
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

fn default_uptime_history_path() -> String {
    "uptime_history.json".into()
}

impl Config {
    /// The maintenance window covering this site at `now` (local time), if any.
    pub fn active_maintenance(
        &self,
        url: &str,
        group: &str,
        now: NaiveDateTime,
    ) -> Option<&MaintenanceWindow> {
        self.maintenance_windows
            .iter()
            .find(|window| window.applies_to(url, group) && window.is_active(now))
    }
}

#[derive(Debug, Clone)]
pub struct MonitorTarget {
    pub url: String,
    pub group_name: String,
    pub headers: HashMap<String, String>,
    pub interval: u64,
    pub expect_text: String,
    /// Effective threshold (per-site override or the global one); `0` disables.
    pub slow_threshold_ms: u64,
}

/// Stable key of a monitored target: the same URL may appear in several groups with
/// different headers, so the group is part of the identity.
pub fn target_identity(group_name: &str, url: &str) -> String {
    if group_name.is_empty() {
        url.to_string()
    } else {
        format!("{group_name} :: {url}")
    }
}

impl MonitorTarget {
    /// A target with global defaults, used by the headless command and tests.
    pub fn from_url(url: impl Into<String>, config: &Config) -> Self {
        Self {
            url: url.into(),
            group_name: String::new(),
            headers: HashMap::new(),
            interval: config.monitor_settings.interval,
            expect_text: String::new(),
            slow_threshold_ms: config.monitor_settings.slow_threshold_ms,
        }
    }

    pub fn identity(&self) -> String {
        target_identity(&self.group_name, &self.url)
    }
}

/// Coarse availability verdict used for sorting, summaries and alerting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Health {
    Down,
    Warning,
    Up,
}

/// Verdict implied by the status alone, ignoring maintenance.
pub fn status_health(status: &str) -> Health {
    match status {
        "OK" => Health::Up,
        "WARN" | "SLOW" | "CERT_EXPIRING" | "DOMAIN_EXPIRING" => Health::Warning,
        _ => Health::Down,
    }
}

/// Human-readable explanation of a diagnostic status.
pub fn status_description(status: &str) -> &'static str {
    match status {
        "OK" => "Доступен: код ответа входит в список допустимых",
        "WARN" => "Отвечает, но код ответа из списка предупреждений",
        "SLOW" => "Доступен, но отвечает медленнее заданного порога",
        "CERT_EXPIRING" => "Доступен, но TLS-сертификат скоро истекает",
        "DOMAIN_EXPIRING" => "Доступен, но регистрация домена скоро истекает",
        "CONTENT_MISMATCH" => "Сервер ответил, но в ответе нет ожидаемого текста",
        "HTTP_ERROR" => "Сервер ответил недопустимым HTTP-кодом",
        "HTTP_STUB" => "Ответ похож на страницу-заглушку",
        "HTTP_BLOCK" => "Вероятная HTTP-блокировка: через прокси ресурс доступен",
        "HTTP_TIMEOUT" => "Таймаут HTTP (возможен троттлинг)",
        "REDIRECT_LOOP" => "Слишком много перенаправлений",
        "DNS_BLOCK" => "Вероятная блокировка DNS: DoH и прокси работают",
        "DNS_ERROR" => "Системный DNS не вернул адрес (блокировка не подтверждена)",
        "TCP_BLOCK" => "Вероятная блокировка TCP: через прокси ресурс доступен",
        "TCP_TIMEOUT" => "Таймаут TCP-подключения (блокировка не подтверждена)",
        "TCP_RESET" => "TCP-соединение сброшено (возможен DPI)",
        "TLS_BLOCK" => "Вероятная блокировка TLS (SNI/DPI): через прокси доступен",
        "TLS_ERROR" => "Сбой TLS-рукопожатия (блокировка не подтверждена)",
        "SSL_ERROR" => "Ошибка SSL/TLS: сертификат или протокол",
        "CONN_ERROR" => "Ошибка подключения",
        "URL_ERROR" => "Некорректный URL",
        _ => "Неизвестное состояние",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebsiteResult {
    pub url: String,
    pub ip: String,
    pub status: String,
    pub code: String,
    pub error_type: String,
    pub duration_ms: u64,
    pub retries: u32,
    pub http_method: String,
    pub group_name: String,
    #[serde(default)]
    pub proxy_ok: bool,
    #[serde(default)]
    pub direct_ok: bool,
    #[serde(default)]
    pub dns_anomaly: bool,
    #[serde(default)]
    pub system_ips: Vec<String>,
    #[serde(default)]
    pub reference_ips: Vec<String>,
    #[serde(default)]
    pub icmp_ok: Option<bool>,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub cert_expires: Option<DateTime<Utc>>,
    #[serde(default)]
    pub cert_days_left: Option<i64>,
    #[serde(default)]
    pub domain_expires: Option<DateTime<Utc>>,
    #[serde(default)]
    pub domain_days_left: Option<i64>,
    /// `None` when no expected text is configured or the body was not checked.
    #[serde(default)]
    pub content_ok: Option<bool>,
    /// Checked during a maintenance window: failures are expected and not alerted.
    #[serde(default)]
    pub maintenance: bool,
}

impl WebsiteResult {
    /// Empty result for `url`, before any check step ran.
    pub fn pending(url: &str) -> Self {
        Self {
            url: url.into(),
            ip: "N/A".into(),
            status: "INIT".into(),
            code: String::new(),
            error_type: String::new(),
            duration_ms: 0,
            retries: 0,
            http_method: "GET".into(),
            group_name: String::new(),
            proxy_ok: false,
            direct_ok: false,
            dns_anomaly: false,
            system_ips: Vec::new(),
            reference_ips: Vec::new(),
            icmp_ok: None,
            details: String::new(),
            cert_expires: None,
            cert_days_left: None,
            domain_expires: None,
            domain_days_left: None,
            content_ok: None,
            maintenance: false,
        }
    }

    /// A failure during maintenance counts as a warning: it was planned.
    pub fn health(&self) -> Health {
        match status_health(&self.status) {
            Health::Down if self.maintenance => Health::Warning,
            health => health,
        }
    }

    pub fn is_available(&self) -> bool {
        self.health() != Health::Down
    }

    /// `*_BLOCK` statuses are only set when the proxy route confirmed the resource works.
    pub fn is_suspected_block(&self) -> bool {
        self.status.ends_with("_BLOCK")
    }

    pub fn identity(&self) -> String {
        target_identity(&self.group_name, &self.url)
    }
}

pub fn mask_secret(value: &str) -> String {
    let characters: Vec<_> = value.chars().collect();
    if characters.len() <= 8 {
        "********".into()
    } else {
        format!(
            "{}...{}",
            characters[..4].iter().collect::<String>(),
            characters[characters.len() - 4..]
                .iter()
                .collect::<String>()
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UptimeSiteData {
    pub checks_total: usize,
    pub checks_ok: usize,
    pub last_status: String,
    pub last_check: String,
    pub history: Vec<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UptimeHistoryFile {
    pub version: i32,
    pub last_updated: String,
    pub sites: HashMap<String, UptimeSiteData>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M").unwrap()
    }

    fn window(days: &[&str], start: &str, end: &str) -> MaintenanceWindow {
        MaintenanceWindow {
            name: String::new(),
            days: days.iter().map(|day| day.to_string()).collect(),
            start: start.into(),
            end: end.into(),
            targets: Vec::new(),
        }
    }

    #[test]
    fn website_entry_reads_string_or_object_and_writes_compactly() {
        let entries: Vec<WebsiteEntry> = serde_json::from_str(
            r#"["https://a.example", {"url": "https://b.example", "expect_text": "Welcome"}]"#,
        )
        .unwrap();
        assert_eq!(entries[0], WebsiteEntry::new("https://a.example"));
        assert_eq!(entries[1].expect_text, "Welcome");
        assert_eq!(
            serde_json::to_string(&entries).unwrap(),
            r#"["https://a.example",{"url":"https://b.example","expect_text":"Welcome"}]"#
        );
    }

    #[test]
    fn maintenance_window_on_selected_days() {
        // 2026-10-05 is a Monday.
        let monday_only = window(&["пн"], "02:00", "03:00");
        assert!(monday_only.is_active(at("2026-10-05 02:30")));
        assert!(!monday_only.is_active(at("2026-10-05 03:00")));
        assert!(!monday_only.is_active(at("2026-10-06 02:30")));
    }

    #[test]
    fn overnight_window_belongs_to_its_start_day() {
        let sunday_night = window(&["sun"], "23:00", "01:00");
        assert!(sunday_night.is_active(at("2026-10-04 23:30")));
        assert!(sunday_night.is_active(at("2026-10-05 00:30")));
        assert!(!sunday_night.is_active(at("2026-10-05 23:30")));
    }

    #[test]
    fn maintenance_window_matches_targets_by_substring() {
        let mut only_api = window(&[], "00:00", "00:00");
        only_api.targets = vec!["API".into()];
        assert!(only_api.applies_to("https://x.example", "api"));
        assert!(!only_api.applies_to("https://x.example", ""));
    }

    #[test]
    fn maintenance_failure_is_a_warning() {
        let mut result = WebsiteResult::pending("https://a.example");
        result.status = "TCP_TIMEOUT".into();
        assert_eq!(result.health(), Health::Down);
        result.maintenance = true;
        assert_eq!(result.health(), Health::Warning);
        assert_eq!(status_health("SLOW"), Health::Warning);
    }

    #[test]
    fn masks_unicode_without_invalid_byte_slices() {
        assert_eq!(mask_secret("абвгдежзиклм"), "абвг...иклм");
        assert_eq!(mask_secret("коротко"), "********");
    }
}
