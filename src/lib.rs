use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use chrono::Local;
use serde::{Deserialize, Serialize};

// =========================================================================
// Config Models
// =========================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitorSettings {
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_retries_max")]
    pub retries_max: u32,
    #[serde(default = "default_valid_status_codes")]
    pub valid_status_codes: Vec<i32>,
    #[serde(default = "default_warn_status_codes")]
    pub warn_status_codes: Vec<i32>,
    #[serde(default = "default_sorted")]
    pub sorted: String,
    #[serde(default = "default_ping_enabled")]
    pub ping_enabled: bool,
    #[serde(default = "default_uptime_enabled")]
    pub uptime_enabled: bool,
    #[serde(default = "default_use_head_first")]
    pub use_head_first: bool,
    #[serde(default = "default_proxy_url")]
    pub proxy_url: String,
    #[serde(default = "default_proxy_username")]
    pub proxy_username: String,
    #[serde(default = "default_proxy_password")]
    pub proxy_password: String,
    #[serde(default = "default_doh_server")]
    pub doh_server: String,
}

fn default_interval() -> u64 { 60 }
fn default_timeout() -> u64 { 5 }
fn default_retries_max() -> u32 { 2 }
fn default_valid_status_codes() -> Vec<i32> { vec![200, 201, 202, 204, 300, 301, 302, 303, 307, 308, 418] }
fn default_warn_status_codes() -> Vec<i32> { vec![401, 403, 429] }
fn default_sorted() -> String { "status".to_string() }
fn default_ping_enabled() -> bool { true }
fn default_uptime_enabled() -> bool { false }
fn default_use_head_first() -> bool { true }
fn default_proxy_url() -> String { "".to_string() }
fn default_proxy_username() -> String { "".to_string() }
fn default_proxy_password() -> String { "".to_string() }
fn default_doh_server() -> String { "https://cloudflare-dns.com/dns-query".to_string() }

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
            uptime_enabled: default_uptime_enabled(),
            use_head_first: default_use_head_first(),
            proxy_url: default_proxy_url(),
            proxy_username: default_proxy_username(),
            proxy_password: default_proxy_password(),
            doh_server: default_doh_server(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitorConfig {
    #[serde(default = "default_logging_enabled")]
    pub logging_enabled: bool,
    #[serde(default = "default_log_file_path")]
    pub log_file_path: String,
    #[serde(default = "default_log_max_size_mb")]
    pub log_max_size_mb: u64,
    #[serde(default = "default_log_rotate_daily")]
    pub log_rotate_daily: bool,
}

fn default_logging_enabled() -> bool { false }
fn default_log_file_path() -> String { "monitor.log".to_string() }
fn default_log_max_size_mb() -> u64 { 10 }
fn default_log_rotate_daily() -> bool { true }

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            logging_enabled: default_logging_enabled(),
            log_file_path: default_log_file_path(),
            log_max_size_mb: default_log_max_size_mb(),
            log_rotate_daily: default_log_rotate_daily(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookSettings {
    #[serde(default = "default_webhook_enabled")]
    pub enabled: bool,
    #[serde(default = "default_string")]
    pub telegram_bot_token: String,
    #[serde(default = "default_string")]
    pub telegram_chat_id: String,
    #[serde(default = "default_string")]
    pub discord_webhook_url: String,
    #[serde(default = "default_string")]
    pub slack_webhook_url: String,
    #[serde(default = "default_webhook_notify_on_down")]
    pub notify_on_down: bool,
    #[serde(default = "default_webhook_notify_on_recovery")]
    pub notify_on_recovery: bool,
    #[serde(default = "default_min_failures_before_alert")]
    pub min_failures_before_alert: u32,
}

fn default_webhook_enabled() -> bool { false }
fn default_string() -> String { "".to_string() }
fn default_webhook_notify_on_down() -> bool { true }
fn default_webhook_notify_on_recovery() -> bool { true }
fn default_min_failures_before_alert() -> u32 { 3 }

impl Default for WebhookSettings {
    fn default() -> Self {
        Self {
            enabled: default_webhook_enabled(),
            telegram_bot_token: default_string(),
            telegram_chat_id: default_string(),
            discord_webhook_url: default_string(),
            slack_webhook_url: default_string(),
            notify_on_down: default_webhook_notify_on_down(),
            notify_on_recovery: default_webhook_notify_on_recovery(),
            min_failures_before_alert: default_min_failures_before_alert(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebsiteGroup {
    #[serde(default = "default_string")]
    pub name: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default)]
    pub sites: Vec<WebsiteEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebsiteEntry {
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ColorTheme {
    #[serde(default = "default_color_ok")]
    pub ok: String,
    #[serde(default = "default_color_warn")]
    pub warn: String,
    #[serde(default = "default_color_error")]
    pub error: String,
    #[serde(default = "default_color_banner")]
    pub banner: String,
    #[serde(default = "default_color_header")]
    pub header: String,
    #[serde(default = "default_color_fast")]
    pub fast_ms: String,
    #[serde(default = "default_color_medium")]
    pub medium_ms: String,
    #[serde(default = "default_color_slow")]
    pub slow_ms: String,
}

fn default_color_ok() -> String { "Green".to_string() }
fn default_color_warn() -> String { "Yellow".to_string() }
fn default_color_error() -> String { "Red".to_string() }
fn default_color_banner() -> String { "Cyan".to_string() }
fn default_color_header() -> String { "Magenta".to_string() }
fn default_color_fast() -> String { "Green".to_string() }
fn default_color_medium() -> String { "Yellow".to_string() }
fn default_color_slow() -> String { "Red".to_string() }

impl Default for ColorTheme {
    fn default() -> Self {
        Self {
            ok: default_color_ok(),
            warn: default_color_warn(),
            error: default_color_error(),
            banner: default_color_banner(),
            header: default_color_header(),
            fast_ms: default_color_fast(),
            medium_ms: default_color_medium(),
            slow_ms: default_color_slow(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CsvExportSettings {
    #[serde(default = "default_csv_enabled")]
    pub enabled: bool,
    #[serde(default = "default_csv_file_path")]
    pub file_path: String,
}

fn default_csv_enabled() -> bool { false }
fn default_csv_file_path() -> String { "results.csv".to_string() }

impl Default for CsvExportSettings {
    fn default() -> Self {
        Self {
            enabled: default_csv_enabled(),
            file_path: default_csv_file_path(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub monitor_settings: MonitorSettings,
    #[serde(default)]
    pub websites: Vec<String>,
    #[serde(default)]
    pub website_groups: Vec<WebsiteGroup>,
    #[serde(default, rename = "Monitor")]
    pub monitor: MonitorConfig,
    #[serde(default)]
    pub webhooks: WebhookSettings,
    #[serde(default)]
    pub color_theme: ColorTheme,
    #[serde(default)]
    pub csv_export: CsvExportSettings,
    #[serde(default = "default_uptime_history_path")]
    pub uptime_history_path: String,
}

fn default_uptime_history_path() -> String { "uptime_history.json".to_string() }

// =========================================================================
// Result Model
// =========================================================================

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
}

// =========================================================================
// Uptime Persistence Models
// =========================================================================

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

// =========================================================================
// Config Operations
// =========================================================================

pub fn get_default_config() -> Config {
    Config {
        monitor_settings: MonitorSettings::default(),
        websites: vec![
            "https://ya.ru".to_string(),
            "https://google.com".to_string(),
            "https://example.com".to_string(),
            "https://vk.com".to_string(),
            "https://youtube.com".to_string(),
            "https://github.com".to_string(),
            "https://steamcommunity.com".to_string(),
            "https://store.steampowered.com".to_string(),
            "https://twitch.tv".to_string(),
            "https://reddit.com".to_string(),
            "https://wikipedia.org".to_string(),
            "https://x.com".to_string(),
            "https://www.gosuslugi.ru/".to_string(),
            "https://www.gov.ru/".to_string(),
            "https://www.mos.ru/".to_string(),
            "https://rkn.gov.ru/".to_string(),
            "https://www.nalog.gov.ru/".to_string(),
            "https://yandex.ru/maps/".to_string(),
            "https://www.kinopoisk.ru/".to_string(),
            "https://www.sberbank.ru/".to_string(),
            "https://www.vtb.ru/".to_string(),
            "https://alfabank.ru/".to_string(),
            "https://ok.ru/".to_string(),
            "https://www.ozon.ru/".to_string(),
            "https://www.wildberries.ru/".to_string(),
            "https://www.avito.ru/".to_string(),
            "https://lenta.ru/".to_string(),
            "https://www.rbc.ru/".to_string(),
            "https://tass.ru/".to_string(),
            "https://rutube.ru/".to_string(),
            "https://dzen.ru/".to_string(),
            "https://www.instagram.com/".to_string(),
            "https://www.facebook.com/".to_string(),
            "https://www.linkedin.com/".to_string(),
            "https://discord.com/".to_string(),
            "https://www.dailymotion.com/".to_string(),
            "https://soap2day.day/".to_string(),
            "https://rutracker.org/".to_string(),
            "https://www.torproject.org/".to_string(),
            "https://protonvpn.com/".to_string(),
            "https://www.deepl.com/".to_string(),
            "https://www.patreon.com/".to_string(),
            "https://www.bbc.com/russian".to_string(),
            "https://meduza.io/".to_string(),
            "https://www.dw.com/ru/".to_string(),
        ],
        monitor: MonitorConfig::default(),
        webhooks: WebhookSettings::default(),
        color_theme: ColorTheme::default(),
        csv_export: CsvExportSettings::default(),
        uptime_history_path: "uptime_history.json".to_string(),
        website_groups: Vec::new(),
    }
}

pub fn load_or_create_config(path: &Path) -> Config {
    let def = get_default_config();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(mut config) = serde_json::from_str::<Config>(&content) {
                // Validate and clamp settings
                config.monitor_settings.interval = config.monitor_settings.interval.clamp(1, 86400);
                config.monitor_settings.timeout = config.monitor_settings.timeout.clamp(1, 300);
                config.monitor_settings.retries_max = config.monitor_settings.retries_max.clamp(0, 5);
                
                if config.monitor_settings.valid_status_codes.is_empty() {
                    config.monitor_settings.valid_status_codes = def.monitor_settings.valid_status_codes.clone();
                }
                config.monitor_settings.valid_status_codes.sort_unstable();
                config.monitor_settings.valid_status_codes.dedup();

                if config.monitor_settings.warn_status_codes.is_empty() {
                    config.monitor_settings.warn_status_codes = def.monitor_settings.warn_status_codes.clone();
                }
                config.monitor_settings.warn_status_codes.sort_unstable();
                config.monitor_settings.warn_status_codes.dedup();

                let sm = &config.monitor_settings.sorted;
                if sm != "status" && sm != "url" && sm != "duration" {
                    config.monitor_settings.sorted = "status".to_string();
                }

                // Filter out invalid URLs
                let validate_url = |url: &str| -> bool {
                    if url.trim().is_empty() { return false; }
                    if let Ok(parsed) = reqwest::Url::parse(url) {
                        parsed.scheme() == "http" || parsed.scheme() == "https"
                    } else {
                        false
                    }
                };

                config.websites.retain(|u| {
                    let ok = validate_url(u);
                    if !ok {
                        println!("\x1b[33m[ПРЕДУПРЕЖДЕНИЕ] Невалидный URL пропущен: {}\x1b[0m", u);
                    }
                    ok
                });

                for group in &mut config.website_groups {
                    let mut valid_sites = Vec::new();
                    for site in &group.sites {
                        if validate_url(&site.url) {
                            valid_sites.push(site.clone());
                        } else {
                            println!(
                                "\x1b[33m[ПРЕДУПРЕЖДЕНИЕ] Невалидный URL в группе \"{}\" пропущен: {}\x1b[0m",
                                group.name, site.url
                            );
                        }
                    }
                    group.sites = valid_sites;
                }

                if config.websites.is_empty() && config.website_groups.is_empty() {
                    config.websites = def.websites.clone();
                }

                return config;
            }
        }
    }
    // Create new default config if not existing or corrupt
    let json_str = serde_json::to_string_pretty(&def).unwrap_or_default();
    let _ = fs::write(path, json_str);
    def
}

pub fn save_config(config: &Config, path: &Path) {
    if let Ok(json_str) = serde_json::to_string_pretty(config) {
        let _ = fs::write(path, json_str);
    }
}

// =========================================================================
// DNS and Ping helpers
// =========================================================================

pub async fn resolve_dns_async(host: &str, retries_max: u32, delays: &[u64]) -> Option<String> {
    for attempt in 0..=retries_max {
        let host_port = format!("{}:80", host);
        match tokio::net::lookup_host(&host_port).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    return Some(addr.ip().to_string());
                }
            }
            Err(_) => {
                if attempt >= retries_max {
                    return None;
                }
                let idx = (attempt as usize).min(delays.len() - 1);
                tokio::time::sleep(Duration::from_millis(delays[idx])).await;
            }
        }
    }
    None
}

#[cfg(windows)]
pub fn ping_host(host: &str) -> String {
    use std::net::ToSocketAddrs;
    let addr = match format!("{}:0", host).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => return "ICMP_EX".to_string(),
        },
        Err(_) => return "ICMP_EX".to_string(),
    };
    
    // Attempt ping using winping crate
    match winping::Pinger::new() {
        Ok(pinger) => {
            let mut buffer = winping::Buffer::new();
            match pinger.send(addr, &mut buffer) {
                Ok(_) => "".to_string(),
                Err(_) => "ICMP".to_string(),
            }
        }
        Err(_) => "ICMP_EX".to_string(),
    }
}

#[cfg(not(windows))]
pub fn ping_host(_host: &str) -> String {
    "".to_string()
}

// =========================================================================
// Website accessibility checker
// =========================================================================

// =========================================================================
// RKN Censorship Diagnostics (Native rkn-check implementation)
// =========================================================================

pub async fn resolve_system_all(host: &str) -> Vec<String> {
    let host_port = format!("{}:80", host);
    let mut ips = Vec::new();
    if let Ok(addrs) = tokio::net::lookup_host(&host_port).await {
        for addr in addrs {
            ips.push(addr.ip().to_string());
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

pub fn build_proxied_client(
    proxy_url: &str,
    proxy_username: &str,
    proxy_password: &str,
    timeout_secs: u64,
) -> Result<reqwest::Client, reqwest::Error> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(60));
    
    if !proxy_url.trim().is_empty() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            let mut proxy = proxy;
            if !proxy_username.is_empty() {
                proxy = proxy.basic_auth(proxy_username, proxy_password);
            } else if let Ok(url) = reqwest::Url::parse(proxy_url) {
                let username = url.username();
                let password = url.password();
                if !username.is_empty() {
                    proxy = proxy.basic_auth(username, password.unwrap_or(""));
                }
            }
            builder = builder.proxy(proxy);
        }
    }
    builder.build()
}

pub async fn resolve_doh_all(
    client: &reqwest::Client,
    host: &str,
    doh_server: &str,
    timeout_duration: Duration,
    proxy_url: &str,
    proxy_username: &str,
    proxy_password: &str,
) -> Vec<String> {
    let doh_client = if !proxy_url.trim().is_empty() {
        build_proxied_client(proxy_url, proxy_username, proxy_password, timeout_duration.as_secs()).unwrap_or_else(|_| client.clone())
    } else {
        client.clone()
    };
    
    let url = if doh_server.contains('?') {
        format!("{}&name={}&type=A", doh_server, host)
    } else {
        format!("{}?name={}&type=A", doh_server, host)
    };
    
    let mut ips = Vec::new();
    let req = doh_client.get(&url)
        .header("Accept", "application/dns-json")
        .timeout(timeout_duration);
    if let Ok(resp) = req.send().await {
        #[derive(serde::Deserialize)]
        struct Answer {
            #[serde(rename = "type")]
            ans_type: u16,
            data: String,
        }
        #[derive(serde::Deserialize)]
        struct DohResponse {
            #[serde(rename = "Answer")]
            answer: Option<Vec<Answer>>,
        }
        if let Ok(doh_resp) = resp.json::<DohResponse>().await {
            if let Some(answers) = doh_resp.answer {
                for ans in answers {
                    if ans.ans_type == 1 { // A record
                        ips.push(ans.data);
                    }
                }
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

pub async fn check_tcp(host: &str, timeout_duration: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    let addr_str = format!("{}:443", host);
    let addrs: Vec<_> = match tokio::net::lookup_host(&addr_str).await {
        Ok(iter) => iter.collect(),
        Err(e) => return Err(format!("DNS resolution failed: {}", e)),
    };
    if addrs.is_empty() {
        return Err("No IP addresses found".to_string());
    }
    
    let connect_future = tokio::net::TcpStream::connect(&addrs[0]);
    match tokio::time::timeout(timeout_duration, connect_future).await {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(e)) => {
            let err_msg = e.to_string().to_lowercase();
            if err_msg.contains("reset") || err_msg.contains("abort") || err_msg.contains("refused") {
                Err("connection reset".to_string())
            } else {
                Err(e.to_string())
            }
        }
        Err(_) => Err("timeout".to_string()),
    }
}

pub async fn check_tls(host: &str, timeout_duration: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    let addr_str = format!("{}:443", host);
    let addrs: Vec<_> = match tokio::net::lookup_host(&addr_str).await {
        Ok(iter) => iter.collect(),
        Err(e) => return Err(format!("DNS resolution failed: {}", e)),
    };
    if addrs.is_empty() {
        return Err("No IP addresses found".to_string());
    }
    
    let connect_future = tokio::net::TcpStream::connect(&addrs[0]);
    let stream = match tokio::time::timeout(timeout_duration, connect_future).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("TCP connect failed: {}", e)),
        Err(_) => return Err("TCP timeout".to_string()),
    };
    
    let std_stream = match stream.into_std() {
        Ok(s) => s,
        Err(_) => return Err("Failed to convert TcpStream to std".to_string()),
    };
    let _ = std_stream.set_nonblocking(false);
    
    let host_owned = host.to_string();
    let handshake_task = tokio::task::spawn_blocking(move || -> Result<Duration, String> {
        let connector = native_tls::TlsConnector::builder().build().map_err(|e| e.to_string())?;
        match connector.connect(&host_owned, std_stream) {
            Ok(_) => Ok(start.elapsed()),
            Err(e) => {
                let err_msg = e.to_string().to_lowercase();
                if err_msg.contains("reset") || err_msg.contains("abort") {
                    Err("connection reset".to_string())
                } else if err_msg.contains("timeout") {
                    Err("timeout".to_string())
                } else {
                    Err(e.to_string())
                }
            }
        }
    });
    
    match tokio::time::timeout(timeout_duration, handshake_task).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => Err(format!("Handshake task panicked: {}", e)),
        Err(_) => Err("timeout".to_string()),
    }
}

const STUB_MARKERS: &[&str] = &[
    "доступ ограничен",
    "доступ к запрашиваемому ресурсу",
    "решению роскомнадзора",
    "решением суда",
    "заблокирован",
    "blocked by roskomnadzor",
    "blocked by rkn",
    "rkn.gov.ru/org/register",
    "единый реестр",
    "запрещен",
];

pub fn looks_like_stub(body: &str) -> bool {
    let lower = body.to_lowercase();
    STUB_MARKERS.iter().any(|&marker| lower.contains(marker))
}

// =========================================================================
// Website accessibility checker
// =========================================================================

pub async fn check_website_async(
    client: &reqwest::Client,
    raw_url: &str,
    custom_headers: &HashMap<String, String>,
    config: &Config,
) -> WebsiteResult {
    let mut result = WebsiteResult {
        url: raw_url.to_string(),
        ip: "N/A".to_string(),
        status: "INIT".to_string(),
        code: "".to_string(),
        error_type: "".to_string(),
        duration_ms: 0,
        retries: 0,
        http_method: "GET".to_string(),
        group_name: "".to_string(),
        proxy_ok: false,
    };

    let parsed_url = match reqwest::Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => {
            result.status = "URL_ERROR".to_string();
            result.code = "ERR".to_string();
            result.error_type = "URL".to_string();
            return result;
        }
    };

    let host = match parsed_url.host_str() {
        Some(h) => h,
        None => {
            result.status = "URL_ERROR".to_string();
            result.code = "ERR".to_string();
            result.error_type = "URL".to_string();
            return result;
        }
    };

    let delays = [250, 750, 1500];

    // 1. Parallel DNS (System vs DoH) to detect DNS hijacking/poisoning
    let doh_timeout = Duration::from_secs(config.monitor_settings.timeout.max(1));
    let sys_dns_task = resolve_system_all(host);
    let doh_dns_task = resolve_doh_all(
        client,
        host,
        &config.monitor_settings.doh_server,
        doh_timeout,
        &config.monitor_settings.proxy_url,
        &config.monitor_settings.proxy_username,
        &config.monitor_settings.proxy_password,
    );
    let (sys_ips, doh_ips) = tokio::join!(sys_dns_task, doh_dns_task);

    // If system DNS fails completely but DoH succeeds, it is DNS poisoning block
    if sys_ips.is_empty() && !doh_ips.is_empty() {
        result.status = "DNS_BLOCK".to_string();
        result.code = "DNS".to_string();
        result.error_type = "DNS".to_string();
        
        // Attempt proxy fallback check
        if !config.monitor_settings.proxy_url.trim().is_empty() {
            if let Ok(proxied_client) = build_proxied_client(
                &config.monitor_settings.proxy_url,
                &config.monitor_settings.proxy_username,
                &config.monitor_settings.proxy_password,
                config.monitor_settings.timeout,
            ) {
                if let Ok(resp) = proxied_client.get(parsed_url.clone()).send().await {
                    let status_code = resp.status().as_u16() as i32;
                    let is_ok = config.monitor_settings.valid_status_codes.contains(&status_code);
                    let is_stub = if let Ok(body) = resp.text().await { looks_like_stub(&body) } else { false };
                    if is_ok && !is_stub {
                        result.proxy_ok = true;
                    }
                }
            }
        }
        return result;
    }

    if sys_ips.is_empty() && doh_ips.is_empty() {
        result.status = "DNS_ERROR".to_string();
        result.code = "ERR".to_string();
        result.error_type = "DNS".to_string();
        return result;
    }

    // Capture first IP
    result.ip = sys_ips[0].clone();

    // Check disjoint address sets (DNS mismatch)
    let dns_mismatch = if !sys_ips.is_empty() && !doh_ips.is_empty() {
        sys_ips.iter().all(|ip| !doh_ips.contains(ip))
    } else {
        false
    };

    // Perform ping in blocking thread pool (if enabled)
    let host_owned = host.to_string();
    let ping_enabled = config.monitor_settings.ping_enabled;
    let ping_task = tokio::task::spawn_blocking(move || {
        if ping_enabled {
            ping_host(&host_owned)
        } else {
            "".to_string()
        }
    });
    let ping_err = ping_task.await.unwrap_or_else(|_| "ICMP_EX".to_string());
    if !ping_err.is_empty() {
        result.error_type = ping_err;
    }

    let attempts = config.monitor_settings.retries_max + 1;
    let mut tries = 0;
    let mut method_used = if config.monitor_settings.use_head_first { "HEAD" } else { "GET" };
    let mut last_err = None;

    let start_instant = Instant::now();

    while tries < attempts {
        tries += 1;
        let method = if method_used == "HEAD" {
            reqwest::Method::HEAD
        } else {
            reqwest::Method::GET
        };

        let mut req = client.request(method, parsed_url.clone());
        for (k, v) in custom_headers {
            req = req.header(k, v);
        }

        match req.send().await {
            Ok(resp) => {
                let status_code = resp.status().as_u16() as i32;

                if method_used == "HEAD" && (status_code == 405 || status_code == 501) {
                    method_used = "GET";
                    if tries < attempts {
                        let delay_ms = delays[(tries as usize - 1).min(delays.len() - 1)].min(2000);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    continue;
                }

                result.duration_ms = start_instant.elapsed().as_millis() as u64;
                result.retries = tries - 1;
                result.http_method = method_used.to_string();
                result.code = status_code.to_string();

                // Check HTTP 451 (Unavailable For Legal Reasons)
                if status_code == 451 {
                    result.status = "HTTP_STUB".to_string();
                    result.code = "451".to_string();
                    result.error_type = "HTTP".to_string();
                    
                    // Attempt proxy fallback check
                    if !config.monitor_settings.proxy_url.trim().is_empty() {
                        if let Ok(proxied_client) = build_proxied_client(
                            &config.monitor_settings.proxy_url,
                            &config.monitor_settings.proxy_username,
                            &config.monitor_settings.proxy_password,
                            config.monitor_settings.timeout,
                        ) {
                            if let Ok(resp) = proxied_client.get(parsed_url.clone()).send().await {
                                let status_code = resp.status().as_u16() as i32;
                                let is_ok = config.monitor_settings.valid_status_codes.contains(&status_code);
                                let is_stub = if let Ok(body) = resp.text().await { looks_like_stub(&body) } else { false };
                                if is_ok && !is_stub {
                                    result.proxy_ok = true;
                                }
                            }
                        }
                    }
                    return result;
                }

                // Check response body snippet for block stub indicators
                if let Ok(body_text) = resp.text().await {
                    if looks_like_stub(&body_text) {
                        result.status = "HTTP_STUB".to_string();
                        result.code = "STUB".to_string();
                        result.error_type = "HTTP".to_string();
                        
                        // Attempt proxy fallback check
                        if !config.monitor_settings.proxy_url.trim().is_empty() {
                            if let Ok(proxied_client) = build_proxied_client(
                                &config.monitor_settings.proxy_url,
                                &config.monitor_settings.proxy_username,
                                &config.monitor_settings.proxy_password,
                                config.monitor_settings.timeout,
                            ) {
                                if let Ok(resp) = proxied_client.get(parsed_url.clone()).send().await {
                                    let status_code = resp.status().as_u16() as i32;
                                    let is_ok = config.monitor_settings.valid_status_codes.contains(&status_code);
                                    let is_stub = if let Ok(body) = resp.text().await { looks_like_stub(&body) } else { false };
                                    if is_ok && !is_stub {
                                        result.proxy_ok = true;
                                    }
                                }
                            }
                        }
                        return result;
                    }
                }

                let is_ok = config.monitor_settings.valid_status_codes.contains(&status_code);
                let is_warn = !is_ok && config.monitor_settings.warn_status_codes.contains(&status_code);

                if is_ok {
                    result.status = "OK".to_string();
                    result.error_type = if dns_mismatch { "DNS_MISMATCH".to_string() } else { "".to_string() };
                } else if is_warn {
                    result.status = "WARN".to_string();
                    result.error_type = "PARTIAL".to_string();
                } else {
                    result.status = "HTTP_ERROR".to_string();
                    result.error_type = "HTTP".to_string();
                }
                return result;
            }
            Err(e) => {
                let is_transient = if let Some(status) = e.status() {
                    let s = status.as_u16();
                    s == 408 || s == 425 || s == 429 || (s >= 500 && s <= 504)
                } else {
                    true
                };

                last_err = Some(e);
                if is_transient && tries < attempts {
                    let delay_ms = delays[(tries as usize - 1).min(delays.len() - 1)].min(2000);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                } else {
                    break;
                }
            }
        }
    }

    result.duration_ms = start_instant.elapsed().as_millis() as u64;
    result.retries = tries.saturating_sub(1);
    result.http_method = method_used.to_string();

    // If HTTP failed, execute TCP and TLS diagnostics to pinpoint the censorship layer
    let timeout_val = Duration::from_secs(config.monitor_settings.timeout.max(1));
    match check_tcp(host, timeout_val).await {
        Ok(_) => {
            // TCP connected successfully, check TLS
            match check_tls(host, timeout_val).await {
                Ok(_) => {
                    // TCP and TLS are fine, fall back to standard HTTP error mappings
                    if let Some(err) = last_err {
                        let err_str = err.to_string().to_lowercase();
                        if err.is_timeout() {
                            result.status = "TIMEOUT".to_string();
                            result.code = "T/O".to_string();
                            result.error_type = "TIMEOUT".to_string();
                        } else if err.is_redirect() {
                            result.status = "REDIRECT_LOOP".to_string();
                            result.code = "3xx".to_string();
                            result.error_type = "REDIRECT".to_string();
                        } else if err_str.contains("ssl") || err_str.contains("tls") || err_str.contains("certificate") {
                            result.status = "SSL_ERROR".to_string();
                            result.code = "SSL".to_string();
                            result.error_type = "SSL".to_string();
                        } else {
                            result.status = "CONN_ERROR".to_string();
                            result.code = "ERR".to_string();
                            result.error_type = "NETWORK".to_string();
                        }
                    } else {
                        result.status = "CONN_ERROR".to_string();
                        result.code = "ERR".to_string();
                        result.error_type = "NETWORK".to_string();
                    }
                }
                Err(tls_err) => {
                    let err = tls_err.to_lowercase();
                    if err.contains("reset") || err.contains("abort") {
                        result.status = "TLS_BLOCK".to_string();
                        result.code = "RST".to_string();
                        result.error_type = "SSL".to_string();
                    } else if err.contains("timeout") {
                        result.status = "TLS_BLOCK".to_string();
                        result.code = "T/O".to_string();
                        result.error_type = "SSL".to_string();
                    } else {
                        result.status = "SSL_ERROR".to_string();
                        result.code = "SSL".to_string();
                        result.error_type = "SSL".to_string();
                    }
                }
            }
        }
        Err(tcp_err) => {
            let err = tcp_err.to_lowercase();
            if err.contains("timeout") {
                result.status = "TCP_BLOCK".to_string();
                result.code = "T/O".to_string();
                result.error_type = "TIMEOUT".to_string();
            } else if err.contains("reset") || err.contains("abort") {
                result.status = "TCP_RESET".to_string();
                result.code = "RST".to_string();
                result.error_type = "NETWORK".to_string();
            } else {
                result.status = "CONN_ERROR".to_string();
                result.code = "ERR".to_string();
                result.error_type = "NETWORK".to_string();
            }
        }
    }

    // If blocked, check if it can be bypassed via proxy
    if result.status != "OK" && result.status != "WARN" && !config.monitor_settings.proxy_url.trim().is_empty() {
        if let Ok(proxied_client) = build_proxied_client(
            &config.monitor_settings.proxy_url,
            &config.monitor_settings.proxy_username,
            &config.monitor_settings.proxy_password,
            config.monitor_settings.timeout,
        ) {
            let method = if method_used == "HEAD" {
                reqwest::Method::HEAD
            } else {
                reqwest::Method::GET
            };
            let mut req = proxied_client.request(method, parsed_url.clone());
            for (k, v) in custom_headers {
                req = req.header(k, v);
            }
            if let Ok(resp) = req.send().await {
                let status_code = resp.status().as_u16() as i32;
                let is_ok = config.monitor_settings.valid_status_codes.contains(&status_code);
                let is_stub = if let Ok(body) = resp.text().await { looks_like_stub(&body) } else { false };
                if is_ok && !is_stub {
                    result.proxy_ok = true;
                }
            }
        }
    }

    result
}

// =========================================================================
// Logging Results
// =========================================================================

#[derive(Serialize)]
struct LogRecord<'a> {
    timestamp: String,
    results: Vec<LogResultEntry<'a>>,
}

#[derive(Serialize)]
struct LogResultEntry<'a> {
    url: &'a str,
    ip: &'a str,
    status: &'a str,
    code: &'a str,
    duration_ms: u64,
    retries: u32,
    http_method: &'a str,
    group_name: &'a str,
}

pub fn get_current_log_path(base_path: &str, rotate_daily: bool, script_dir: &Path) -> PathBuf {
    let mut final_path = PathBuf::from(base_path);
    if rotate_daily {
        let date_str = Local::now().format("%Y-%m-%d").to_string();
        let ext = final_path.extension().and_then(|e| e.to_str()).unwrap_or("log");
        let name_no_ext = final_path.file_stem().and_then(|s| s.to_str()).unwrap_or("monitor");
        final_path = PathBuf::from(format!("{}_{}.{}", name_no_ext, date_str, ext));
    }
    script_dir.join(final_path)
}

pub fn rotate_log_if_needed(path: &Path, max_size_mb: u64) {
    if !path.exists() { return; }
    if let Ok(metadata) = fs::metadata(path) {
        let max_bytes = max_size_mb * 1024 * 1024;
        if metadata.len() < max_bytes { return; }
        
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("log");
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("monitor");

        for i in 1..=999 {
            let candidate = parent.join(format!("{}_{:03}.{}", file_stem, i, ext));
            if !candidate.exists() {
                let _ = fs::rename(path, candidate);
                break;
            }
        }
    }
}

pub async fn log_results_async(results: &[WebsiteResult], config: &Config, script_dir: &Path) {
    let path = get_current_log_path(&config.monitor.log_file_path, config.monitor.log_rotate_daily, script_dir);
    // Rotate blocks, execute on spawn_blocking
    let path_clone = path.clone();
    let max_size = config.monitor.log_max_size_mb;
    let _ = tokio::task::spawn_blocking(move || {
        rotate_log_if_needed(&path_clone, max_size);
    }).await;

    let log_entries = results.iter().map(|r| LogResultEntry {
        url: &r.url,
        ip: &r.ip,
        status: &r.status,
        code: &r.code,
        duration_ms: r.duration_ms,
        retries: r.retries,
        http_method: &r.http_method,
        group_name: &r.group_name,
    }).collect::<Vec<_>>();

    let log_record = LogRecord {
        timestamp: Local::now().to_rfc3339(),
        results: log_entries,
    };

    if let Ok(mut json) = serde_json::to_string(&log_record) {
        json.push('\n');
        // Append to file
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        if let Ok(mut file) = options.open(&path) {
            use std::io::Write;
            let _ = file.write_all(json.as_bytes());
        }
    }
}

// =========================================================================
// CSV Exporter
// =========================================================================

pub async fn export_csv_async(results: &[WebsiteResult], config: &Config, uptime_history: &HashMap<String, Vec<bool>>, script_dir: &Path) {
    let path = script_dir.join(&config.csv_export.file_path);
    let write_header = !path.exists();
    
    let path_clone = path.clone();
    let results_clone = results.to_vec();
    let history_clone = uptime_history.clone();

    let _ = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path_clone)?;
            
        let mut wtr = csv::WriterBuilder::new()
            .has_headers(write_header)
            .from_writer(file);

        if write_header {
            wtr.write_record(&[
                "Timestamp", "URL", "Group", "IP", "Status", "Code", "Method", "Retries", "DurationMs", "UptimePercent"
            ])?;
        }

        let ts = Local::now().to_rfc3339();
        for r in &results_clone {
            let uptime_percent = if let Some(h) = history_clone.get(&r.url) {
                let ok_count = h.iter().filter(|&&x| x).count();
                if !h.is_empty() {
                    (ok_count as f64 * 100.0 / h.len() as f64).round()
                } else {
                    0.0
                }
            } else {
                0.0
            };

            wtr.write_record(&[
                &ts,
                &r.url,
                &r.group_name,
                &r.ip,
                &r.status,
                &r.code,
                &r.http_method,
                &r.retries.to_string(),
                &r.duration_ms.to_string(),
                &format!("{:.2}", uptime_percent),
            ])?;
        }
        wtr.flush()?;
        Ok(())
    }).await;
}

// =========================================================================
// Webhook notifications
// =========================================================================

pub async fn send_telegram_webhook(client: &reqwest::Client, bot_token: &str, chat_id: &str, message: &str) {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML"
    });
    let _ = client.post(&url).json(&payload).send().await;
}

pub async fn send_discord_webhook(client: &reqwest::Client, url: &str, message: &str) {
    let is_down = message.contains("НЕДОСТУПЕН");
    let color = if is_down { 0xFF0000 } else { 0x00FF00 };
    let title = if is_down { "Сайт недоступен" } else { "Сайт восстановлен" };
    let payload = serde_json::json!({
        "embeds": [{
            "title": title,
            "description": message,
            "color": color
        }]
    });
    let _ = client.post(url).json(&payload).send().await;
}

pub async fn send_slack_webhook(client: &reqwest::Client, url: &str, message: &str) {
    let payload = serde_json::json!({
        "text": message
    });
    let _ = client.post(url).json(&payload).send().await;
}

pub async fn send_all_webhooks(client: &reqwest::Client, config: &Config, message: &str) {
    if !config.webhooks.enabled { return; }
    
    let mut handles = Vec::new();

    if !config.webhooks.telegram_bot_token.is_empty() && !config.webhooks.telegram_chat_id.is_empty() {
        let client_clone = client.clone();
        let token = config.webhooks.telegram_bot_token.clone();
        let chat_id = config.webhooks.telegram_chat_id.clone();
        let msg = message.to_string();
        handles.push(tokio::spawn(async move {
            send_telegram_webhook(&client_clone, &token, &chat_id, &msg).await;
        }));
    }

    if !config.webhooks.discord_webhook_url.is_empty() {
        let client_clone = client.clone();
        let url = config.webhooks.discord_webhook_url.clone();
        let msg = message.to_string();
        handles.push(tokio::spawn(async move {
            send_discord_webhook(&client_clone, &url, &msg).await;
        }));
    }

    if !config.webhooks.slack_webhook_url.is_empty() {
        let client_clone = client.clone();
        let url = config.webhooks.slack_webhook_url.clone();
        let msg = message.to_string();
        handles.push(tokio::spawn(async move {
            send_slack_webhook(&client_clone, &url, &msg).await;
        }));
    }

    if !handles.is_empty() {
        // Run all webhooks concurrently, with a 10s timeout overall
        let combined = async {
            for h in handles {
                let _ = h.await;
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(10), combined).await;
    }
}

// =========================================================================
// Uptime Persistence
// =========================================================================

pub fn load_uptime_history(config: &Config, script_dir: &Path) -> HashMap<String, Vec<bool>> {
    let path = script_dir.join(&config.uptime_history_path);
    let mut history = HashMap::new();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(file_data) = serde_json::from_str::<UptimeHistoryFile>(&content) {
                for (url, data) in file_data.sites {
                    let trimmed = if data.history.len() > 1440 {
                        data.history[data.history.len() - 1440..].to_vec()
                    } else {
                        data.history
                    };
                    history.insert(url, trimmed);
                }
            }
        }
    }
    history
}

pub fn save_uptime_history(config: &Config, history: &HashMap<String, Vec<bool>>, script_dir: &Path) {
    let path = script_dir.join(&config.uptime_history_path);
    let tmp_path = path.with_extension("tmp");
    
    let mut file_data = UptimeHistoryFile {
        version: 1,
        last_updated: Local::now().to_rfc3339(),
        sites: HashMap::new(),
    };

    for (url, hist) in history {
        let trimmed_hist = if hist.len() > 1440 {
            hist[hist.len() - 1440..].to_vec()
        } else {
            hist.clone()
        };
        let ok_count = trimmed_hist.iter().filter(|&&x| x).count();
        let last_status = if let Some(&last) = trimmed_hist.last() {
            if last { "OK".to_string() } else { "ERROR".to_string() }
        } else {
            "".to_string()
        };

        file_data.sites.insert(url.clone(), UptimeSiteData {
            checks_total: trimmed_hist.len(),
            checks_ok: ok_count,
            last_status,
            last_check: Local::now().to_rfc3339(),
            history: trimmed_hist,
        });
    }

    if let Ok(json_str) = serde_json::to_string_pretty(&file_data) {
        if fs::write(&tmp_path, json_str).is_ok() {
            let _ = fs::rename(&tmp_path, path);
        }
    }
}
