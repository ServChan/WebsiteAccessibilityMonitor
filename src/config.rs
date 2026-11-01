use std::collections::HashSet;
use std::fs;
use std::path::Path;

use reqwest::header::{HeaderName, HeaderValue};

use crate::model::{
    Config, MonitorTarget, WebsiteEntry, parse_clock, parse_weekday, target_identity,
};
use crate::notice;
use crate::storage::write_atomic;

pub fn default_config() -> Config {
    Config {
        monitor_settings: Default::default(),
        websites: vec![
            "https://example.com".into(),
            "https://github.com".into(),
            "https://wikipedia.org".into(),
        ],
        website_groups: Vec::new(),
        logging: Default::default(),
        webhooks: Default::default(),
        color_theme: Default::default(),
        csv_export: Default::default(),
        uptime_history_path: "uptime_history.json".into(),
        maintenance_windows: Vec::new(),
    }
}

fn valid_http_url(value: &str) -> bool {
    reqwest::Url::parse(value)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
}

/// Turns user input such as `example.com/health` into a checked absolute URL.
/// A missing scheme defaults to HTTPS.
pub fn normalize_target_url(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Адрес не указан. Введите, например, https://example.com".into());
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = reqwest::Url::parse(&candidate)
        .map_err(|error| format!("Не удалось разобрать адрес: {error}. Проверьте написание."))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "Схема {}:// не поддерживается. Используйте http:// или https://",
            url.scheme()
        ));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("В адресе нет имени хоста. Пример: https://example.com".into());
    }
    Ok(url.to_string())
}

fn sanitize_codes(codes: &mut Vec<u16>, fallback: &[u16]) {
    codes.retain(|code| (100..=599).contains(code));
    if codes.is_empty() {
        codes.extend_from_slice(fallback);
    }
    codes.sort_unstable();
    codes.dedup();
}

/// Drops an entry with an unusable URL and its invalid headers; returns whether to keep it.
fn sanitize_entry(site: &mut WebsiteEntry, group: &str, warn: &impl Fn(String)) -> bool {
    site.url = site.url.trim().to_string();
    if !valid_http_url(&site.url) {
        if group.is_empty() {
            warn(format!("Невалидный URL пропущен: {}", site.url));
        } else {
            warn(format!(
                "Невалидный URL в группе \"{group}\" пропущен: {}",
                site.url
            ));
        }
        return false;
    }
    site.headers.retain(|name, value| {
        let valid =
            HeaderName::from_bytes(name.as_bytes()).is_ok() && HeaderValue::from_str(value).is_ok();
        if !valid {
            warn(format!(
                "Некорректный HTTP-заголовок для {} пропущен: {}",
                site.url, name
            ));
        }
        valid
    });
    site.expect_text = site.expect_text.trim().to_string();
    site.slow_threshold_ms = site.slow_threshold_ms.map(|value| value.min(600_000));
    true
}

fn sanitize_config(mut config: Config, defaults: &Config, report: bool) -> Config {
    let warn = |message: String| {
        if report {
            notice::warn(message);
        }
    };
    let settings = &mut config.monitor_settings;
    settings.interval = settings.interval.clamp(1, 86_400);
    settings.timeout = settings.timeout.clamp(1, 300);
    settings.retries_max = settings.retries_max.min(5);
    settings.max_concurrency = settings.max_concurrency.clamp(1, 512);
    settings.response_body_limit_kb = settings.response_body_limit_kb.clamp(1, 1_024);

    sanitize_codes(
        &mut settings.valid_status_codes,
        &defaults.monitor_settings.valid_status_codes,
    );
    sanitize_codes(
        &mut settings.warn_status_codes,
        &defaults.monitor_settings.warn_status_codes,
    );
    let valid_codes = settings.valid_status_codes.clone();
    settings
        .warn_status_codes
        .retain(|code| !valid_codes.contains(code));

    if !matches!(settings.sorted.as_str(), "status" | "url" | "duration") {
        settings.sorted = "status".into();
    }
    settings.doh_server = settings.doh_server.trim().to_string();
    if reqwest::Url::parse(&settings.doh_server)
        .ok()
        .is_none_or(|url| url.scheme() != "https" || url.host_str().is_none())
    {
        if !settings.doh_server.is_empty() {
            warn(format!(
                "Некорректный doh_server заменён на {}",
                defaults.monitor_settings.doh_server
            ));
        }
        settings.doh_server = defaults.monitor_settings.doh_server.clone();
    }
    settings.proxy_url = settings.proxy_url.trim().to_string();
    if !settings.proxy_url.is_empty() && reqwest::Proxy::all(&settings.proxy_url).is_err() {
        warn("Некорректный proxy_url отключён".into());
        settings.proxy_url.clear();
    }

    config.logging.log_max_size_mb = config.logging.log_max_size_mb.clamp(1, 10_240);
    config.webhooks.min_failures_before_alert =
        config.webhooks.min_failures_before_alert.clamp(1, 1_000);
    for value in [
        &mut config.webhooks.telegram_bot_token,
        &mut config.webhooks.telegram_chat_id,
        &mut config.webhooks.discord_webhook_url,
        &mut config.webhooks.slack_webhook_url,
    ] {
        *value = value.trim().to_string();
    }

    settings.slow_threshold_ms = settings.slow_threshold_ms.min(600_000);
    settings.cert_warn_days = settings.cert_warn_days.min(365);
    settings.domain_warn_days = settings.domain_warn_days.clamp(1, 365);

    config
        .websites
        .retain_mut(|site| sanitize_entry(site, "", &warn));
    for group in &mut config.website_groups {
        group.interval = group.interval.clamp(1, 86_400);
        let name = group.name.clone();
        group
            .sites
            .retain_mut(|site| sanitize_entry(site, &name, &warn));
    }
    config
        .website_groups
        .retain(|group| !group.sites.is_empty());

    config.maintenance_windows.retain_mut(|window| {
        window.start = window.start.trim().to_string();
        window.end = window.end.trim().to_string();
        if parse_clock(&window.start).is_none() || parse_clock(&window.end).is_none() {
            warn(format!(
                "Окно обслуживания «{}» пропущено: время задаётся как ЧЧ:ММ",
                window.label()
            ));
            return false;
        }
        let label = window.label();
        window.days.retain(|day| {
            let known = parse_weekday(day).is_some();
            if !known {
                warn(format!(
                    "Неизвестный день «{day}» в окне обслуживания «{label}» пропущен; используйте mon..sun или пн..вс"
                ));
            }
            known
        });
        true
    });

    config
}

/// Loads `path`, creating it with defaults when absent.
///
/// `Err` means the file exists but cannot be used; it is left untouched so the user can fix
/// it, and callers must not overwrite it with defaults.
pub fn try_load_config(path: &Path) -> Result<Config, String> {
    let defaults = default_config();
    if !path.exists() {
        if let Err(error) = save_config(&defaults, path) {
            notice::error(error);
        }
        return Ok(defaults);
    }
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Не удалось прочитать {}: {error}", path.display()))?;
    // Notepad on older Windows saves UTF-8 with a BOM, which serde_json rejects.
    let config = serde_json::from_str::<Config>(content.trim_start_matches('\u{feff}')).map_err(
        |error| {
            format!(
                "{} повреждён и оставлен без изменений: {error}",
                path.display()
            )
        },
    )?;
    Ok(sanitize_config(config, &defaults, true))
}

/// Like [`try_load_config`], but falls back to defaults. A corrupt file is never overwritten.
pub fn load_or_create_config(path: &Path) -> Config {
    try_load_config(path).unwrap_or_else(|error| {
        notice::error(format!("{error}. Используются настройки по умолчанию."));
        default_config()
    })
}

/// Sanitizes and atomically writes the configuration. Returns what was actually written,
/// or a user-facing error message.
pub fn save_config(config: &Config, path: &Path) -> Result<Config, String> {
    let sanitized = sanitize_config(config.clone(), &default_config(), false);
    let json = serde_json::to_vec_pretty(&sanitized)
        .map_err(|error| format!("Не удалось сериализовать настройки: {error}"))?;
    write_atomic(path, &json)
        .map_err(|error| format!("Не удалось сохранить {}: {error}", path.display()))?;
    Ok(sanitized)
}

/// Adds a top-level website. Returns `false` when the URL is already monitored.
pub fn add_website(config: &mut Config, url: &str) -> bool {
    if config.websites.iter().any(|existing| existing.url == url) {
        return false;
    }
    config.websites.push(WebsiteEntry::new(url));
    true
}

/// The configuration entry behind a target identity, wherever it is defined.
pub fn find_entry_mut<'a>(config: &'a mut Config, identity: &str) -> Option<&'a mut WebsiteEntry> {
    if let Some(index) = config.websites.iter().position(|site| site.url == identity) {
        return config.websites.get_mut(index);
    }
    config.website_groups.iter_mut().find_map(|group| {
        let name = &group.name;
        group
            .sites
            .iter_mut()
            .find(|site| target_identity(name, &site.url) == identity)
    })
}

/// Sets (or clears with an empty string) the text a site's response must contain.
pub fn set_expect_text(config: &mut Config, identity: &str, text: &str) -> bool {
    match find_entry_mut(config, identity) {
        Some(entry) => {
            entry.expect_text = text.trim().to_string();
            true
        }
        None => false,
    }
}

/// Removes the target with the given identity from `websites` or from its group.
/// Groups left empty are dropped. Returns `false` when nothing matched.
pub fn remove_target(config: &mut Config, identity: &str) -> bool {
    let before = config.websites.len();
    config.websites.retain(|site| site.url != identity);
    if config.websites.len() != before {
        return true;
    }
    let mut removed = false;
    for group in &mut config.website_groups {
        let before = group.sites.len();
        let name = group.name.clone();
        group
            .sites
            .retain(|site| target_identity(&name, &site.url) != identity);
        removed |= group.sites.len() != before;
    }
    config
        .website_groups
        .retain(|group| !group.sites.is_empty());
    removed
}

pub fn configured_sites(config: &Config) -> Vec<MonitorTarget> {
    let mut targets = Vec::new();
    let mut exact_seen = HashSet::new();

    let target = |site: &WebsiteEntry, group: &str, interval: u64| MonitorTarget {
        url: site.url.clone(),
        group_name: group.to_string(),
        headers: site.headers.clone(),
        interval,
        expect_text: site.expect_text.clone(),
        slow_threshold_ms: site
            .slow_threshold_ms
            .unwrap_or(config.monitor_settings.slow_threshold_ms),
    };
    let sites = config
        .websites
        .iter()
        .map(|site| target(site, "", config.monitor_settings.interval))
        .chain(config.website_groups.iter().flat_map(|group| {
            group
                .sites
                .iter()
                .map(move |site| target(site, &group.name, group.interval))
        }));
    for site in sites {
        if exact_seen.insert(site.identity()) {
            targets.push(site);
        }
    }
    targets
}

pub fn history_capacity(interval_seconds: u64) -> usize {
    (86_400_u64.div_ceil(interval_seconds.max(1))).clamp(1, 86_400) as usize
}

pub fn redact_proxy_url(value: &str) -> String {
    if value.trim().is_empty() {
        return String::new();
    }
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return "<некорректный URL>".into();
    };
    if url.password().is_some() {
        let _ = url.set_password(Some("********"));
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_config_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, b"{ definitely invalid").unwrap();

        let config = load_or_create_config(&path);

        assert!(!config.websites.is_empty());
        assert_eq!(fs::read(&path).unwrap(), b"{ definitely invalid");
    }

    #[test]
    fn top_level_and_group_sites_are_combined() {
        let mut config = default_config();
        config.websites = vec!["https://example.com".into()];
        config.website_groups = vec![crate::WebsiteGroup {
            name: "API".into(),
            interval: 10,
            sites: vec!["https://example.net/health".into()],
        }];

        let targets = configured_sites(&config);

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[1].interval, 10);
    }

    #[test]
    fn per_site_options_reach_the_target() {
        let mut config = default_config();
        config.monitor_settings.slow_threshold_ms = 1_000;
        config.websites = vec![
            "https://a.example/".into(),
            crate::WebsiteEntry {
                slow_threshold_ms: Some(250),
                ..crate::WebsiteEntry::new("https://b.example/")
            },
        ];
        assert!(set_expect_text(
            &mut config,
            "https://a.example/",
            "  Welcome "
        ));

        let targets = configured_sites(&config);

        assert_eq!(targets[0].expect_text, "Welcome");
        assert_eq!(targets[0].slow_threshold_ms, 1_000);
        assert_eq!(targets[1].slow_threshold_ms, 250);
    }

    #[test]
    fn invalid_maintenance_windows_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            r#"{"websites": ["https://example.com"], "maintenance_windows": [
                {"start": "02:00", "end": "03:00", "days": ["пн", "someday"]},
                {"start": "25:00", "end": "03:00"}
            ]}"#,
        )
        .unwrap();

        let config = load_or_create_config(&path);

        assert_eq!(config.maintenance_windows.len(), 1);
        assert_eq!(config.maintenance_windows[0].days, vec!["пн".to_string()]);
    }

    #[test]
    fn history_capacity_tracks_real_day() {
        assert_eq!(history_capacity(60), 1_440);
        assert_eq!(history_capacity(30), 2_880);
        assert_eq!(history_capacity(86_400), 1);
    }

    #[test]
    fn proxy_password_is_redacted_for_ui() {
        assert_eq!(
            redact_proxy_url("socks5h://user:secret@127.0.0.1:1080"),
            "socks5h://user:********@127.0.0.1:1080"
        );
    }

    #[test]
    fn empty_proxy_is_not_reported_as_invalid() {
        assert_eq!(redact_proxy_url(""), "");
    }

    #[test]
    fn user_input_is_normalized_to_https_url() {
        assert_eq!(
            normalize_target_url("  example.com/health ").unwrap(),
            "https://example.com/health"
        );
        assert_eq!(
            normalize_target_url("http://example.net:8080").unwrap(),
            "http://example.net:8080/"
        );
        assert!(normalize_target_url("").is_err());
        assert!(normalize_target_url("ftp://example.com").is_err());
    }

    #[test]
    fn targets_are_added_once_and_removed_from_groups() {
        let mut config = default_config();
        config.websites = vec!["https://example.com/".into()];
        config.website_groups = vec![crate::WebsiteGroup {
            name: "API".into(),
            interval: 10,
            sites: vec!["https://example.net/health".into()],
        }];

        assert!(!add_website(&mut config, "https://example.com/"));
        assert!(add_website(&mut config, "https://example.org/"));
        assert!(remove_target(
            &mut config,
            "API :: https://example.net/health"
        ));
        assert!(config.website_groups.is_empty());
        assert!(remove_target(&mut config, "https://example.org/"));
        assert!(!remove_target(&mut config, "https://missing.example/"));
        assert_eq!(config.websites, vec!["https://example.com/".into()]);
    }

    #[test]
    fn removing_the_last_site_does_not_bring_defaults_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut config = default_config();
        config.websites.clear();

        let saved = save_config(&config, &path).unwrap();

        assert!(saved.websites.is_empty());
        assert!(load_or_create_config(&path).websites.is_empty());
    }

    #[test]
    fn keys_of_earlier_versions_are_still_read() {
        let config: Config = serde_json::from_str(
            r#"{"Monitor": {"logging_enabled": true}, "color_theme": {"banner": "Blue"}}"#,
        )
        .unwrap();

        assert!(config.logging.logging_enabled);
        assert_eq!(config.color_theme.accent, "Blue");
    }

    #[test]
    fn config_with_utf8_bom_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "\u{feff}{\"websites\": [\"https://example.com\"]}").unwrap();

        let config = load_or_create_config(&path);

        assert_eq!(config.websites, vec!["https://example.com".into()]);
    }
}
