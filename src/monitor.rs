//! Monitoring engine shared by the interactive UI and the background service: schedule,
//! results, maintenance windows, uptime history, alerts and per-cycle persistence.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use futures_util::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use tokio::sync::Semaphore;

use crate::{
    AlertKind, Checker, Config, Health, MonitorTarget, NoticeLevel, WebsiteResult,
    build_direct_client, build_proxied_client, configured_sites, export_csv_async,
    history_capacity, load_uptime_history, log_results_async, notice, save_uptime_history,
    send_all_webhooks, status_description,
};

#[derive(Debug, Clone)]
pub struct Site {
    pub identity: String,
    pub target: MonitorTarget,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    pub done: usize,
    pub total: usize,
    pub started: Instant,
    pub manual: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CycleSummary {
    pub finished_at: DateTime<Local>,
    pub duration: Duration,
    pub checked: usize,
    pub failed: usize,
    pub manual: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Summary {
    pub up: usize,
    pub warn: usize,
    pub down: usize,
    pub pending: usize,
    pub maintenance: usize,
    pub average_ms: Option<u64>,
}

impl Summary {
    pub const fn total(&self) -> usize {
        self.up + self.warn + self.down + self.pending
    }

    pub const fn available(&self) -> usize {
        self.up + self.warn
    }
}

/// Totals for Prometheus counters.
#[derive(Debug, Default, Clone, Copy)]
pub struct CheckCounts {
    pub ok: u64,
    pub failed: u64,
}

/// Messages a running scan sends back to the owner of the [`Monitor`].
#[derive(Debug)]
pub enum ScanMessage {
    Result {
        identity: String,
        started: Instant,
        result: Box<WebsiteResult>,
    },
    Finished,
}

/// Something worth telling the user about.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    Down {
        url: String,
        status: String,
    },
    Recovered {
        url: String,
        code: String,
        duration_ms: u64,
    },
    /// The site failed `failures` times in a row: the alert threshold was reached.
    AlertThreshold {
        url: String,
        failures: u32,
    },
    CycleFinished(CycleSummary),
}

impl MonitorEvent {
    pub fn level(&self) -> NoticeLevel {
        match self {
            Self::Down { .. } | Self::AlertThreshold { .. } => NoticeLevel::Error,
            Self::Recovered { .. } | Self::CycleFinished(_) => NoticeLevel::Info,
        }
    }

    pub fn text(&self) -> String {
        match self {
            Self::Down { url, status } => {
                format!(
                    "{url} недоступен: {status} — {}",
                    status_description(status)
                )
            }
            Self::Recovered {
                url,
                code,
                duration_ms,
            } => format!("{url} снова доступен: HTTP {code}, {duration_ms} мс"),
            Self::AlertThreshold { url, failures } => format!(
                "Сбой {url}: {} подряд",
                plural(*failures as usize, "проверка", "проверки", "проверок")
            ),
            Self::CycleFinished(cycle) => format!(
                "Проверено {} за {:.1} с, недоступно: {}",
                plural(cycle.checked, "сайт", "сайта", "сайтов"),
                cycle.duration.as_secs_f64(),
                cycle.failed
            ),
        }
    }
}

/// Russian plural form: 1 сайт, 2 сайта, 5 сайтов, 21 сайт.
pub fn plural(count: usize, one: &str, few: &str, many: &str) -> String {
    let word = match (count % 10, count % 100) {
        (1, 11) => many,
        (1, _) => one,
        (2..=4, 12..=14) => many,
        (2..=4, _) => few,
        _ => many,
    };
    format!("{count} {word}")
}

/// Marks a result checked inside a maintenance window. Returns whether it applied.
pub fn mark_maintenance(config: &Config, result: &mut WebsiteResult, now: DateTime<Local>) -> bool {
    let Some(window) =
        config.active_maintenance(&result.url, &result.group_name, now.naive_local())
    else {
        return false;
    };
    result.maintenance = true;
    let note = format!("окно обслуживания {}", window.label());
    if result.details.is_empty() {
        result.details = note;
    } else {
        result.details = format!("{note}; {}", result.details);
    }
    true
}

#[derive(Debug, Default, Clone, Copy)]
struct AlertState {
    failures: u32,
    alerted: bool,
}

fn webhook_client(config: &Config) -> Result<Client, String> {
    build_proxied_client(&config.monitor_settings.proxy_url, 15)
        .or_else(|_| build_direct_client(15))
        .map_err(|error| format!("Не удалось создать клиент уведомлений: {error}"))
}

pub struct Monitor {
    config: Config,
    script_dir: PathBuf,
    checker: Checker,
    webhook_client: Client,
    sites: Vec<Site>,
    results: HashMap<String, WebsiteResult>,
    checked_at: HashMap<String, DateTime<Local>>,
    uptime_history: HashMap<String, Vec<bool>>,
    history_capacity: usize,
    last_checked: HashMap<String, Instant>,
    cycle_results: Vec<WebsiteResult>,
    alerts: HashMap<String, AlertState>,
    counts: HashMap<String, CheckCounts>,
    scan: Option<ScanProgress>,
    last_cycle: Option<CycleSummary>,
}

impl Monitor {
    pub fn new(config: Config, script_dir: PathBuf) -> Result<Self, String> {
        let checker = Checker::new(&config)?;
        let webhook_client = webhook_client(&config)?;
        let uptime_history = if config.monitor_settings.uptime_enabled {
            load_uptime_history(&config, &script_dir)
        } else {
            HashMap::new()
        };
        let mut monitor = Self {
            config,
            script_dir,
            checker,
            webhook_client,
            sites: Vec::new(),
            results: HashMap::new(),
            checked_at: HashMap::new(),
            uptime_history,
            history_capacity: 1,
            last_checked: HashMap::new(),
            cycle_results: Vec::new(),
            alerts: HashMap::new(),
            counts: HashMap::new(),
            scan: None,
            last_cycle: None,
        };
        monitor.rebuild_sites();
        Ok(monitor)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn script_dir(&self) -> &Path {
        &self.script_dir
    }

    /// Applies a new configuration. State of sites that remain configured is kept. On a
    /// client error the configuration is still applied with the previous clients.
    pub fn set_config(&mut self, config: Config) -> Result<(), String> {
        let clients =
            Checker::new(&config).and_then(|checker| Ok((checker, webhook_client(&config)?)));
        let outcome = match clients {
            Ok((checker, webhook_client)) => {
                self.checker = checker;
                self.webhook_client = webhook_client;
                Ok(())
            }
            Err(error) => Err(error),
        };
        if !config.monitor_settings.uptime_enabled {
            self.uptime_history.clear();
        } else if self.uptime_history.is_empty() {
            self.uptime_history = load_uptime_history(&config, &self.script_dir);
        }
        self.config = config;
        self.rebuild_sites();
        outcome
    }

    /// Makes every site due immediately.
    pub fn reset_schedule(&mut self) {
        self.last_checked.clear();
    }

    fn rebuild_sites(&mut self) {
        self.sites = configured_sites(&self.config)
            .into_iter()
            .map(|target| Site {
                identity: target.identity(),
                target,
            })
            .collect();
        self.history_capacity = self
            .sites
            .iter()
            .map(|site| history_capacity(site.target.interval))
            .max()
            .unwrap_or(1);
        let known: HashSet<String> = self
            .sites
            .iter()
            .map(|site| site.identity.clone())
            .collect();
        self.results.retain(|identity, _| known.contains(identity));
        self.checked_at
            .retain(|identity, _| known.contains(identity));
        self.last_checked
            .retain(|identity, _| known.contains(identity));
        self.alerts.retain(|identity, _| known.contains(identity));
        self.counts.retain(|identity, _| known.contains(identity));
        self.uptime_history
            .retain(|identity, _| known.contains(identity));
    }

    // ------------------------------------------------------------------ views

    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    pub fn result(&self, identity: &str) -> Option<&WebsiteResult> {
        self.results.get(identity)
    }

    pub fn checked_at(&self, identity: &str) -> Option<DateTime<Local>> {
        self.checked_at.get(identity).copied()
    }

    pub fn uptime(&self, identity: &str) -> &[bool] {
        self.uptime_history.get(identity).map_or(&[], Vec::as_slice)
    }

    pub fn uptime_history(&self) -> &HashMap<String, Vec<bool>> {
        &self.uptime_history
    }

    pub fn counts(&self, identity: &str) -> CheckCounts {
        self.counts.get(identity).copied().unwrap_or_default()
    }

    pub fn scan(&self) -> Option<ScanProgress> {
        self.scan
    }

    pub fn last_cycle(&self) -> Option<CycleSummary> {
        self.last_cycle
    }

    pub fn summary(&self) -> Summary {
        let mut summary = Summary::default();
        let mut total_ms = 0_u64;
        let mut timed = 0_u64;
        for site in &self.sites {
            let result = self.result(&site.identity);
            match result.map(WebsiteResult::health) {
                Some(Health::Up) => summary.up += 1,
                Some(Health::Warning) => summary.warn += 1,
                Some(Health::Down) => summary.down += 1,
                None => summary.pending += 1,
            }
            if result.is_some_and(|result| result.maintenance) {
                summary.maintenance += 1;
            }
            if let Some(result) = result.filter(|result| result.direct_ok) {
                total_ms = total_ms.saturating_add(result.duration_ms);
                timed += 1;
            }
        }
        summary.average_ms = (timed > 0).then(|| total_ms / timed);
        summary
    }

    fn remaining(&self, site: &Site, now: Instant) -> Duration {
        let interval = Duration::from_secs(site.target.interval.max(1));
        self.last_checked
            .get(&site.identity)
            .map_or(Duration::ZERO, |last| {
                interval.saturating_sub(now.saturating_duration_since(*last))
            })
    }

    /// Time until the next site is due.
    pub fn next_due(&self) -> Duration {
        let now = Instant::now();
        self.sites
            .iter()
            .map(|site| self.remaining(site, now))
            .min()
            .unwrap_or(Duration::from_secs(60))
    }

    // ------------------------------------------------------------------ scanning

    /// Starts checking every due site (all of them when `manual`). Results arrive through
    /// `send` and must be passed to [`Monitor::handle`]. Returns `false` when a scan is
    /// already running or nothing is due.
    pub fn start_scan<F>(&mut self, manual: bool, send: F) -> bool
    where
        F: Fn(ScanMessage) + Send + Sync + Clone + 'static,
    {
        if self.scan.is_some() {
            return false;
        }
        let now = Instant::now();
        let targets: Vec<(String, MonitorTarget)> = self
            .sites
            .iter()
            .filter(|site| manual || self.remaining(site, now).is_zero())
            .map(|site| (site.identity.clone(), site.target.clone()))
            .collect();
        if targets.is_empty() {
            return false;
        }
        self.scan = Some(ScanProgress {
            done: 0,
            total: targets.len(),
            started: now,
            manual,
        });
        self.cycle_results.clear();
        let config = Arc::new(self.config.clone());
        let checker = self.checker.clone();
        tokio::spawn(async move {
            let semaphore = Arc::new(Semaphore::new(config.monitor_settings.max_concurrency));
            let mut tasks = FuturesUnordered::new();
            for (identity, target) in targets {
                let checker = checker.clone();
                let config = Arc::clone(&config);
                let semaphore = Arc::clone(&semaphore);
                let send = send.clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = semaphore.acquire_owned().await;
                    // The schedule is anchored to the start of a check, so slow sites do not
                    // drift by their own response time every cycle.
                    let started = Instant::now();
                    let result = checker.check(&target, &config).await;
                    send(ScanMessage::Result {
                        identity,
                        started,
                        result: Box::new(result),
                    });
                }));
            }
            while tasks.next().await.is_some() {}
            send(ScanMessage::Finished);
        });
        true
    }

    pub fn handle(&mut self, message: ScanMessage) -> Vec<MonitorEvent> {
        match message {
            ScanMessage::Result {
                identity,
                started,
                result,
            } => self.apply_result(identity, started, *result),
            ScanMessage::Finished => self.finish_scan().into_iter().collect(),
        }
    }

    fn apply_result(
        &mut self,
        identity: String,
        started: Instant,
        mut result: WebsiteResult,
    ) -> Vec<MonitorEvent> {
        if let Some(scan) = &mut self.scan {
            scan.done += 1;
        }
        // The site may have been removed while its check was in flight.
        if !self.sites.iter().any(|site| site.identity == identity) {
            return Vec::new();
        }
        let now = Local::now();
        let in_maintenance = mark_maintenance(&self.config, &mut result, now);
        self.last_checked.insert(identity.clone(), started);
        self.checked_at.insert(identity.clone(), now);
        let counts = self.counts.entry(identity.clone()).or_default();
        if status_is_available(&result) {
            counts.ok += 1;
        } else {
            counts.failed += 1;
        }

        let mut events = Vec::new();
        // Planned downtime neither counts against uptime nor raises alerts.
        if !in_maintenance {
            self.record_uptime(&identity, result.is_available());
            events.extend(self.handle_alert(&identity, &result));
        }
        let previous = self.results.insert(identity, result.clone());
        if !in_maintenance {
            events.extend(transition(previous.as_ref(), &result));
        }
        self.cycle_results.push(result);
        events
    }

    fn finish_scan(&mut self) -> Option<MonitorEvent> {
        let scan = self.scan.take()?;
        let cycle = CycleSummary {
            finished_at: Local::now(),
            duration: scan.started.elapsed(),
            checked: self.cycle_results.len(),
            failed: self
                .cycle_results
                .iter()
                .filter(|result| !result.is_available())
                .count(),
            manual: scan.manual,
        };
        self.last_cycle = Some(cycle);
        self.persist_cycle();
        Some(MonitorEvent::CycleFinished(cycle))
    }

    /// Writes history, journal and CSV in the background; errors become notices.
    fn persist_cycle(&mut self) {
        let results = std::mem::take(&mut self.cycle_results);
        let config = self.config.clone();
        let script_dir = self.script_dir.clone();
        let history = self.uptime_history.clone();
        tokio::spawn(async move {
            if config.monitor_settings.uptime_enabled {
                let (config, history, script_dir) =
                    (config.clone(), history.clone(), script_dir.clone());
                let saved = tokio::task::spawn_blocking(move || {
                    save_uptime_history(&config, &history, &script_dir)
                })
                .await
                .unwrap_or_else(|error| Err(format!("Сохранение истории прервано: {error}")));
                if let Err(error) = saved {
                    notice::error(error);
                }
            }
            if config.monitor.logging_enabled
                && let Err(error) = log_results_async(&results, &config, &script_dir).await
            {
                notice::error(error);
            }
            if config.csv_export.enabled
                && let Err(error) = export_csv_async(&results, &config, &history, &script_dir).await
            {
                notice::error(error);
            }
        });
    }

    /// Saves the uptime history synchronously, e.g. right before the process exits.
    pub fn save_history_now(&self) -> Result<(), String> {
        if self.config.monitor_settings.uptime_enabled {
            save_uptime_history(&self.config, &self.uptime_history, &self.script_dir)
        } else {
            Ok(())
        }
    }

    fn record_uptime(&mut self, identity: &str, available: bool) {
        if !self.config.monitor_settings.uptime_enabled {
            return;
        }
        let history = self.uptime_history.entry(identity.to_string()).or_default();
        history.push(available);
        if history.len() > self.history_capacity {
            let excess = history.len() - self.history_capacity;
            history.drain(..excess);
        }
    }

    fn handle_alert(&mut self, identity: &str, result: &WebsiteResult) -> Option<MonitorEvent> {
        let hooks = &self.config.webhooks;
        let state = self.alerts.entry(identity.to_string()).or_default();
        let mut alert = None;
        let mut event = None;
        if result.is_available() {
            if state.alerted && hooks.notify_on_recovery {
                alert = Some((
                    AlertKind::Recovered,
                    format!(
                        "ВОССТАНОВЛЕН: {}\nСтатус: {} ({})\nВремя ответа: {} мс",
                        result.url, result.status, result.code, result.duration_ms
                    ),
                ));
            }
            *state = AlertState::default();
        } else {
            state.failures = state.failures.saturating_add(1);
            if state.failures == hooks.min_failures_before_alert {
                let failures = state.failures;
                if hooks.notify_on_down {
                    state.alerted = true;
                    let proxy = if self.config.monitor_settings.proxy_url.is_empty() {
                        "не настроен"
                    } else if result.proxy_ok {
                        "доступен"
                    } else {
                        "недоступен"
                    };
                    alert = Some((
                        AlertKind::Down,
                        format!(
                            "НЕДОСТУПЕН: {}\nСтатус: {} ({})\nПричина: {}\nДиагностика: {}\nЧерез прокси: {}\nСбоев подряд: {}",
                            result.url,
                            result.status,
                            result.code,
                            status_description(&result.status),
                            if result.details.is_empty() {
                                "—"
                            } else {
                                &result.details
                            },
                            proxy,
                            failures
                        ),
                    ));
                }
                event = Some(MonitorEvent::AlertThreshold {
                    url: result.url.clone(),
                    failures,
                });
            }
        }
        if self.config.webhooks.enabled
            && let Some((kind, message)) = alert
        {
            let client = self.webhook_client.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                send_all_webhooks(&client, &config, kind, &message).await;
            });
        }
        event
    }
}

/// Availability judged by the status alone: a maintenance window does not make a failed
/// check succeed in the counters.
fn status_is_available(result: &WebsiteResult) -> bool {
    crate::status_health(&result.status) != Health::Down
}

fn transition(previous: Option<&WebsiteResult>, current: &WebsiteResult) -> Option<MonitorEvent> {
    match (
        previous.map(WebsiteResult::is_available),
        current.is_available(),
    ) {
        (Some(true) | None, false) => Some(MonitorEvent::Down {
            url: current.url.clone(),
            status: current.status.clone(),
        }),
        (Some(false), true) => Some(MonitorEvent::Recovered {
            url: current.url.clone(),
            code: current.code.clone(),
            duration_ms: current.duration_ms,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MaintenanceWindow, get_default_config};

    fn result(url: &str, status: &str) -> WebsiteResult {
        let mut result = WebsiteResult::pending(url);
        result.status = status.into();
        result.direct_ok = status == "OK";
        result
    }

    fn monitor(urls: &[&str]) -> (Monitor, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let mut config = get_default_config();
        config.websites = urls.iter().map(|url| (*url).into()).collect();
        config.monitor_settings.uptime_enabled = true;
        let monitor = Monitor::new(config, directory.path().to_path_buf()).unwrap();
        (monitor, directory)
    }

    fn feed(monitor: &mut Monitor, url: &str, status: &str) -> Vec<MonitorEvent> {
        monitor.handle(ScanMessage::Result {
            identity: url.into(),
            started: Instant::now(),
            result: Box::new(result(url, status)),
        })
    }

    #[test]
    fn russian_plurals() {
        assert_eq!(plural(1, "сайт", "сайта", "сайтов"), "1 сайт");
        assert_eq!(plural(3, "сайт", "сайта", "сайтов"), "3 сайта");
        assert_eq!(plural(11, "сайт", "сайта", "сайтов"), "11 сайтов");
        assert_eq!(plural(22, "сайт", "сайта", "сайтов"), "22 сайта");
    }

    #[tokio::test]
    async fn alert_threshold_fires_once_and_recovery_resets_it() {
        let (mut monitor, _directory) = monitor(&["https://a.example/"]);
        let mut config = monitor.config().clone();
        config.webhooks.min_failures_before_alert = 2;
        monitor.set_config(config).unwrap();

        let first = feed(&mut monitor, "https://a.example/", "TCP_TIMEOUT");
        assert!(matches!(first.as_slice(), [MonitorEvent::Down { .. }]));
        let second = feed(&mut monitor, "https://a.example/", "TCP_TIMEOUT");
        assert!(matches!(
            second.as_slice(),
            [MonitorEvent::AlertThreshold { failures: 2, .. }]
        ));
        assert!(feed(&mut monitor, "https://a.example/", "TCP_TIMEOUT").is_empty());
        let recovered = feed(&mut monitor, "https://a.example/", "OK");
        assert!(matches!(
            recovered.as_slice(),
            [MonitorEvent::Recovered { .. }]
        ));
        assert_eq!(
            monitor.uptime("https://a.example/"),
            &[false, false, false, true]
        );
        assert_eq!(monitor.counts("https://a.example/").failed, 3);
    }

    #[tokio::test]
    async fn maintenance_suppresses_alerts_and_uptime() {
        let (mut monitor, _directory) = monitor(&["https://a.example/"]);
        let mut config = monitor.config().clone();
        config.webhooks.min_failures_before_alert = 1;
        config.maintenance_windows = vec![MaintenanceWindow {
            name: "релиз".into(),
            days: Vec::new(),
            start: "00:00".into(),
            end: "00:00".into(),
            targets: Vec::new(),
        }];
        monitor.set_config(config).unwrap();

        let events = feed(&mut monitor, "https://a.example/", "TCP_TIMEOUT");

        assert!(events.is_empty(), "{events:?}");
        let stored = monitor.result("https://a.example/").unwrap();
        assert!(stored.maintenance);
        assert!(stored.details.contains("релиз"));
        assert_eq!(stored.health(), Health::Warning);
        assert!(monitor.uptime("https://a.example/").is_empty());
        assert_eq!(monitor.summary().maintenance, 1);
    }

    #[tokio::test]
    async fn removed_site_results_are_ignored() {
        let (mut monitor, _directory) = monitor(&["https://a.example/", "https://b.example/"]);
        let mut config = monitor.config().clone();
        config.websites.truncate(1);
        monitor.set_config(config).unwrap();

        assert!(feed(&mut monitor, "https://b.example/", "TCP_TIMEOUT").is_empty());
        assert!(monitor.result("https://b.example/").is_none());
    }
}
