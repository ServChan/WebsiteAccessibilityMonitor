//! Continuous background monitoring without a UI: for systemd, a Windows service or a plain
//! console. Events go to stdout (or a log file), metrics optionally to an HTTP endpoint.

use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use chrono::Local;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::metrics::{self, Snapshot};
use crate::monitor::{Monitor, MonitorEvent, plural};
use crate::{NoticeLevel, rotate_log_if_needed, set_notice_sink, try_load_config};

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub config_path: PathBuf,
    /// Base for relative paths in the configuration (history, logs, CSV).
    pub script_dir: PathBuf,
    /// Address for `/metrics`, e.g. `127.0.0.1:9898`.
    pub metrics: Option<SocketAddr>,
    /// Do not report routine cycle summaries, only problems.
    pub quiet: bool,
    /// Write events to this file instead of stdout (used by the Windows service).
    pub log_file: Option<PathBuf>,
}

const LOG_FILE_LIMIT_MB: u64 = 10;

/// Timestamped event lines to stdout or a size-capped file.
#[derive(Clone)]
pub struct EventLog {
    file: Option<Arc<Mutex<(PathBuf, File)>>>,
}

impl EventLog {
    pub fn stdout() -> Self {
        Self { file: None }
    }

    pub fn file(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Не удалось создать {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("Не удалось открыть журнал {}: {error}", path.display()))?;
        Ok(Self {
            file: Some(Arc::new(Mutex::new((path.to_path_buf(), file)))),
        })
    }

    pub fn write(&self, level: NoticeLevel, text: &str) {
        let line = format!(
            "{} [{}] {text}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            level.label()
        );
        let Some(file) = &self.file else {
            println!("{line}");
            return;
        };
        let Ok(mut guard) = file.lock() else {
            return;
        };
        let (path, handle) = &mut *guard;
        if fs::metadata(&*path)
            .is_ok_and(|metadata| metadata.len() >= LOG_FILE_LIMIT_MB * 1024 * 1024)
            && rotate_log_if_needed(path, LOG_FILE_LIMIT_MB).is_ok()
            && let Ok(fresh) = OpenOptions::new().create(true).append(true).open(&*path)
        {
            *handle = fresh;
        }
        let _ = writeln!(handle, "{line}");
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn refresh(snapshot: &Snapshot, monitor: &Monitor) {
    if let Ok(mut text) = snapshot.write() {
        *text = metrics::render(monitor);
    }
}

/// Runs until `shutdown` resolves. Fails only on startup problems (unreadable config,
/// busy metrics port); later errors are logged and monitoring continues.
pub async fn run(
    options: DaemonOptions,
    log: EventLog,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    let config = try_load_config(&options.config_path)?;
    let mut monitor = Monitor::new(config, options.script_dir.clone())?;
    let snapshot: Snapshot = Arc::new(RwLock::new(String::new()));
    refresh(&snapshot, &monitor);

    let metrics_task = match options.metrics {
        Some(address) => {
            let listener = TcpListener::bind(address)
                .await
                .map_err(|error| format!("Не удалось открыть порт метрик {address}: {error}"))?;
            Some(tokio::spawn(metrics::serve(
                listener,
                Arc::clone(&snapshot),
            )))
        }
        None => None,
    };

    let (notice_tx, mut notices) = mpsc::unbounded_channel();
    set_notice_sink(Some(notice_tx));
    let (scan_tx, mut scans) = mpsc::unbounded_channel();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut config_stamp = modified(&options.config_path);

    log.write(
        NoticeLevel::Info,
        &format!(
            "WAM {} запущен в фоновом режиме: {}, настройки {}{}",
            env!("CARGO_PKG_VERSION"),
            plural(monitor.sites().len(), "сайт", "сайта", "сайтов"),
            options.config_path.display(),
            options
                .metrics
                .map(|address| format!(", метрики http://{address}/metrics"))
                .unwrap_or_default()
        ),
    );

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            Some(message) = scans.recv() => {
                for event in monitor.handle(message) {
                    let routine = matches!(&event, MonitorEvent::CycleFinished(cycle) if cycle.failed == 0);
                    if !(options.quiet && routine) {
                        log.write(event.level(), &event.text());
                    }
                }
                refresh(&snapshot, &monitor);
            }
            Some(notice) = notices.recv() => log.write(notice.level, &notice.message),
            _ = ticker.tick() => {
                let stamp = modified(&options.config_path);
                if stamp != config_stamp {
                    config_stamp = stamp;
                    match try_load_config(&options.config_path) {
                        Ok(config) => {
                            if let Err(error) = monitor.set_config(config) {
                                log.write(NoticeLevel::Error, &error);
                            }
                            log.write(
                                NoticeLevel::Info,
                                &format!(
                                    "Настройки перечитаны: {}",
                                    plural(monitor.sites().len(), "сайт", "сайта", "сайтов")
                                ),
                            );
                            refresh(&snapshot, &monitor);
                        }
                        Err(error) => log.write(
                            NoticeLevel::Error,
                            &format!("{error}. Продолжаю с прежними настройками."),
                        ),
                    }
                }
                if monitor.scan().is_none() && monitor.next_due().is_zero() {
                    let scan_tx = scan_tx.clone();
                    monitor.start_scan(false, move |message| {
                        let _ = scan_tx.send(message);
                    });
                }
            }
        }
    }

    set_notice_sink(None);
    if let Some(task) = metrics_task {
        task.abort();
    }
    if let Err(error) = monitor.save_history_now() {
        log.write(NoticeLevel::Error, &error);
    }
    log.write(NoticeLevel::Info, "WAM остановлен");
    Ok(())
}

/// Resolves on Ctrl+C, and on SIGTERM where it exists (systemd stops services with it).
pub async fn termination_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::{get_default_config, save_config};

    #[tokio::test]
    async fn checks_sites_serves_metrics_and_stops_cleanly() {
        let site = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let site_address = site.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = site.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let _ = stream.read(&mut buffer).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let mut config = get_default_config();
        config.websites = vec![format!("http://{site_address}/").as_str().into()];
        config.monitor_settings.ping_enabled = false;
        config.monitor_settings.timeout = 2;
        config.monitor_settings.doh_server = "https://invalid.invalid/dns-query".into();
        config.monitor_settings.domain_check_enabled = false;
        config.monitor_settings.uptime_enabled = true;
        save_config(&config, &config_path).unwrap();

        let metrics_address = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        let log_path = directory.path().join("service.log");
        let options = DaemonOptions {
            config_path,
            script_dir: directory.path().to_path_buf(),
            metrics: Some(metrics_address),
            quiet: false,
            log_file: Some(log_path.clone()),
        };
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let daemon = tokio::spawn(run(options, EventLog::file(&log_path).unwrap(), async {
            let _ = stop_rx.await;
        }));

        let client = reqwest::Client::new();
        let mut body = String::new();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(response) = client
                .get(format!("http://{metrics_address}/metrics"))
                .send()
                .await
            {
                body = response.text().await.unwrap_or_default();
                if body.contains("wam_up{") {
                    break;
                }
            }
        }
        stop_tx.send(()).unwrap();
        daemon.await.unwrap().unwrap();

        assert!(body.contains("wam_up{"), "{body}");
        let log = fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("запущен в фоновом режиме"), "{log}");
        assert!(log.contains("WAM остановлен"), "{log}");
        assert!(directory.path().join("uptime_history.json").exists());
    }

    #[tokio::test]
    async fn broken_config_fails_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        fs::write(&config_path, "{ broken").unwrap();
        let options = DaemonOptions {
            config_path,
            script_dir: directory.path().to_path_buf(),
            metrics: None,
            quiet: true,
            log_file: None,
        };

        let outcome = run(options, EventLog::stdout(), std::future::pending()).await;

        assert!(outcome.unwrap_err().contains("повреждён"));
    }
}
