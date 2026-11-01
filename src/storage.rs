use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::Local;
use serde::Serialize;

use crate::config::{configured_sites, history_capacity};
use crate::model::{Config, UptimeHistoryFile, UptimeSiteData, WebsiteResult};
use crate::notice;

/// `config.json` -> `config.json.tmp`: appending keeps files with the same stem apart.
fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map_or_else(OsString::new, OsString::from);
    name.push(suffix);
    path.with_file_name(name)
}

/// Writes a file so that readers only ever see the old or the new content.
/// `fs::rename` replaces an existing destination on every supported platform
/// (`MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }

    let temp_path = sibling_with_suffix(path, ".tmp");
    let written = (|| {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    let result = written.and_then(|()| fs::rename(&temp_path, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

/// Relative paths in the configuration are resolved against the program directory.
pub fn resolve_data_path(configured: &str, data_dir: &Path) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        path
    } else {
        data_dir.join(path)
    }
}

pub fn current_log_path(base_path: &str, rotate_daily: bool, data_dir: &Path) -> PathBuf {
    let mut relative = PathBuf::from(base_path);
    if rotate_daily {
        let date = Local::now().format("%Y-%m-%d");
        let stem = relative
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("monitor");
        let extension = relative
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("log");
        relative.set_file_name(format!("{stem}_{date}.{extension}"));
    }
    if relative.is_absolute() {
        relative
    } else {
        data_dir.join(relative)
    }
}

pub fn rotate_log_if_needed(path: &Path, max_size_mb: u64) -> io::Result<()> {
    let Ok(metadata) = fs::metadata(path) else {
        return Ok(());
    };
    let max_bytes = max_size_mb.max(1).saturating_mul(1024 * 1024);
    if metadata.len() < max_bytes {
        return Ok(());
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("log");
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("monitor");
    for index in 1..=999 {
        let candidate = parent.join(format!("{stem}_{index:03}.{extension}"));
        if !candidate.exists() {
            return fs::rename(path, candidate);
        }
    }
    Err(io::Error::other(
        "исчерпан диапазон имён для ротации журнала",
    ))
}

#[derive(Serialize)]
struct LogRecord<'a> {
    timestamp: String,
    results: &'a [WebsiteResult],
}

/// Appends one JSON line with the results of a cycle.
pub async fn log_results_async(
    results: &[WebsiteResult],
    config: &Config,
    data_dir: &Path,
) -> Result<PathBuf, String> {
    let path = current_log_path(
        &config.logging.log_file_path,
        config.logging.log_rotate_daily,
        data_dir,
    );
    let record = LogRecord {
        timestamp: Local::now().to_rfc3339(),
        results,
    };
    let mut json = serde_json::to_vec(&record)
        .map_err(|error| format!("Не удалось сериализовать запись журнала: {error}"))?;
    json.push(b'\n');
    let max_size = config.logging.log_max_size_mb;

    let result = tokio::task::spawn_blocking(move || -> io::Result<PathBuf> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        if let Err(error) = rotate_log_if_needed(&path, max_size) {
            notice::warn(format!("Не удалось ротировать журнал: {error}"));
        }
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?
            .write_all(&json)?;
        Ok(path)
    })
    .await;
    match result {
        Ok(Ok(path)) => Ok(path),
        Ok(Err(error)) => Err(format!("Не удалось записать журнал: {error}")),
        Err(error) => Err(format!("Запись журнала завершилась аварийно: {error}")),
    }
}

/// Percentage of successful samples, or `None` when nothing has been recorded yet.
pub fn uptime_percent(samples: &[bool]) -> Option<f64> {
    if samples.is_empty() {
        None
    } else {
        Some(100.0 * samples.iter().filter(|sample| **sample).count() as f64 / samples.len() as f64)
    }
}

const CSV_HEADER: [&str; 13] = [
    "Timestamp",
    "URL",
    "Group",
    "IP",
    "Status",
    "Code",
    "Method",
    "Retries",
    "DurationMs",
    "UptimePercent",
    "ProxyOk",
    "DnsAnomaly",
    "Details",
];

/// Appends the given results to the configured CSV file and returns its path.
pub async fn export_csv_async(
    results: &[WebsiteResult],
    config: &Config,
    uptime_history: &HashMap<String, Vec<bool>>,
    data_dir: &Path,
) -> Result<PathBuf, String> {
    let path = resolve_data_path(&config.csv_export.file_path, data_dir);
    let rows: Vec<(WebsiteResult, Option<f64>)> = results
        .iter()
        .map(|item| {
            let uptime = uptime_history
                .get(&item.identity())
                .and_then(|samples| uptime_percent(samples));
            (item.clone(), uptime)
        })
        .collect();
    let result = tokio::task::spawn_blocking(move || -> Result<PathBuf, csv::Error> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let write_header = fs::metadata(&path).map_or(true, |metadata| metadata.len() == 0);
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);
        if write_header {
            writer.write_record(CSV_HEADER)?;
        }

        let timestamp = Local::now().to_rfc3339();
        for (item, uptime) in &rows {
            writer.write_record([
                timestamp.as_str(),
                item.url.as_str(),
                item.group_name.as_str(),
                item.ip.as_str(),
                item.status.as_str(),
                item.code.as_str(),
                item.http_method.as_str(),
                &item.retries.to_string(),
                &item.duration_ms.to_string(),
                &uptime
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_default(),
                &item.proxy_ok.to_string(),
                &item.dns_anomaly.to_string(),
                item.details.as_str(),
            ])?;
        }
        writer.flush()?;
        Ok(path)
    })
    .await;
    match result {
        Ok(Ok(path)) => Ok(path),
        Ok(Err(error)) => Err(format!("Не удалось экспортировать CSV: {error}")),
        Err(error) => Err(format!("Экспорт CSV завершился аварийно: {error}")),
    }
}

fn uptime_capacity(config: &Config) -> usize {
    configured_sites(config)
        .iter()
        .map(|target| history_capacity(target.interval))
        .max()
        .unwrap_or_else(|| history_capacity(config.monitor_settings.interval))
}

pub fn load_uptime_history(config: &Config, data_dir: &Path) -> HashMap<String, Vec<bool>> {
    let path = resolve_data_path(&config.uptime_history_path, data_dir);
    let capacity = uptime_capacity(config);
    let Ok(content) = fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let Ok(file) = serde_json::from_str::<UptimeHistoryFile>(&content) else {
        notice::warn(format!(
            "История аптайма {} повреждена; она не будет перезаписана до следующего сохранения",
            path.display()
        ));
        return HashMap::new();
    };
    file.sites
        .into_iter()
        .map(|(url, data)| {
            let start = data.history.len().saturating_sub(capacity);
            (url, data.history[start..].to_vec())
        })
        .collect()
}

/// Blocking: call from `spawn_blocking` when used inside the async UI loop.
pub fn save_uptime_history(
    config: &Config,
    history: &HashMap<String, Vec<bool>>,
    data_dir: &Path,
) -> Result<(), String> {
    let path = resolve_data_path(&config.uptime_history_path, data_dir);
    let capacity = uptime_capacity(config);
    let now = Local::now().to_rfc3339();
    let sites = history
        .iter()
        .map(|(url, samples)| {
            let start = samples.len().saturating_sub(capacity);
            let trimmed = samples[start..].to_vec();
            let checks_ok = trimmed.iter().filter(|sample| **sample).count();
            let last_status = trimmed
                .last()
                .map_or("UNKNOWN", |sample| if *sample { "OK" } else { "ERROR" });
            (
                url.clone(),
                UptimeSiteData {
                    checks_total: trimmed.len(),
                    checks_ok,
                    last_status: last_status.into(),
                    last_check: now.clone(),
                    history: trimmed,
                },
            )
        })
        .collect();
    let file = UptimeHistoryFile {
        version: 2,
        last_updated: now,
        sites,
    };
    let json = serde_json::to_vec(&file)
        .map_err(|error| format!("Не удалось сериализовать историю аптайма: {error}"))?;
    write_atomic(&path, &json)
        .map_err(|error| format!("Не удалось сохранить историю аптайма: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_rotation_keeps_parent_directory() {
        let path = current_log_path("logs/monitor.log", true, Path::new("C:/app"));
        assert_eq!(path.parent().unwrap(), Path::new("C:/app/logs"));
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("monitor_")
        );
    }

    #[test]
    fn atomic_write_replaces_existing_file_without_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert!(!sibling_with_suffix(&path, ".tmp").exists());
    }

    #[test]
    fn temp_file_does_not_collide_with_same_stem() {
        let path = Path::new("dir/config.json");
        assert_eq!(
            sibling_with_suffix(path, ".tmp"),
            Path::new("dir/config.json.tmp")
        );
    }

    #[test]
    fn uptime_percent_is_unknown_without_samples() {
        assert_eq!(uptime_percent(&[]), None);
        assert_eq!(uptime_percent(&[true, false, true, true]), Some(75.0));
    }

    #[test]
    fn uptime_history_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::default_config();
        let history = HashMap::from([("https://example.com".to_string(), vec![true, false])]);

        save_uptime_history(&config, &history, dir.path()).unwrap();

        assert_eq!(load_uptime_history(&config, dir.path()), history);
    }

    #[tokio::test]
    async fn csv_export_reports_written_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::default_config();

        let path = export_csv_async(&[], &config, &HashMap::new(), dir.path())
            .await
            .unwrap();

        let content = fs::read_to_string(path).unwrap();
        assert!(content.starts_with("Timestamp,URL"));
    }
}
