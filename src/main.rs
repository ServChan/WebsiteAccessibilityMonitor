use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use website_accessibility_monitor::daemon::{self, DaemonOptions, EventLog};
use website_accessibility_monitor::monitor::mark_maintenance;
use website_accessibility_monitor::tui::{self, UiProfile};
use website_accessibility_monitor::{
    Checker, Config, WebsiteEntry, WebsiteResult, configured_sites, default_config,
    load_or_create_config, normalize_target_url, status_description,
};

fn usage() -> String {
    format!(
        "WebsiteAccessibilityMonitor (wam) {}\n\n\
         Интерфейс в терминале:\n  \
         wam [--config PATH] [--lite]\n\n\
         Одноразовая проверка:\n  \
         wam --once [--config PATH] [--json]\n  \
         wam [--json] URL ...\n\n\
         Постоянный фоновый режим (для systemd, планировщика или консоли):\n  \
         wam --watch [--config PATH] [--metrics АДРЕС] [--quiet] [--log-file PATH]\n\n\
         Служба Windows (консоль от имени администратора):\n  \
         wam --install-service [--config PATH] [--metrics АДРЕС]\n  \
         wam --uninstall-service\n\n\
         Параметры:\n  \
         --config PATH     файл настроек (по умолчанию config.json: для интерфейса рядом\n                    \
         с программой, для остальных режимов в текущей папке)\n  \
         --lite            компактный интерфейс для узких окон и SSH/RDP\n  \
         --once            проверить цели из config.json один раз и завершиться\n  \
         --json            результат одноразовой проверки в JSON\n  \
         --metrics АДРЕС   отдавать метрики Prometheus, например 127.0.0.1:9898\n  \
         --quiet           не писать итоги циклов без сбоев\n  \
         --log-file PATH   писать события в файл вместо консоли\n  \
         -h, --help        показать эту справку\n  \
         -V, --version     показать версию\n\n\
         Схему адреса можно не указывать: example.com проверяется как https://example.com/.\n\
         Коды завершения одноразовой проверки: 0 — все цели OK/WARN, 2 — есть недоступные,\n\
         1 — ошибка запуска. Внутри интерфейса нажмите ? — список горячих клавиш.",
        env!("CARGO_PKG_VERSION")
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Interface,
    Once,
    Watch,
    Service,
    InstallService,
    UninstallService,
}

struct Options {
    mode: Mode,
    config_path: Option<PathBuf>,
    lite: bool,
    json: bool,
    metrics: Option<SocketAddr>,
    quiet: bool,
    log_file: Option<PathBuf>,
    urls: Vec<String>,
}

fn parse_options() -> Result<Option<Options>, String> {
    let mut options = Options {
        mode: Mode::Interface,
        config_path: None,
        lite: false,
        json: false,
        metrics: None,
        quiet: false,
        log_file: None,
        urls: Vec::new(),
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = |name: &str| {
            arguments
                .next()
                .ok_or_else(|| format!("после {name} требуется значение"))
        };
        match argument.as_str() {
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--json" => options.json = true,
            "--lite" => options.lite = true,
            "--once" => options.mode = Mode::Once,
            "--quiet" => options.quiet = true,
            "--watch" => options.mode = Mode::Watch,
            "--service" => options.mode = Mode::Service,
            "--install-service" => options.mode = Mode::InstallService,
            "--uninstall-service" => options.mode = Mode::UninstallService,
            "--config" => options.config_path = Some(PathBuf::from(value("--config")?)),
            "--log-file" => options.log_file = Some(PathBuf::from(value("--log-file")?)),
            "--metrics" => {
                let raw = value("--metrics")?;
                // A bare port is a common shorthand; keep it local by default.
                let address = if raw.chars().all(|character| character.is_ascii_digit()) {
                    format!("127.0.0.1:{raw}")
                } else {
                    raw.clone()
                };
                options.metrics = Some(address.parse().map_err(|_| {
                    format!("некорректный адрес метрик «{raw}»; пример: 127.0.0.1:9898")
                })?);
            }
            other if other.starts_with('-') => {
                return Err(format!("неизвестный параметр: {other}\n\n{}", usage()));
            }
            url => {
                let url = normalize_target_url(url).map_err(|error| format!("{url}: {error}"))?;
                options.urls.push(url);
            }
        }
    }
    if options.mode == Mode::Interface && (options.json || !options.urls.is_empty()) {
        options.mode = Mode::Once;
    }
    if options.mode != Mode::Once && !options.urls.is_empty() {
        return Err("адреса в командной строке поддерживаются только для одноразовой проверки; для фонового режима укажите их в config.json".into());
    }
    if options.mode == Mode::Interface
        && (options.quiet || options.metrics.is_some() || options.log_file.is_some())
    {
        return Err("--metrics, --quiet и --log-file работают только вместе с --watch".into());
    }
    if options.mode != Mode::Interface && options.lite {
        return Err("--lite относится только к интерфейсу в терминале".into());
    }
    Ok(Some(options))
}

/// Directory of the executable: the interface keeps its files next to the program.
fn program_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn config_path(options: &Options) -> PathBuf {
    options
        .config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("config.json"))
}

/// Absolute path, so that a service started from `System32` finds the same file.
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Relative paths in the configuration resolve next to the config file.
fn data_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn run_interface(options: Options) -> Result<ExitCode, String> {
    let config_path = absolute(
        &options
            .config_path
            .unwrap_or_else(|| program_dir().join("config.json")),
    );
    let profile = if options.lite {
        UiProfile::Lite
    } else {
        UiProfile::Full
    };
    tui::run(profile, data_dir(&config_path), config_path).map(|()| ExitCode::SUCCESS)
}

fn daemon_options(options: &Options) -> DaemonOptions {
    let config_path = absolute(&config_path(options));
    let data_dir = data_dir(&config_path);
    DaemonOptions {
        log_file: options.log_file.as_deref().map(absolute),
        config_path,
        data_dir,
        metrics: options.metrics,
        quiet: options.quiet,
    }
}

async fn check_all(config: Config) -> Result<Vec<WebsiteResult>, String> {
    let checker = Checker::new(&config)?;
    let semaphore = Arc::new(Semaphore::new(config.monitor_settings.max_concurrency));
    let config = Arc::new(config);
    let tasks: Vec<_> = configured_sites(&config)
        .into_iter()
        .map(|target| {
            let checker = checker.clone();
            let config = Arc::clone(&config);
            let semaphore = Arc::clone(&semaphore);
            tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                let mut result = checker.check(&target, &config).await;
                mark_maintenance(&config, &mut result, chrono::Local::now());
                result
            })
        })
        .collect();
    Ok(futures_util::future::join_all(tasks)
        .await
        .into_iter()
        .flatten()
        .collect())
}

fn print_table(results: &[WebsiteResult]) {
    println!("СТАТУС\tКОД\tВРЕМЯ\tURL\tДЕТАЛИ");
    for result in results {
        let details = if result.details.is_empty() {
            status_description(&result.status)
        } else {
            &result.details
        };
        println!(
            "{}\t{}\t{} ms\t{}\t{}",
            result.status, result.code, result.duration_ms, result.url, details
        );
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Runtime::new()
        .map_err(|error| format!("не удалось запустить асинхронную среду: {error}"))
}

fn run_once(options: Options) -> Result<ExitCode, String> {
    let config = if options.urls.is_empty() {
        load_or_create_config(&config_path(&options))
    } else {
        let mut config = default_config();
        config.websites = options
            .urls
            .iter()
            .map(|url| WebsiteEntry::new(url.as_str()))
            .collect();
        config.website_groups.clear();
        config.monitor_settings.ping_enabled = false;
        config
    };
    if configured_sites(&config).is_empty() {
        return Err(
            "нет целей: добавьте сайты в config.json или укажите адреса в командной строке".into(),
        );
    }
    let runtime = runtime()?;
    let outcome = runtime.block_on(check_all(config));
    // Blocking ICMP probes may still be waiting for their timeout; do not hang on exit.
    runtime.shutdown_timeout(Duration::from_millis(300));
    let results = outcome?;

    if options.json {
        let json = serde_json::to_string_pretty(&results)
            .map_err(|error| format!("не удалось сериализовать результаты: {error}"))?;
        println!("{json}");
    } else {
        print_table(&results);
    }
    Ok(if results.iter().all(WebsiteResult::is_available) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn run_watch(options: Options) -> Result<ExitCode, String> {
    let daemon_options = daemon_options(&options);
    let log = match &daemon_options.log_file {
        Some(path) => EventLog::file(path)?,
        None => EventLog::stdout(),
    };
    let runtime = runtime()?;
    let outcome = runtime.block_on(daemon::run(
        daemon_options,
        log,
        daemon::termination_signal(),
    ));
    runtime.shutdown_timeout(Duration::from_millis(500));
    outcome.map(|()| ExitCode::SUCCESS)
}

#[cfg(windows)]
fn install_service(options: Options) -> Result<ExitCode, String> {
    use std::ffi::OsString;

    let daemon_options = daemon_options(&options);
    // Create a default config now, so the service does not start against a missing file.
    load_or_create_config(&daemon_options.config_path);
    let executable = std::env::current_exe()
        .map_err(|error| format!("не удалось определить путь программы: {error}"))?;
    let log_file = daemon_options
        .log_file
        .clone()
        .unwrap_or_else(|| daemon_options.data_dir.join("wam-service.log"));
    let mut arguments = vec![
        OsString::from("--config"),
        daemon_options.config_path.clone().into_os_string(),
        OsString::from("--log-file"),
        log_file.clone().into_os_string(),
    ];
    if let Some(address) = daemon_options.metrics {
        arguments.push(OsString::from("--metrics"));
        arguments.push(OsString::from(address.to_string()));
    }
    if daemon_options.quiet {
        arguments.push(OsString::from("--quiet"));
    }
    website_accessibility_monitor::service::install(&executable, arguments)?;
    println!(
        "Служба {} установлена и запущена.\nНастройки: {}\nЖурнал: {}",
        website_accessibility_monitor::service::SERVICE_NAME,
        daemon_options.config_path.display(),
        log_file.display()
    );
    if let Some(address) = daemon_options.metrics {
        println!("Метрики: http://{address}/metrics");
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(windows)]
fn uninstall_service() -> Result<ExitCode, String> {
    website_accessibility_monitor::service::uninstall()?;
    println!("Служба удалена.");
    Ok(ExitCode::SUCCESS)
}

#[cfg(windows)]
fn run_service(options: Options) -> Result<ExitCode, String> {
    website_accessibility_monitor::service::run(daemon_options(&options))
        .map(|()| ExitCode::SUCCESS)
}

#[cfg(not(windows))]
fn windows_only() -> Result<ExitCode, String> {
    Err("службы Windows доступны только в Windows; в Linux используйте --watch с systemd (пример юнита в deploy/)".into())
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(Some(options)) => options,
        Ok(None) => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("Ошибка: {message}");
            return ExitCode::FAILURE;
        }
    };
    let outcome = match options.mode {
        Mode::Interface => run_interface(options),
        Mode::Once => run_once(options),
        Mode::Watch => run_watch(options),
        #[cfg(windows)]
        Mode::Service => run_service(options),
        #[cfg(windows)]
        Mode::InstallService => install_service(options),
        #[cfg(windows)]
        Mode::UninstallService => uninstall_service(),
        #[cfg(not(windows))]
        Mode::Service | Mode::InstallService | Mode::UninstallService => windows_only(),
    };
    outcome.unwrap_or_else(|message| {
        eprintln!("Ошибка: {message}");
        ExitCode::FAILURE
    })
}
