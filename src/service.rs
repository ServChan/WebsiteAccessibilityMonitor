//! Windows service: install, remove and run the background monitor under the Service
//! Control Manager. Installing and removing require an elevated (administrator) console.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::daemon::{self, DaemonOptions, EventLog};

pub const SERVICE_NAME: &str = "WebsiteAccessibilityMonitor";
const DISPLAY_NAME: &str = "Website Accessibility Monitor";
const DESCRIPTION: &str =
    "Фоновый мониторинг доступности сайтов (WAM): проверки, уведомления и метрики Prometheus.";

static OPTIONS: OnceLock<DaemonOptions> = OnceLock::new();

fn describe(error: windows_service::Error) -> String {
    let text = error.to_string();
    if text.contains("os error 5") || text.to_lowercase().contains("access is denied") {
        format!("{text}. Запустите консоль от имени администратора.")
    } else {
        text
    }
}

/// Registers the service with automatic start and launches it.
/// `arguments` are passed to the executable after `--service`.
pub fn install(executable: &Path, arguments: Vec<OsString>) -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(describe)?;
    let mut launch_arguments = vec![OsString::from("--service")];
    launch_arguments.extend(arguments);
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        launch_arguments,
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(describe)?;
    service.set_description(DESCRIPTION).map_err(describe)?;
    service.start::<&OsStr>(&[]).map_err(describe)?;
    Ok(())
}

/// Stops the service if it runs and deletes it.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(describe)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(describe)?;
    if service
        .query_status()
        .is_ok_and(|status| status.current_state != ServiceState::Stopped)
    {
        let _ = service.stop();
        for _ in 0..50 {
            if service
                .query_status()
                .is_ok_and(|status| status.current_state == ServiceState::Stopped)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    service.delete().map_err(describe)
}

/// Hands the process to the Service Control Manager. Blocks until the service stops.
pub fn run(options: DaemonOptions) -> Result<(), String> {
    let _ = OPTIONS.set(options);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|error| {
        format!(
            "{error}. Режим --service запускается только диспетчером служб; для консоли используйте --watch."
        )
    })
}

define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, exit_code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let Some(options) = OPTIONS.get().cloned() else {
        return;
    };
    let stop = Arc::new(Notify::new());
    let stop_handler = Arc::clone(&stop);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_handler.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let log = options
        .log_file
        .as_deref()
        .map(EventLog::file)
        .transpose()
        .unwrap_or(None)
        .unwrap_or_else(EventLog::stdout);
    let _ = handle.set_service_status(status(ServiceState::Running, 0));
    let outcome = tokio::runtime::Runtime::new()
        .map_err(|error| error.to_string())
        .and_then(|runtime| {
            let result = runtime.block_on(daemon::run(options, log.clone(), async move {
                stop.notified().await;
            }));
            runtime.shutdown_timeout(Duration::from_millis(500));
            result
        });
    let exit_code = match outcome {
        Ok(()) => 0,
        Err(error) => {
            log.write(crate::NoticeLevel::Error, &error);
            1
        }
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, exit_code));
}
