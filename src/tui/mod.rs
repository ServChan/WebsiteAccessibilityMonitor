//! Full-screen terminal interface shared by `SiteMonitor` and `SiteMonitorLite`.

mod app;
mod input;
mod theme;
mod view;

use std::io::{self, stdout};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste, Event, EventStream};
use crossterm::execute;
use futures_util::StreamExt;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;

use app::App;
pub use app::UiProfile;

use crate::set_notice_sink;

struct Options {
    config_path: Option<PathBuf>,
}

fn usage(profile: UiProfile) -> String {
    let name = match profile {
        UiProfile::Full => "SiteMonitor",
        UiProfile::Lite => "SiteMonitorLite",
    };
    format!(
        "{name} {version} — монитор доступности сайтов\n\n\
         Использование:\n  {name} [--config PATH]\n\n\
         Параметры:\n  \
         --config PATH   файл настроек (по умолчанию config.json рядом с программой)\n  \
         -h, --help      показать эту справку\n  \
         -V, --version   показать версию\n\n\
         Внутри программы нажмите ? — список горячих клавиш.",
        version = env!("CARGO_PKG_VERSION")
    )
}

fn parse_options(profile: UiProfile) -> Result<Option<Options>, String> {
    let mut options = Options { config_path: None };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!("{}", usage(profile));
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--config" => {
                let path = arguments
                    .next()
                    .ok_or("После --config укажите путь к файлу настроек")?;
                options.config_path = Some(PathBuf::from(path));
            }
            other => {
                return Err(format!(
                    "Неизвестный параметр: {other}\n\n{}",
                    usage(profile)
                ));
            }
        }
    }
    Ok(Some(options))
}

/// Directory of the executable: config, history and logs live next to the program.
fn program_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Entry point for the interactive binaries.
pub fn main(profile: UiProfile) -> ExitCode {
    let options = match parse_options(profile) {
        Ok(Some(options)) => options,
        Ok(None) => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Не удалось запустить асинхронную среду: {error}");
            return ExitCode::FAILURE;
        }
    };
    let script_dir = program_dir();
    let config_path = options
        .config_path
        .unwrap_or_else(|| script_dir.join("config.json"));
    let outcome = runtime.block_on(run(profile, script_dir, config_path));
    // Blocking ICMP probes may still be waiting for their timeout; do not hang on exit.
    runtime.shutdown_timeout(Duration::from_millis(300));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Ошибка: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Restores the terminal on drop, including early returns and errors.
struct TerminalGuard {
    terminal: DefaultTerminal,
}

impl TerminalGuard {
    fn new() -> io::Result<Self> {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
        let terminal = ratatui::try_init()?;
        // Bracketed paste delivers a pasted token or URL as one event instead of keystrokes.
        let _ = execute!(stdout(), EnableBracketedPaste);
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = execute!(stdout(), DisableBracketedPaste);
    ratatui::restore();
}

async fn run(profile: UiProfile, script_dir: PathBuf, config_path: PathBuf) -> io::Result<()> {
    let (notice_tx, mut notices) = mpsc::unbounded_channel();
    set_notice_sink(Some(notice_tx));
    let result = run_loop(profile, script_dir, config_path, &mut notices).await;
    set_notice_sink(None);
    // Anything reported after the screen closed is still worth showing.
    while let Ok(notice) = notices.try_recv() {
        eprintln!("[{}] {}", notice.level.label(), notice.message);
    }
    result
}

async fn run_loop(
    profile: UiProfile,
    script_dir: PathBuf,
    config_path: PathBuf,
    notices: &mut mpsc::UnboundedReceiver<crate::Notice>,
) -> io::Result<()> {
    let mut app = App::new(profile, script_dir, config_path).map_err(io::Error::other)?;
    let mut messages = app
        .take_receiver()
        .ok_or_else(|| io::Error::other("канал сообщений уже занят"))?;
    let mut guard = TerminalGuard::new()?;
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(profile.tick());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !app.should_quit {
        guard.terminal.draw(|frame| view::render(frame, &mut app))?;
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) => app.handle_key(key),
                Some(Ok(Event::Paste(text))) => app.handle_paste(&text),
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error),
                None => break,
            },
            Some(message) = messages.recv() => {
                app.handle_message(message);
                // Drain a burst of results before redrawing once.
                while let Ok(message) = messages.try_recv() {
                    app.handle_message(message);
                }
            }
            Some(notice) = notices.recv() => app.handle_notice(notice),
            _ = ticker.tick() => app.tick(),
        }
    }
    Ok(())
}
