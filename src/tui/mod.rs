//! Full-screen terminal interface: the default mode of `wam`, compact with `--lite`.

mod app;
mod input;
mod theme;
mod view;

use std::io::{self, stdout};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste, Event, EventStream};
use crossterm::execute;
use futures_util::StreamExt;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;

use app::App;
pub use app::UiProfile;

use crate::set_notice_sink;

/// Entry point of the interactive mode. Relative paths in the configuration resolve
/// against `data_dir`.
pub fn run(profile: UiProfile, data_dir: PathBuf, config_path: PathBuf) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("не удалось запустить асинхронную среду: {error}"))?;
    let outcome = runtime.block_on(run_screen(profile, data_dir, config_path));
    // Blocking ICMP probes may still be waiting for their timeout; do not hang on exit.
    runtime.shutdown_timeout(Duration::from_millis(300));
    outcome.map_err(|error| error.to_string())
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

async fn run_screen(profile: UiProfile, data_dir: PathBuf, config_path: PathBuf) -> io::Result<()> {
    let (notice_tx, mut notices) = mpsc::unbounded_channel();
    set_notice_sink(Some(notice_tx));
    let result = run_loop(profile, data_dir, config_path, &mut notices).await;
    set_notice_sink(None);
    // Anything reported after the screen closed is still worth showing.
    while let Ok(notice) = notices.try_recv() {
        eprintln!("[{}] {}", notice.level.label(), notice.message);
    }
    result
}

async fn run_loop(
    profile: UiProfile,
    data_dir: PathBuf,
    config_path: PathBuf,
    notices: &mut mpsc::UnboundedReceiver<crate::Notice>,
) -> io::Result<()> {
    let mut app = App::new(profile, data_dir, config_path).map_err(io::Error::other)?;
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
