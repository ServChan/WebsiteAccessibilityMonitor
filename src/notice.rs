//! Library-level warnings and errors.
//!
//! Library code must never write to stdout/stderr directly while a full-screen TUI owns the
//! terminal: a stray `eprintln!` lands in the middle of the alternate screen and corrupts it.
//! Messages are therefore routed through a process-wide sink. Without a sink (headless mode,
//! tests) they fall back to stderr.

use std::sync::Mutex;

use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Warning,
    Error,
}

impl NoticeLevel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "ИНФО",
            Self::Warning => "ПРЕДУПРЕЖДЕНИЕ",
            Self::Error => "ОШИБКА",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Notice {
    pub level: NoticeLevel,
    pub message: String,
}

static SINK: Mutex<Option<UnboundedSender<Notice>>> = Mutex::new(None);

/// Installs (or removes with `None`) the receiver of library notices.
pub fn set_notice_sink(sender: Option<UnboundedSender<Notice>>) {
    if let Ok(mut sink) = SINK.lock() {
        *sink = sender;
    }
}

pub(crate) fn emit(level: NoticeLevel, message: impl Into<String>) {
    let notice = Notice {
        level,
        message: message.into(),
    };
    let undelivered = match SINK.lock() {
        Ok(sink) => match sink.as_ref() {
            Some(sender) => sender.send(notice).err().map(|error| error.0),
            None => Some(notice),
        },
        Err(_) => Some(notice),
    };
    if let Some(notice) = undelivered {
        eprintln!("[{}] {}", notice.level.label(), notice.message);
    }
}

pub(crate) fn warn(message: impl Into<String>) {
    emit(NoticeLevel::Warning, message);
}

pub(crate) fn error(message: impl Into<String>) {
    emit(NoticeLevel::Error, message);
}
