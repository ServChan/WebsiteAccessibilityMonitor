//! Interactive monitor with the compact layout for narrow windows and slow terminals.

use std::process::ExitCode;

use website_accessibility_monitor::tui::{self, UiProfile};

fn main() -> ExitCode {
    tui::main(UiProfile::Lite)
}
