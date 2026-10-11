//! Interactive monitor with the full layout.

use std::process::ExitCode;

use website_accessibility_monitor::tui::{self, UiProfile};

fn main() -> ExitCode {
    tui::main(UiProfile::Full)
}
