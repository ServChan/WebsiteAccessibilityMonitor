use ratatui::style::{Color, Modifier, Style};

use crate::{ColorTheme, Health};

/// Palette resolved from `color_theme` in config.json.
///
/// Colour is always a secondary signal: every status also carries a text marker, so the
/// UI stays usable with `NO_COLOR`, in monochrome terminals and for colour-blind users.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Theme {
    pub(crate) ok: Color,
    pub(crate) warn: Color,
    pub(crate) error: Color,
    pub(crate) accent: Color,
    pub(crate) fast: Color,
    pub(crate) medium: Color,
    pub(crate) slow: Color,
    pub(crate) border: Color,
}

impl Theme {
    pub(crate) fn from_config(config: &ColorTheme) -> Self {
        if no_color_requested() {
            return Self::monochrome();
        }
        Self {
            ok: parse_color(&config.ok, Color::Green),
            warn: parse_color(&config.warn, Color::Yellow),
            error: parse_color(&config.error, Color::Red),
            accent: parse_color(&config.banner, Color::Cyan),
            fast: parse_color(&config.fast_ms, Color::Green),
            medium: parse_color(&config.medium_ms, Color::Yellow),
            slow: parse_color(&config.slow_ms, Color::Red),
            border: Color::DarkGray,
        }
    }

    pub(crate) const fn monochrome() -> Self {
        Self {
            ok: Color::Reset,
            warn: Color::Reset,
            error: Color::Reset,
            accent: Color::Reset,
            fast: Color::Reset,
            medium: Color::Reset,
            slow: Color::Reset,
            border: Color::Reset,
        }
    }

    pub(crate) fn health(&self, health: Option<Health>) -> Color {
        match health {
            Some(Health::Up) => self.ok,
            Some(Health::Warning) => self.warn,
            Some(Health::Down) => self.error,
            None => Color::Reset,
        }
    }

    pub(crate) fn duration(&self, milliseconds: u64) -> Color {
        match milliseconds {
            0..300 => self.fast,
            300..1_000 => self.medium,
            _ => self.slow,
        }
    }

    pub(crate) fn heading(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub(crate) fn key(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    /// Selection uses reverse video: it is visible in light, dark and high-contrast themes.
    pub(crate) fn selection(&self) -> Style {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    }
}

fn no_color_requested() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
}

pub(crate) fn parse_color(name: &str, fallback: Color) -> Color {
    let name = name.trim();
    if let Some(hex) = name.strip_prefix('#')
        && hex.len() == 6
        && let Ok(value) = u32::from_str_radix(hex, 16)
    {
        return Color::Rgb((value >> 16) as u8, (value >> 8) as u8, value as u8);
    }
    // Standard ANSI colours are tuned by terminal themes for both light and dark
    // backgrounds; the bright variants (e.g. bright yellow) vanish on a light background,
    // so they are only used when asked for explicitly with a "light" prefix.
    match name.to_lowercase().replace(['_', '-', ' '], "").as_str() {
        "black" => Color::Black,
        "darkgray" | "darkgrey" => Color::DarkGray,
        "gray" | "grey" => Color::Gray,
        "white" => Color::White,
        "red" | "darkred" => Color::Red,
        "green" | "darkgreen" => Color::Green,
        "yellow" | "darkyellow" => Color::Yellow,
        "blue" | "darkblue" => Color::Blue,
        "magenta" | "darkmagenta" => Color::Magenta,
        "cyan" | "darkcyan" => Color::Cyan,
        "lightred" => Color::LightRed,
        "lightgreen" => Color::LightGreen,
        "lightyellow" => Color::LightYellow,
        "lightblue" => Color::LightBlue,
        "lightmagenta" => Color::LightMagenta,
        "lightcyan" => Color::LightCyan,
        "default" | "reset" => Color::Reset,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_console_names_and_hex() {
        assert_eq!(parse_color("DarkCyan", Color::Reset), Color::Cyan);
        assert_eq!(parse_color("dark_red", Color::Reset), Color::Red);
        assert_eq!(parse_color("Light-Green", Color::Reset), Color::LightGreen);
        assert_eq!(
            parse_color("#1e90ff", Color::Reset),
            Color::Rgb(30, 144, 255)
        );
        assert_eq!(parse_color("nonsense", Color::Blue), Color::Blue);
    }
}
