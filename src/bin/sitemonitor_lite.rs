use std::collections::HashMap;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Local;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    style::{Color, ResetColor, SetForegroundColor},
    terminal::{self, Clear, ClearType},
};
use tokio::sync::oneshot;

use website_accessibility_monitor::*;

// =========================================================================
// Console utilities
// =========================================================================

fn get_width() -> u16 {
    terminal::size().map(|(w, _)| w.max(52) - 3).unwrap_or(95)
}

fn get_height() -> u16 {
    terminal::size().map(|(_, h)| h.max(10)).unwrap_or(30)
}

fn safe_clear() {
    let _ = execute!(stdout(), Clear(ClearType::Purge), Clear(ClearType::All), crossterm::cursor::MoveTo(0, 0));
}

fn safe_set_cursor(left: u16, top: u16) {
    let w = get_width();
    let left = left.min(w);
    let _ = execute!(stdout(), crossterm::cursor::MoveTo(left, top));
}

fn safe_write(s: &str) {
    print!("{}", s);
    let _ = stdout().flush();
}

fn safe_write_line(s: &str) {
    println!("{}", s);
    let _ = stdout().flush();
}

fn set_color(c: Color) {
    let _ = execute!(stdout(), SetForegroundColor(c));
}

fn reset_color() {
    let _ = execute!(stdout(), ResetColor);
}

fn pad(s: &str, len: usize) -> String {
    let char_count = s.chars().count();
    if char_count > len {
        s.chars().take(len).collect()
    } else {
        let mut padded = s.to_string();
        for _ in 0..(len - char_count) {
            padded.push(' ');
        }
        padded
    }
}

fn center_in_box(s: &str, width: usize) -> String {
    let char_count = s.chars().count();
    if char_count > width {
        s.chars().take(width).collect()
    } else {
        let pad_left = (width - char_count) / 2;
        let pad_right = width - char_count - pad_left;
        format!("{}{}{}", " ".repeat(pad_left), s, " ".repeat(pad_right))
    }
}

fn write_centered(text: &str, color: Option<Color>) {
    let width = get_width() as usize;
    if let Some(c) = color {
        set_color(c);
    }
    let char_count = text.chars().count();
    let pad_left = (width + char_count) / 2;
    safe_write_line(&format!("{:>width$}", text, width = pad_left));
    if color.is_some() {
        reset_color();
    }
}

struct RawModeGuard;
impl RawModeGuard {
    fn new() -> Self {
        let _ = terminal::enable_raw_mode();
        let _ = execute!(stdout(), Hide);
        RawModeGuard
    }
}
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), Show);
        let _ = terminal::disable_raw_mode();
    }
}

// =========================================================================
// Drawing functions
// =========================================================================

fn print_banner() {
    let h = get_height();
    if h < 24 {
        let title = "=== SITE MONITOR (v2.0.0) ===";
        set_color(Color::Cyan);
        write_centered(title, None);
        reset_color();
        return;
    }
    let w = get_width() as usize;
    let border = "═".repeat(w);
    let title = "S I T E   M O N I T O R";
    let version = "v2.0.0  |  Lite Edition";
    let sub = "[ Monitoring Dashboard ]";

    set_color(Color::Cyan);
    safe_write_line(&border);
    safe_write_line("");
    write_centered(title, None);
    write_centered(sub, None);
    write_centered(version, None);
    safe_write_line("");
    safe_write_line(&border);
    reset_color();
}

fn print_results(results: &[WebsiteResult]) {
    let w = get_width() as usize;
    
    let stat_w = 10;
    let ip_w = 16;
    let code_w = 5;
    let method_w = 6;
    let retry_w = 5;
    let dur_w = 8;
    let borders_width = 9;
    
    let site_w = if w > (stat_w + ip_w + code_w + method_w + retry_w + dur_w + borders_width) {
        w - (stat_w + ip_w + code_w + method_w + retry_w + dur_w + borders_width)
    } else {
        16
    };

    let make_hline = |left: char, mid: char, right: char, fill: char, cols: &[usize]| -> String {
        let mut sb = String::new();
        sb.push(left);
        for (idx, &col) in cols.iter().enumerate() {
            sb.push_str(&fill.to_string().repeat(col));
            if idx < cols.len() - 1 {
                sb.push(mid);
            } else {
                sb.push(right);
            }
        }
        sb
    };

    let cols = vec![stat_w, site_w, ip_w, code_w, method_w, retry_w, dur_w];

    let top_line = make_hline('┌', '┬', '┐', '─', &cols);
    let hdr_line = make_hline('├', '┼', '┤', '─', &cols);
    let bot_line = make_hline('└', '┴', '┘', '─', &cols);

    let write_table_row = |cells: &[(&str, usize, Option<Color>)]| {
        set_color(Color::DarkGrey);
        safe_write("│");
        reset_color();
        for (i, cell) in cells.iter().enumerate() {
            let text = cell.0;
            let width = cell.1;
            let color = cell.2;
            
            if i == 1 && text.contains(" [Proxy OK]") {
                if let Some(pos) = text.find(" [Proxy OK]") {
                    let url_part = &text[..pos];
                    let tag_part = &text[pos..]; // " [Proxy OK]"
                    
                    let url_chars = url_part.chars().count();
                    let tag_chars = tag_part.chars().count();
                    let total_chars = url_chars + tag_chars;
                    
                    if let Some(c) = color {
                        set_color(c);
                    }
                    if total_chars > width {
                        let take_len = width.saturating_sub(tag_chars);
                        safe_write(&url_part.chars().take(take_len).collect::<String>());
                        reset_color();
                        set_color(Color::Cyan);
                        safe_write(tag_part);
                        reset_color();
                    } else {
                        safe_write(url_part);
                        reset_color();
                        set_color(Color::Cyan);
                        safe_write(tag_part);
                        reset_color();
                        let pad_len = width - total_chars;
                        safe_write(&" ".repeat(pad_len));
                    }
                }
            } else {
                if let Some(c) = color {
                    set_color(c);
                }
                safe_write(&pad(text, width));
                reset_color();
            }
            
            set_color(Color::DarkGrey);
            safe_write("│");
            reset_color();
        }
        safe_write_line("");
    };

    // Table Header
    set_color(Color::DarkGrey);
    safe_write_line(&top_line);
    reset_color();

    write_table_row(&[
        ("  Статус", stat_w, Some(Color::Cyan)),
        ("  Сайт", site_w, Some(Color::Cyan)),
        ("  IP", ip_w, Some(Color::Cyan)),
        (" Код", code_w, Some(Color::Cyan)),
        (" Метод", method_w, Some(Color::Cyan)),
        (" Повт", retry_w, Some(Color::Cyan)),
        ("   мс", dur_w, Some(Color::Cyan)),
    ]);

    set_color(Color::DarkGrey);
    safe_write_line(&hdr_line);
    reset_color();

    // Let's compute how many rows we can display
    let h_term = get_height() as usize;
    let mut overhead = 12;
    if h_term < 24 { overhead -= 6; } // banner compact
    if h_term < 16 { overhead -= 2; } // last check hidden
    if h_term >= 28 { overhead += 5 + results.len(); } // uptime table overhead (approximate)

    let max_rows = h_term.saturating_sub(overhead).max(3);
    let total_count = results.len();
    let display_count = total_count.min(max_rows);
    let hidden_count = total_count.saturating_sub(display_count);

    // Data rows
    let mut avail = 0;
    for (idx, r) in results.iter().enumerate() {
        if r.status == "OK" || r.status == "WARN" {
            avail += 1;
        }

        if idx >= display_count {
            continue;
        }

        let status_color = if r.status == "OK" {
            Color::Green
        } else if r.status == "WARN" {
            Color::Yellow
        } else {
            Color::Red
        };

        let status_icon = if r.status == "OK" {
            " ● "
        } else if r.status == "WARN" {
            " ▲ "
        } else {
            " ✖ "
        };

        let dur_color = if r.duration_ms < 500 {
            Color::Green
        } else if r.duration_ms <= 2000 {
            Color::Yellow
        } else {
            Color::Red
        };

        let formatted_status = format!("{}{}", status_icon, r.status);
        let url_cell = if r.proxy_ok {
            format!(" {} [Proxy OK]", r.url)
        } else {
            format!(" {}", r.url)
        };
        let ip_cell = format!(" {}", r.ip);
        let code_cell = format!(" {}", r.code);
        let method_cell = format!(" {}", r.http_method);
        let retries_cell = format!(" {}", r.retries);
        let dur_cell = format!("{:>width$}", r.duration_ms, width = dur_w);

        write_table_row(&[
            (&formatted_status, stat_w, Some(status_color)),
            (&url_cell, site_w, Some(Color::White)),
            (&ip_cell, ip_w, Some(Color::Grey)),
            (&code_cell, code_w, None),
            (&method_cell, method_w, Some(Color::DarkGrey)),
            (&retries_cell, retry_w, None),
            (&dur_cell, dur_w, Some(dur_color)),
        ]);
    }

    if hidden_count > 0 {
        let msg = format!(" ... и еще {} сайтов скрыто (увеличьте высоту окна)", hidden_count);
        let merged_width = site_w + ip_w + code_w + method_w + retry_w + dur_w + 5;
        write_table_row(&[
            ("  •••", stat_w, Some(Color::Yellow)),
            (&msg, merged_width, Some(Color::Yellow)),
        ]);
    }

    set_color(Color::DarkGrey);
    safe_write_line(&bot_line);
    reset_color();

    // Summary line
    let total_count = results.len();
    let pct = if total_count > 0 { avail as f64 * 100.0 / total_count as f64 } else { 0.0 };
    let sum_color = if pct >= 90.0 {
        Color::Green
    } else if pct >= 50.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    safe_write("  ");
    set_color(sum_color);
    safe_write_line(&format!("● {}/{} доступно ({:.1}%)", avail, total_count, pct));
    reset_color();
    safe_write_line("");
}

fn print_uptime(results: &[WebsiteResult], uptime_history: &HashMap<String, Vec<bool>>) {
    let w = get_width() as usize;
    let url_w = 30;
    let pct_w = 9;
    let bar_length = if w > (url_w + pct_w + 6) { w - url_w - pct_w - 6 } else { 0 };

    let top_line = format!("┌{}┬{}┬{}┐", "─".repeat(url_w), "─".repeat(pct_w), "─".repeat(bar_length + 2));
    let hdr_line = format!("├{}┼{}┼{}┤", "─".repeat(url_w), "─".repeat(pct_w), "─".repeat(bar_length + 2));
    let bot_line = format!("└{}┴{}┴{}┘", "─".repeat(url_w), "─".repeat(pct_w), "─".repeat(bar_length + 2));

    set_color(Color::DarkGrey); safe_write_line(&top_line); reset_color();
    
    set_color(Color::DarkGrey); safe_write("│");
    set_color(Color::Cyan); safe_write(&pad(" Сайт", url_w));
    set_color(Color::DarkGrey); safe_write("│");
    set_color(Color::Cyan); safe_write(&pad(" Аптайм", pct_w));
    set_color(Color::DarkGrey); safe_write("│");
    set_color(Color::Cyan); safe_write(&pad(" За сутки", bar_length + 2));
    set_color(Color::DarkGrey); safe_write_line("│"); reset_color();

    set_color(Color::DarkGrey); safe_write_line(&hdr_line); reset_color();

    for r in results {
        set_color(Color::DarkGrey); safe_write("│"); reset_color();
        if let Some(history) = uptime_history.get(&r.url) {
            let daily_history = if history.len() > 1440 {
                &history[history.len() - 1440..]
            } else {
                history
            };
            let daily_count = daily_history.len();
            let green_count = daily_history.iter().filter(|&&x| x).count();
            let uptime_percent = if daily_count > 0 {
                green_count as f64 * 100.0 / daily_count as f64
            } else {
                0.0
            };

            set_color(Color::White);
            safe_write(&pad(&format!(" {}", r.url), url_w));
            reset_color();

            set_color(Color::DarkGrey); safe_write("│");
            let pct_color = if uptime_percent >= 99.0 {
                Color::Green
            } else if uptime_percent >= 90.0 {
                Color::Yellow
            } else {
                Color::Red
            };
            set_color(pct_color);
            safe_write(&format!("{:>7.2}% ", uptime_percent));
            reset_color();

            set_color(Color::DarkGrey); safe_write("│ ");
            
            let display_history = if history.len() > bar_length {
                &history[history.len() - bar_length..]
            } else {
                history
            };

            for &stat in display_history {
                let col = if stat { Color::Green } else { Color::Red };
                set_color(col);
                safe_write("█");
            }
            reset_color();

            let remaining = bar_length.saturating_sub(display_history.len());
            if remaining > 0 {
                set_color(Color::DarkGrey);
                safe_write(&"░".repeat(remaining));
                reset_color();
            }
            safe_write(" ");
        } else {
            set_color(Color::White);
            safe_write(&pad(&format!(" {}", r.url), url_w));
            reset_color();

            set_color(Color::DarkGrey); safe_write("│");
            set_color(Color::DarkGrey);
            safe_write(&format!("{:>7.2}% ", 0.0));
            reset_color();

            set_color(Color::DarkGrey); safe_write("│ ");
            set_color(Color::DarkGrey);
            safe_write(&"░".repeat(bar_length));
            reset_color();
            safe_write(" ");
        }
        set_color(Color::DarkGrey); safe_write_line("│"); reset_color();
    }
    set_color(Color::DarkGrey); safe_write_line(&bot_line); reset_color();
}

// =========================================================================
// Settings Menu
// =========================================================================

fn draw_settings_screen(
    config: &Config,
    active_idx: usize,
    scroll_offset: usize,
    is_editing: bool,
    edit_buffer: &str,
) {
    let w = (get_width() as usize).min(76);
    let h = get_height() as usize;

    safe_clear();

    let title_line = " НАСТРОЙКИ МОНИТОРИНГА ";
    let title_pad = (w.saturating_sub(title_line.chars().count() + 2)) / 2;
    let top_border = format!("┌{} {} {}┐", "─".repeat(title_pad), title_line, "─".repeat(w - title_pad - title_line.chars().count() - 2));
    
    set_color(Color::Cyan);
    safe_write_line(&top_border);
    reset_color();

    let items = vec![
        "Интервал сканирования (сек)",
        "Таймаут соединения (сек)",
        "Количество ретраев",
        "Пинг хостов (ICMP)",
        "Сбор аптайма за сутки",
        "Быстрый метод HEAD",
        "Логирование результатов",
        "Путь к файлу логов",
        "Экспорт в CSV файл",
        "Путь к файлу CSV",
        "Включить вебхуки",
        "Telegram Bot Token",
        "Telegram Chat ID",
        "Прокси сервер (Proxy URL)",
        "DoH Сервер (DNS-over-HTTPS)",
    ];

    let visible_height = h.saturating_sub(10).max(1);
    let end_idx = (scroll_offset + visible_height).min(items.len());

    for idx in scroll_offset..end_idx {
        let is_active = idx == active_idx;
        let name = items[idx];

        set_color(Color::Cyan);
        safe_write("│ ");
        reset_color();

        if is_active {
            set_color(Color::Cyan);
            safe_write("> ");
            set_color(Color::White);
            safe_write(&pad(name, 34));
        } else {
            safe_write("  ");
            set_color(Color::Grey);
            safe_write(&pad(name, 34));
        }
        reset_color();

        let val_str = match idx {
            0 => {
                let val = config.monitor_settings.interval;
                format!("< {:>4} сек >", val)
            }
            1 => {
                let val = config.monitor_settings.timeout;
                format!("< {:>4} сек >", val)
            }
            2 => {
                let val = config.monitor_settings.retries_max;
                format!("< {:>4} >", val)
            }
            3 => {
                if config.monitor_settings.ping_enabled { "[  ВКЛ   ]".to_string() } else { "[  ВЫКЛ  ]".to_string() }
            }
            4 => {
                if config.monitor_settings.uptime_enabled { "[  ВКЛ   ]".to_string() } else { "[  ВЫКЛ  ]".to_string() }
            }
            5 => {
                if config.monitor_settings.use_head_first { "[  ВКЛ   ]".to_string() } else { "[  ВЫКЛ  ]".to_string() }
            }
            6 => {
                if config.monitor.logging_enabled { "[  ВКЛ   ]".to_string() } else { "[  ВЫКЛ  ]".to_string() }
            }
            7 => {
                if is_active && is_editing {
                    format!("[ {}_ ]", edit_buffer)
                } else {
                    format!("[ {} ]", config.monitor.log_file_path)
                }
            }
            8 => {
                if config.csv_export.enabled { "[  ВКЛ   ]".to_string() } else { "[  ВЫКЛ  ]".to_string() }
            }
            9 => {
                if is_active && is_editing {
                    format!("[ {}_ ]", edit_buffer)
                } else {
                    format!("[ {} ]", config.csv_export.file_path)
                }
            }
            10 => {
                if config.webhooks.enabled { "[  ВКЛ   ]".to_string() } else { "[  ВЫКЛ  ]".to_string() }
            }
            11 => {
                if is_active && is_editing {
                    format!("[ {}_ ]", edit_buffer)
                } else {
                    let tok = &config.webhooks.telegram_bot_token;
                    if tok.is_empty() {
                        "[ <не задан> ]".to_string()
                    } else if tok.len() > 8 {
                        format!("[ {}...{} ]", &tok[..4], &tok[tok.len()-4..])
                    } else {
                        "[ ******** ]".to_string()
                    }
                }
            }
            12 => {
                if is_active && is_editing {
                    format!("[ {}_ ]", edit_buffer)
                } else {
                    let id = &config.webhooks.telegram_chat_id;
                    if id.is_empty() { "[ <не задан> ]".to_string() } else { format!("[ {} ]", id) }
                }
            }
            13 => {
                if is_active && is_editing {
                    format!("[ {}_ ]", edit_buffer)
                } else {
                    let url = &config.monitor_settings.proxy_url;
                    if url.is_empty() { "[ <не задан> ]".to_string() } else { format!("[ {} ]", url) }
                }
            }
            14 => {
                if is_active && is_editing {
                    format!("[ {}_ ]", edit_buffer)
                } else {
                    format!("[ {} ]", config.monitor_settings.doh_server)
                }
            }
            _ => "".to_string(),
        };

        let val_w = w.saturating_sub(34 + 6);
        let val_padded = pad(&val_str, val_w);
        
        if is_active {
            if is_editing {
                set_color(Color::Yellow);
            } else {
                set_color(Color::Green);
            }
            safe_write(&val_padded);
        } else {
            match idx {
                3 | 4 | 5 | 6 | 8 | 10 => {
                    let val = match idx {
                        3 => config.monitor_settings.ping_enabled,
                        4 => config.monitor_settings.uptime_enabled,
                        5 => config.monitor_settings.use_head_first,
                        6 => config.monitor.logging_enabled,
                        8 => config.csv_export.enabled,
                        10 => config.webhooks.enabled,
                        _ => false,
                    };
                    if val {
                        set_color(Color::Green);
                    } else {
                        set_color(Color::DarkGrey);
                    }
                }
                _ => {
                    set_color(Color::White);
                }
            }
            safe_write(&val_padded);
        }
        reset_color();

        set_color(Color::Cyan);
        safe_write_line(" │");
        reset_color();
    }

    let rendered_rows = end_idx - scroll_offset;
    if rendered_rows < visible_height {
        for _ in rendered_rows..visible_height {
            set_color(Color::Cyan);
            safe_write("│ ");
            safe_write(&" ".repeat(w - 4));
            safe_write_line(" │");
            reset_color();
        }
    }

    let mid_border = format!("├{}┤", "─".repeat(w - 2));
    set_color(Color::Cyan);
    safe_write_line(&mid_border);
    reset_color();

    let desc = match active_idx {
        0 => "Интервал времени между проверками доступности сайтов (в секундах).",
        1 => "Время ожидания ответа от каждого сайта перед фиксатией таймаута (в секундах).",
        2 => "Количество повторных попыток запроса в случае сбоя (макс. 5).",
        3 => "Отправлять ICMP эхо-запросы перед HTTP-проверками (нужны права админа).",
        4 => "Расчет и отображение процента аптайма за последние 24 часа в консоли.",
        5 => "Использовать HEAD-запросы вместо GET для экономии трафика.",
        6 => "Записывать историю всех проверок в текстовый лог-файл.",
        7 => "Имя или абсолютный путь к текстовому файлу логов.",
        8 => "Экспортировать результаты проверок в CSV-таблицу после каждого цикла.",
        9 => "Имя или абсолютный путь к экспортируемому CSV-файлу.",
        10 => "Отправка уведомлений о сбоях/восстановлении в Telegram.",
        11 => "Токен вашего Telegram-бота, полученный от @BotFather.",
        12 => "ID чата или канала для отправки уведомлений Telegram.",
        13 => "URL-адрес HTTP/SOCKS5 прокси-сервера (например: http://127.0.0.1:8080).",
        14 => "Адрес DNS-over-HTTPS (DoH) сервера для разрешения имен хостов.",
        _ => "",
    };

    let desc_w = w - 4;
    let words = desc.split_whitespace().collect::<Vec<&str>>();
    let mut lines = Vec::new();
    let mut current_line = String::new();
    for word in words {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.chars().count() + 1 + word.chars().count() <= desc_w {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    for i in 0..2 {
        set_color(Color::Cyan);
        safe_write("│ ");
        reset_color();

        if i < lines.len() {
            set_color(Color::White);
            safe_write(&pad(&lines[i], desc_w));
        } else {
            safe_write(&" ".repeat(desc_w));
        }
        reset_color();

        set_color(Color::Cyan);
        safe_write_line(" │");
        reset_color();
    }

    set_color(Color::Cyan);
    safe_write_line(&mid_border);
    reset_color();

    set_color(Color::Cyan);
    safe_write("│ ");
    reset_color();

    let instr1 = if is_editing {
        "Редактирование... Введите новое значение."
    } else {
        "▲/▼ Выбор  ·  ◄/► Изменить  ·  Enter Ввод текста  ·  Esc Выйти без сохр."
    };
    set_color(Color::DarkGrey);
    safe_write(&pad(instr1, w - 4));
    reset_color();

    set_color(Color::Cyan);
    safe_write_line(" │");
    safe_write("│ ");
    reset_color();

    let instr2 = if is_editing {
        "Enter - подтвердить ввод, Esc - отмена."
    } else {
        "Нажмите O для сохранения изменений и выхода."
    };
    set_color(Color::DarkGrey);
    safe_write(&pad(instr2, w - 4));
    reset_color();

    set_color(Color::Cyan);
    safe_write_line(" │");

    let bot_border = format!("└{}┘", "─".repeat(w - 2));
    safe_write_line(&bot_border);
    reset_color();
}

async fn show_settings_menu(
    config: &mut Config,
    config_path: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut active_idx = 0;
    let mut scroll_offset = 0;
    let mut is_editing = false;
    let mut edit_buffer = String::new();
    let num_items = 15;

    loop {
        let h = get_height() as usize;
        let visible_height = h.saturating_sub(10).max(1);

        if active_idx < scroll_offset {
            scroll_offset = active_idx;
        } else if active_idx >= scroll_offset + visible_height {
            scroll_offset = active_idx - visible_height + 1;
        }

        draw_settings_screen(config, active_idx, scroll_offset, is_editing, &edit_buffer);

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != event::KeyEventKind::Release {
                    if is_editing {
                        match key.code {
                            KeyCode::Enter => {
                                match active_idx {
                                    7 => config.monitor.log_file_path = edit_buffer.clone(),
                                    9 => config.csv_export.file_path = edit_buffer.clone(),
                                    11 => config.webhooks.telegram_bot_token = edit_buffer.clone(),
                                    12 => config.webhooks.telegram_chat_id = edit_buffer.clone(),
                                    13 => config.monitor_settings.proxy_url = edit_buffer.clone(),
                                    14 => config.monitor_settings.doh_server = edit_buffer.clone(),
                                    _ => {}
                                }
                                is_editing = false;
                            }
                            KeyCode::Esc => {
                                is_editing = false;
                            }
                            KeyCode::Backspace => {
                                edit_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                if edit_buffer.chars().count() < 60 {
                                    edit_buffer.push(c);
                                }
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Up => {
                                if active_idx > 0 {
                                    active_idx -= 1;
                                }
                            }
                            KeyCode::Down => {
                                if active_idx < num_items - 1 {
                                    active_idx += 1;
                                }
                            }
                            KeyCode::Left => {
                                match active_idx {
                                    0 => config.monitor_settings.interval = config.monitor_settings.interval.saturating_sub(5).max(1),
                                    1 => config.monitor_settings.timeout = config.monitor_settings.timeout.saturating_sub(1).max(1),
                                    2 => config.monitor_settings.retries_max = config.monitor_settings.retries_max.saturating_sub(1),
                                    3 => config.monitor_settings.ping_enabled = !config.monitor_settings.ping_enabled,
                                    4 => config.monitor_settings.uptime_enabled = !config.monitor_settings.uptime_enabled,
                                    5 => config.monitor_settings.use_head_first = !config.monitor_settings.use_head_first,
                                    6 => config.monitor.logging_enabled = !config.monitor.logging_enabled,
                                    8 => config.csv_export.enabled = !config.csv_export.enabled,
                                    10 => config.webhooks.enabled = !config.webhooks.enabled,
                                    _ => {}
                                }
                            }
                            KeyCode::Right => {
                                match active_idx {
                                    0 => config.monitor_settings.interval = config.monitor_settings.interval.saturating_add(5).min(86400),
                                    1 => config.monitor_settings.timeout = config.monitor_settings.timeout.saturating_add(1).min(300),
                                    2 => config.monitor_settings.retries_max = config.monitor_settings.retries_max.saturating_add(1).min(5),
                                    3 => config.monitor_settings.ping_enabled = !config.monitor_settings.ping_enabled,
                                    4 => config.monitor_settings.uptime_enabled = !config.monitor_settings.uptime_enabled,
                                    5 => config.monitor_settings.use_head_first = !config.monitor_settings.use_head_first,
                                    6 => config.monitor.logging_enabled = !config.monitor.logging_enabled,
                                    8 => config.csv_export.enabled = !config.csv_export.enabled,
                                    10 => config.webhooks.enabled = !config.webhooks.enabled,
                                    _ => {}
                                }
                            }
                            KeyCode::Enter => {
                                match active_idx {
                                    3 => config.monitor_settings.ping_enabled = !config.monitor_settings.ping_enabled,
                                    4 => config.monitor_settings.uptime_enabled = !config.monitor_settings.uptime_enabled,
                                    5 => config.monitor_settings.use_head_first = !config.monitor_settings.use_head_first,
                                    6 => config.monitor.logging_enabled = !config.monitor.logging_enabled,
                                    8 => config.csv_export.enabled = !config.csv_export.enabled,
                                    10 => config.webhooks.enabled = !config.webhooks.enabled,
                                    7 => {
                                        is_editing = true;
                                        edit_buffer = config.monitor.log_file_path.clone();
                                    }
                                    9 => {
                                        is_editing = true;
                                        edit_buffer = config.csv_export.file_path.clone();
                                    }
                                    11 => {
                                        is_editing = true;
                                        edit_buffer = config.webhooks.telegram_bot_token.clone();
                                    }
                                    12 => {
                                        is_editing = true;
                                        edit_buffer = config.webhooks.telegram_chat_id.clone();
                                    }
                                    13 => {
                                        is_editing = true;
                                        edit_buffer = config.monitor_settings.proxy_url.clone();
                                    }
                                    14 => {
                                        is_editing = true;
                                        edit_buffer = config.monitor_settings.doh_server.clone();
                                    }
                                    _ => {}
                                }
                            }
                            KeyCode::Char('o') | KeyCode::Char('O') => {
                                save_config(config, config_path);
                                return Ok(true);
                            }
                            KeyCode::Esc => {
                                *config = load_or_create_config(config_path);
                                return Ok(false);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

// =========================================================================
// Main Entry
// =========================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let script_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let config_path = script_dir.join("config.json");

    let mut config = load_or_create_config(&config_path);
    let mut client = build_http_client(&config);
    let mut uptime_history = load_uptime_history(&config, &script_dir);
    let mut failure_count: HashMap<String, u32> = HashMap::new();
    let mut config_reloaded = false;
    let mut need_check = true;
    let mut results: Vec<WebsiteResult> = Vec::new();
    let mut last_check_time = Local::now();

    let _raw_mode_guard = RawModeGuard::new();

    loop {
        if need_check {
            last_check_time = Local::now();
            let total = config.websites.len();
            let done_counter = Arc::new(AtomicUsize::new(0));

            let (overlay_tx, overlay_rx) = oneshot::channel::<()>();

            // Spawn simplified overlay spinner task
            let done_clone = Arc::clone(&done_counter);
            let overlay_handle = tokio::spawn(async move {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0;
                let start_instant = Instant::now();
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                let mut rx = overlay_rx;
                let mut prev_w = 0;
                let mut prev_h = 0;

                loop {
                    tokio::select! {
                        _ = &mut rx => {
                            break;
                        }
                        _ = interval.tick() => {
                            let w = get_width();
                            let h = get_height();
                            if w != prev_w || h != prev_h {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                safe_clear();
                                print_banner();
                                prev_w = get_width();
                                prev_h = get_height();
                            }

                            let done = done_clone.load(Ordering::Relaxed);
                            let t1 = format!(" СКАНИРОВАНИЕ {} ", frames[i % frames.len()]);
                            let elapsed = start_instant.elapsed();
                            let elapsed_mins = elapsed.as_secs() / 60;
                            let elapsed_secs = elapsed.as_secs() % 60;
                            let elapsed_ms = (elapsed.as_millis() % 1000) / 100;
                            let t2 = format!(" Готово {}/{} • {:02}:{:02}.{} ", done, total, elapsed_mins, elapsed_secs, elapsed_ms);
                            
                            let box_w = t1.chars().count().max(t2.chars().count()).max(28) + 4;
                            let left = if w > box_w as u16 { (w - box_w as u16) / 2 } else { 0 };
                            let top = if h > 4 { (h - 4) / 2 } else { 0 };
                            let horiz = "─".repeat(box_w - 2);
                            
                            safe_set_cursor(left, top);
                            set_color(Color::DarkGrey);
                            safe_write(&format!("┌{}┐", horiz));
                            
                            safe_set_cursor(left, top + 1);
                            safe_write(&format!("│{}│", center_in_box(&t1, box_w - 2)));
                            
                            safe_set_cursor(left, top + 2);
                            safe_write(&format!("│{}│", center_in_box(&t2, box_w - 2)));
                            
                            safe_set_cursor(left, top + 3);
                            safe_write(&format!("└{}┘", horiz));
                            reset_color();
                            i += 1;
                        }
                    }
                }
            });

            // Run website checks concurrently
            let mut check_tasks = Vec::new();
            for url in &config.websites {
                let client_clone = client.clone();
                let config_clone = config.clone();
                let done_clone = Arc::clone(&done_counter);
                let url_str = url.clone();
                let headers = HashMap::new(); // empty headers for Lite edition

                check_tasks.push(tokio::spawn(async move {
                    let res = check_website_async(&client_clone, &url_str, &headers, &config_clone).await;
                    done_clone.fetch_add(1, Ordering::Relaxed);
                    res
                }));
            }

            results.clear();
            for task in futures_util::future::join_all(check_tasks).await {
                if let Ok(res) = task {
                    results.push(res);
                }
            }

            // Cancel overlay
            let _ = overlay_tx.send(());
            let _ = overlay_handle.await;

            // Sort by status if specified in config
            if config.monitor_settings.sorted == "status" {
                results.sort_by(|a, b| {
                    let a_fail = a.status != "OK" && a.status != "WARN";
                    let b_fail = b.status != "OK" && b.status != "WARN";
                    a_fail.cmp(&b_fail).then_with(|| a.url.cmp(&b.url))
                });
            }

            if config.monitor_settings.uptime_enabled {
                let history_max = 1440;
                for r in &results {
                    let hist = uptime_history.entry(r.url.clone()).or_insert_with(Vec::new);
                    hist.push(r.status == "OK" || r.status == "WARN");
                    if hist.len() > history_max {
                        hist.remove(0);
                    }
                }
                save_uptime_history(&config, &uptime_history, &script_dir);
            }

            // Failure alerts in Lite mode
            for r in &results {
                let f_count = failure_count.entry(r.url.clone()).or_insert(0);
                if r.status == "OK" || r.status == "WARN" {
                    *f_count = 0;
                } else {
                    *f_count += 1;
                    if *f_count == 3 {
                        let block_reason = get_block_reason_ru(&r.status);
                        let bypass_status = if r.proxy_ok { "Доступен" } else { "Недоступен" };
                        set_color(Color::Yellow);
                        safe_write_line(&format!(
                            "[АЛЕРТ] Сайт {} трижды подряд недоступен! Статус: {} (Причина: {}, Обход через прокси: {})",
                            r.url, r.status, block_reason, bypass_status
                        ));
                        reset_color();
                    }
                }
            }

            if config.monitor.logging_enabled {
                log_results_async(&results, &config, &script_dir).await;
            }
        }

        need_check = true;

        safe_clear();
        print_banner();

        let h = get_height();
        if h >= 16 {
            safe_write_line(&format!("Мониторинг начался в: {}\n", last_check_time.format("%Y-%m-%d %H:%M:%S")));
        }

        print_results(&results);

        if config.monitor_settings.uptime_enabled && h >= 28 {
            safe_write_line(&"-".repeat(get_width() as usize));
            write_centered("АПТАЙМ ЗА СУТКИ", Some(Color::Cyan));
            safe_write_line(&"-".repeat(get_width() as usize));

            print_uptime(&results, &uptime_history);
        }

        // Interface list if all down
        if !results.is_empty() && results.iter().all(|r| r.status != "OK" && r.status != "WARN") {
            safe_write_line("\nНи один сайт не отвечает. Проверьте сетевое подключение.");
        }

        if config_reloaded {
            config_reloaded = false;
            let current_urls: std::collections::HashSet<String> = config.websites.iter().cloned().collect();
            uptime_history.retain(|k, _| current_urls.contains(k));
            failure_count.retain(|k, _| current_urls.contains(k));
        }

        safe_write_line("");
        let countdown_line_top = get_height().saturating_sub(2);
        let total_delay = config.monitor_settings.interval.max(1) * 1000;
        let delay_step = 100;
        let mut elapsed = 0;
        let mut break_now = false;

        while elapsed < total_delay {
            let remaining = total_delay.saturating_sub(elapsed);
            let remaining_sec = (remaining + 999) / 1000;
            let total_bars = 30;
            let filled_bars = (total_bars as f64 - (remaining as f64 * total_bars as f64) / total_delay as f64).clamp(0.0, total_bars as f64) as usize;
            let progress_bar = format!("{}{}", "█".repeat(filled_bars), "░".repeat(total_bars - filled_bars));

            safe_set_cursor(0, countdown_line_top);
            safe_write("Обн: ");
            set_color(Color::Blue); safe_write("R"); reset_color();
            safe_write(" | Настройки: ");
            set_color(Color::Blue); safe_write("O"); reset_color();
            safe_write(" | Ожидание ");
            safe_write(&format!("[{}] {}s", progress_bar, remaining_sec));
            safe_write(" | ");
            set_color(Color::Red); safe_write("Ctrl+C"); reset_color();
            safe_write(" Выход");
            let _ = execute!(stdout(), Clear(ClearType::UntilNewLine));

            if event::poll(Duration::from_millis(delay_step))? {
                match event::read()? {
                    Event::Key(key) => {
                        if key.kind != event::KeyEventKind::Release {
                            if let KeyCode::Char('c') | KeyCode::Char('C') = key.code {
                                if key.modifiers.contains(KeyModifiers::CONTROL) {
                                    break_now = true;
                                    elapsed = total_delay; // break loop
                                    break;
                                }
                            } else if let KeyCode::Char('r') | KeyCode::Char('R') = key.code {
                                config = load_or_create_config(&config_path);
                                client = build_http_client(&config);
                                config_reloaded = true;
                                break_now = true;
                                break;
                            } else if let KeyCode::Char('o') | KeyCode::Char('O') = key.code {
                                let saved = show_settings_menu(&mut config, &config_path).await?;
                                if saved {
                                    client = build_http_client(&config);
                                    config_reloaded = true;
                                    need_check = true;
                                }
                                break_now = true;
                                break;
                            }
                        }
                    }
                    Event::Resize(_, _) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        need_check = false;
                        break_now = false;
                        break;
                    }
                    _ => {}
                }
            }
            elapsed += delay_step;
        }

        if break_now && elapsed >= total_delay {
            break;
        }
    }

    Ok(())
}

fn build_http_client(config: &Config) -> reqwest::Client {
    let timeout = Duration::from_secs(config.monitor_settings.timeout.max(1));
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    );
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("*/*"),
    );
    reqwest::Client::builder()
        .timeout(timeout)
        .default_headers(headers)
        .build()
        .unwrap_or_default()
}

fn get_block_reason_ru(status: &str) -> &'static str {
    match status {
        "DNS_BLOCK" => "Блокировка DNS",
        "TCP_BLOCK" => "Блокировка TCP",
        "TCP_RESET" => "Сброс TCP (DPI)",
        "TLS_BLOCK" => "Блокировка TLS (SNI DPI)",
        "HTTP_STUB" => "Заглушка провайдера (HTTP)",
        "TIMEOUT" => "Таймаут соединения",
        "SSL_ERROR" => "Ошибка SSL/TLS",
        "CONN_ERROR" => "Ошибка подключения",
        _ => "Неизвестная ошибка",
    }
}
