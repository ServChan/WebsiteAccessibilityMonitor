use chrono::Local;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, List, ListItem, ListState, Padding, Paragraph, Row,
    Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap,
};

use super::app::{
    App, Confirm, FieldKind, InputModal, InputPurpose, Modal, NOT_SET, OFF, ON, Page, SettingField,
    Site, ToastKind, UiProfile, plural,
};
use super::theme::Theme;
use chrono::{DateTime, Utc};

use crate::{
    Health, NoticeLevel, WebsiteResult, status_description, status_health, uptime_percent,
};

pub(crate) const MIN_WIDTH: u16 = 50;
pub(crate) const MIN_HEIGHT: u16 = 14;
const LABEL_WIDTH: usize = 14;

/// Scroll offsets that must survive between frames.
#[derive(Debug, Default)]
pub(crate) struct ViewState {
    sites: TableState,
    uptime: TableState,
    events: TableState,
    settings: ListState,
}

pub(crate) fn render(frame: &mut Frame<'_>, app: &mut App) {
    let mut view = std::mem::take(&mut app.view);
    draw(frame, app, &mut view);
    app.view = view;
}

fn draw(frame: &mut Frame<'_>, app: &App, view: &mut ViewState) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);
    render_header(frame, app, header);
    render_tabs(frame, app, tabs);
    match app.page {
        Page::Overview => render_overview(frame, app, view, body),
        Page::Sites => render_sites_page(frame, app, view, body),
        Page::Uptime => render_uptime(frame, app, view, body),
        Page::Events => render_events(frame, app, view, body),
        Page::Settings => render_settings(frame, app, view, body),
    }
    render_footer(frame, app, footer);

    match &app.modal {
        Some(Modal::Help) => render_help(frame, app, area),
        Some(Modal::Details) => render_details_popup(frame, app, area),
        Some(Modal::Input(modal)) => render_input(frame, app, modal, area),
        Some(Modal::Confirm(confirm)) => render_confirm(frame, app, confirm, area),
        None => {}
    }
    if let Some(toast) = &app.toast {
        render_toast(frame, app, &toast.text, toast.kind, body);
    }
}

// ---------------------------------------------------------------------- helpers

fn panel<'a>(theme: &Theme, title: impl Into<Line<'a>>) -> Block<'a> {
    Block::default()
        .title(title.into())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.border))
        .padding(Padding::horizontal(1))
}

fn modal_panel<'a>(theme: &Theme, title: impl Into<Line<'a>>) -> Block<'a> {
    panel(theme, title)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(theme.accent))
}

fn title(text: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        format!(" {} ", text.into()),
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

fn hint_spans(theme: &Theme, hints: &[(&str, &str)], width: usize) -> Line<'static> {
    let mut spans = Vec::new();
    let mut used = 0;
    for (key, label) in hints {
        let piece = key.chars().count() + label.chars().count() + 3;
        if used + piece > width {
            break;
        }
        if !spans.is_empty() {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled((*key).to_string(), theme.key()));
        spans.push(Span::raw(format!(" {label}")));
        used += piece;
    }
    Line::from(spans)
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

/// Truncates to `width` characters with an ellipsis.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else if width == 0 {
        String::new()
    } else {
        let mut cut: String = text.chars().take(width - 1).collect();
        cut.push('…');
        cut
    }
}

fn status_text(result: Option<&WebsiteResult>) -> String {
    match result {
        None => "ожидает".into(),
        // A planned outage reads as such, not as an alarm.
        Some(result) if result.maintenance && status_health(&result.status) == Health::Down => {
            "ОБСЛУЖИВАНИЕ".into()
        }
        Some(result) => result.status.clone(),
    }
}

fn date_and_days(expires: DateTime<Utc>, days: Option<i64>) -> String {
    let date = expires.with_timezone(&Local).format("%d.%m.%Y");
    match days {
        Some(days) if days < 0 => format!("истёк {date} ({} назад)", days_label(days)),
        Some(days) => format!("до {date} (осталось {})", days_label(days)),
        None => format!("до {date}"),
    }
}

fn days_label(days: i64) -> String {
    plural(days.unsigned_abs() as usize, "день", "дня", "дней")
}

/// Expiry line, highlighted once inside the warning period.
fn expiry_line(
    theme: &Theme,
    label: &str,
    expires: Option<DateTime<Utc>>,
    days: Option<i64>,
    warn_days: i64,
) -> Line<'static> {
    let (value, style) = match expires {
        None => ("нет данных".to_string(), Style::default()),
        Some(expires) => {
            let style = match days {
                Some(days) if days < 0 => Style::default()
                    .fg(theme.error)
                    .add_modifier(Modifier::BOLD),
                Some(days) if days <= warn_days => {
                    Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)
                }
                _ => Style::default(),
            };
            (date_and_days(expires, days), style)
        }
    };
    Line::from(vec![
        Span::styled(
            format!("{label:<LABEL_WIDTH$}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(value, style),
    ])
}

fn expect_text_line(site: &Site, result: Option<&WebsiteResult>) -> Line<'static> {
    let expected = &site.target.expect_text;
    let value = if expected.is_empty() {
        "не задан (T — задать)".to_string()
    } else {
        match result.and_then(|result| result.content_ok) {
            Some(true) => format!("найден «{expected}»"),
            Some(false) => format!("НЕ найден «{expected}»"),
            None => format!("«{expected}», ещё не проверялся"),
        }
    };
    label_line("Текст ответа", value)
}

fn status_style(theme: &Theme, result: Option<&WebsiteResult>) -> Style {
    let health = result.map(WebsiteResult::health);
    let style = Style::default().fg(theme.health(health));
    if health == Some(Health::Down) {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

fn duration_cell(theme: &Theme, result: Option<&WebsiteResult>) -> Cell<'static> {
    match result {
        Some(result) if result.duration_ms > 0 => Cell::from(Span::styled(
            format!("{} мс", result.duration_ms),
            Style::default().fg(theme.duration(result.duration_ms)),
        )),
        _ => Cell::from("—"),
    }
}

fn availability_phrase(count: usize) -> String {
    let verb = if count % 10 == 1 && count % 100 != 11 {
        "недоступен"
    } else {
        "недоступны"
    };
    format!("{} {verb}", plural(count, "сайт", "сайта", "сайтов"))
}

fn render_scrollbar(
    frame: &mut Frame<'_>,
    area: Rect,
    total: usize,
    visible: usize,
    position: usize,
) {
    if total <= visible {
        return;
    }
    // Content length is the number of scroll positions; with the viewport length the thumb
    // size becomes proportional to the visible share of the list.
    let mut state = ScrollbarState::new(total - visible + 1)
        .viewport_content_length(visible)
        .position(position);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼")),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state,
    );
}

// ---------------------------------------------------------------------- chrome

fn render_header(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let brand = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD | Modifier::REVERSED);
    let state = if let Some(scan) = app.scan() {
        Span::styled(
            format!("ПРОВЕРКА {}/{}", scan.done, scan.total),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    } else if app.paused {
        Span::styled(
            "ПАУЗА",
            Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("РАБОТАЕТ", Style::default().fg(theme.ok))
    };
    let full_left = Line::from(vec![
        Span::styled(" WAM ", brand),
        Span::raw(format!(
            " {} {}  ",
            env!("CARGO_PKG_VERSION"),
            app.profile.label()
        )),
        state.clone(),
    ]);
    let short_left = Line::from(vec![Span::styled(" WAM ", brand), Span::raw(" "), state]);

    let summary = app.summary();
    let counts = |pending: bool| {
        let mut spans = vec![
            Span::styled(format!("OK {}", summary.up), Style::default().fg(theme.ok)),
            Span::raw("  "),
            Span::styled(
                format!("WARN {}", summary.warn),
                Style::default().fg(theme.warn),
            ),
            Span::raw("  "),
            Span::styled(
                format!("СБОЙ {}", summary.down),
                Style::default()
                    .fg(theme.error)
                    .add_modifier(if summary.down > 0 {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            ),
        ];
        if pending && summary.pending > 0 {
            spans.push(Span::raw(format!("  ОЖИДАЕТ {}", summary.pending)));
        }
        spans.push(Span::raw(" "));
        Line::from(spans)
    };

    // The counters matter more than the version, so the left side shrinks first.
    let width = area.width as usize;
    let layouts = [
        (full_left.clone(), Some(counts(true))),
        (short_left.clone(), Some(counts(true))),
        (short_left.clone(), Some(counts(false))),
        (full_left, None),
    ];
    let (left, right) = layouts
        .into_iter()
        .find(|(left, right)| left.width() + right.as_ref().map_or(0, Line::width) + 2 <= width)
        .unwrap_or((short_left, None));
    frame.render_widget(Paragraph::new(left), area);
    if let Some(right) = right {
        frame.render_widget(Paragraph::new(right).alignment(Alignment::Right), area);
    }
}

fn render_tabs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let compact = area.width < 64;
    let mut spans = Vec::new();
    for (index, page) in Page::ALL.iter().enumerate() {
        let name = if compact && *page == Page::Settings {
            "Настр."
        } else {
            page.label()
        };
        let mut label = format!("{} {name}", index + 1);
        if *page == Page::Events && app.unread_problems > 0 {
            label.push_str(&format!(" ({})", app.unread_problems));
        }
        let padded = if compact { label } else { format!(" {label} ") };
        let style = if *page == app.page {
            theme.selection().fg(theme.accent)
        } else {
            Style::default()
        };
        spans.push(Span::styled(padded, style));
        spans.push(Span::raw(if compact { " " } else { "  " }));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let width = area.width as usize;
    if let Some(input) = &app.filter_input {
        let value = input.value();
        let mut spans = vec![
            Span::styled("Фильтр: ", theme.key()),
            Span::raw(value.to_string()),
            Span::styled(" ", theme.selection()),
            Span::raw("   "),
        ];
        spans
            .extend(hint_spans(theme, &[("Enter", "применить"), ("Esc", "сбросить")], width).spans);
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        let x = area.x
            + 8
            + input.value()[..byte_offset(value, input.cursor())]
                .chars()
                .count() as u16;
        frame.set_cursor_position((x.min(area.right().saturating_sub(1)), area.y));
        return;
    }

    let hints: &[(&str, &str)] = match app.page {
        Page::Settings => &[
            ("↑↓", "выбор"),
            ("←→", "изменить"),
            ("Enter", "ввод"),
            ("Ctrl+S", "сохранить"),
            ("Del", "сброс"),
            ("Esc", "назад"),
            ("?", "справка"),
        ],
        Page::Events => &[
            ("↑↓", "прокрутка"),
            ("Tab", "раздел"),
            ("R", "проверить"),
            ("?", "справка"),
            ("Q", "выход"),
        ],
        _ => &[
            ("↑↓", "выбор"),
            ("Enter", "подробно"),
            ("R", "проверить"),
            ("A", "добавить"),
            ("D", "удалить"),
            ("T", "текст"),
            ("/", "фильтр"),
            ("?", "справка"),
            ("S", "сортировка"),
            ("P", "пауза"),
            ("Q", "выход"),
        ],
    };
    let mut line = Line::default();
    if !app.filter.is_empty() && app.page.ne(&Page::Settings) {
        line.spans.push(Span::styled(
            format!("Фильтр «{}» ", fit(&app.filter, 20)),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        line.spans.push(Span::styled("Esc", theme.key()));
        line.spans.push(Span::raw(" сбросить   "));
    }
    let used = line.width();
    line.spans
        .extend(hint_spans(theme, hints, width.saturating_sub(used)).spans);
    frame.render_widget(Paragraph::new(line), area);
}

fn byte_offset(value: &str, chars: usize) -> usize {
    value
        .char_indices()
        .nth(chars)
        .map_or(value.len(), |(index, _)| index)
}

// ---------------------------------------------------------------------- overview

fn render_overview(frame: &mut Frame<'_>, app: &App, view: &mut ViewState, area: Rect) {
    if app.profile == UiProfile::Lite {
        render_site_table(frame, app, view, area, TableMode::Compact);
        return;
    }
    let [summary, rest] = Layout::vertical([Constraint::Length(4), Constraint::Min(0)]).areas(area);
    render_summary(frame, app, summary);
    if rest.width >= 100 {
        let [list, details] =
            Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
                .areas(rest);
        render_site_table(frame, app, view, list, TableMode::Compact);
        render_details_panel(frame, app, details);
    } else if rest.height >= 22 {
        let [list, details] =
            Layout::vertical([Constraint::Min(8), Constraint::Length(12)]).areas(rest);
        render_site_table(frame, app, view, list, TableMode::Compact);
        render_details_panel(frame, app, details);
    } else {
        render_site_table(frame, app, view, rest, TableMode::Compact);
    }
}

fn render_summary(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let summary = app.summary();
    let total = summary.total();
    let lead = if summary.down > 0 {
        vec![
            Span::styled(
                availability_phrase(summary.down),
                Style::default()
                    .fg(theme.error)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "   ·   доступны {} из {}",
                summary.available(),
                total
            )),
        ]
    } else if total == 0 {
        vec![Span::raw("Сайтов пока нет")]
    } else if summary.pending == total {
        vec![Span::styled(
            format!(
                "Первая проверка: {}",
                plural(total, "сайт", "сайта", "сайтов")
            ),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )]
    } else if summary.warn > 0 {
        vec![
            Span::styled(
                format!("Доступны {} из {}", summary.available(), total),
                Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   ·   с предупреждением: {}", summary.warn),
                Style::default().fg(theme.warn),
            ),
        ]
    } else {
        vec![Span::styled(
            format!(
                "Все сайты доступны: {} из {}",
                summary.up,
                total - summary.pending
            ),
            Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
        )]
    };

    let mut lead = lead;
    if summary.maintenance > 0 {
        lead.push(Span::styled(
            format!("   ·   на обслуживании: {}", summary.maintenance),
            Style::default().fg(theme.warn),
        ));
    }
    let status = if let Some(scan) = app.scan() {
        let ratio = if scan.total == 0 {
            0.0
        } else {
            scan.done as f64 / scan.total as f64
        };
        let bar_width = 24;
        let filled = (ratio * bar_width as f64).round() as usize;
        Line::from(vec![
            Span::raw(format!("Проверка {} из {}  ", scan.done, scan.total)),
            Span::styled("█".repeat(filled), Style::default().fg(theme.accent)),
            Span::raw("░".repeat(bar_width - filled)),
            Span::raw(format!("  {:.0}%", ratio * 100.0)),
        ])
    } else {
        let mut parts = Vec::new();
        if let Some(cycle) = app.last_cycle() {
            parts.push(format!(
                "проверено в {} за {:.1} с",
                cycle.finished_at.format("%H:%M:%S"),
                cycle.duration.as_secs_f64()
            ));
        }
        match app.next_check() {
            None => parts.push("автопроверки на паузе (P — продолжить)".into()),
            Some(delay) => parts.push(format!("следующая через {} с", delay.as_secs().max(1))),
        }
        if let Some(average) = summary.average_ms {
            parts.push(format!("среднее время ответа {average} мс"));
        }
        Line::from(capitalize(&parts.join("  ·  ")))
    };

    frame.render_widget(
        Paragraph::new(vec![Line::from(lead), status]).block(panel(theme, title("Сводка"))),
        area,
    );
}

fn capitalize(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableMode {
    Compact,
    Full,
}

fn render_sites_page(frame: &mut Frame<'_>, app: &App, view: &mut ViewState, area: Rect) {
    if app.profile == UiProfile::Full && area.height >= 26 {
        let [table, details] =
            Layout::vertical([Constraint::Min(10), Constraint::Length(12)]).areas(area);
        render_site_table(frame, app, view, table, TableMode::Full);
        render_details_panel(frame, app, details);
    } else {
        render_site_table(frame, app, view, area, TableMode::Full);
    }
}

fn render_no_matches(frame: &mut Frame<'_>, app: &App, area: Rect, heading: &str) {
    let theme = &app.theme;
    if app.filter.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from(Span::styled(
                "Сайтов пока нет",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("A", theme.key()),
                Span::raw(" — добавить первый сайт: проверка начнётся сразу"),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .block(panel(theme, title(heading))),
            area,
        );
        return;
    }
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("Ничего не найдено по запросу «{}»", app.filter),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Esc", theme.key()),
            Span::raw(" — сбросить фильтр,  "),
            Span::styled("/", theme.key()),
            Span::raw(" — изменить запрос"),
        ]),
        Line::from("Поиск идёт по адресу, группе, статусу и его описанию."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(panel(theme, title(heading))),
        area,
    );
}

fn table_title(app: &App, heading: &str, shown: usize) -> Line<'static> {
    let mut text = format!("{heading} · {shown}");
    if shown != app.sites().len() {
        text.push_str(&format!(" из {}", app.sites().len()));
    }
    text.push_str(&format!(" · {}", app.sort_mode.label()));
    title(text)
}

fn render_site_table(
    frame: &mut Frame<'_>,
    app: &App,
    view: &mut ViewState,
    area: Rect,
    mode: TableMode,
) {
    let theme = &app.theme;
    let visible = app.visible_sites();
    if visible.is_empty() {
        render_no_matches(frame, app, area, "Сайты");
        return;
    }
    let width = area.width;
    let show_group = mode == TableMode::Full && app.has_groups() && width >= 96;
    let show_ip = mode == TableMode::Full && width >= 84;
    let show_retries = mode == TableMode::Full && width >= 112;
    let show_cert = mode == TableMode::Full && width >= 100;
    let show_code = mode == TableMode::Full || width >= 64;

    let mut header = vec!["Статус", "Адрес"];
    let mut widths = vec![Constraint::Length(13), Constraint::Min(16)];
    if show_group {
        header.push("Группа");
        widths.push(Constraint::Length(14));
    }
    if show_code {
        header.push("HTTP");
        widths.push(Constraint::Length(5));
    }
    header.push("Время");
    widths.push(Constraint::Length(9));
    if show_ip {
        header.push("IP");
        widths.push(Constraint::Length(17));
    }
    if show_cert {
        header.push("Серт.");
        widths.push(Constraint::Length(6));
    }
    if show_retries {
        header.push("Повт.");
        widths.push(Constraint::Length(5));
    }

    let rows = visible.iter().map(|site| {
        let result = app.result(site);
        let mut address = site.target.url.clone();
        if !show_group && !site.target.group_name.is_empty() {
            address = format!("{address}  [{}]", site.target.group_name);
        }
        let mut cells = vec![
            Cell::from(Span::styled(
                status_text(result),
                status_style(theme, result),
            )),
            Cell::from(address),
        ];
        if show_group {
            cells.push(Cell::from(site.target.group_name.clone()));
        }
        if show_code {
            cells.push(Cell::from(
                result
                    .map(|result| result.code.clone())
                    .filter(|code| !code.is_empty())
                    .unwrap_or_else(|| "—".into()),
            ));
        }
        cells.push(duration_cell(theme, result));
        if show_ip {
            cells.push(Cell::from(
                result
                    .map(|result| result.ip.clone())
                    .unwrap_or_else(|| "—".into()),
            ));
        }
        if show_cert {
            let warn_days = i64::from(app.config().monitor_settings.cert_warn_days);
            cells.push(match result.and_then(|result| result.cert_days_left) {
                Some(days) => {
                    let style = if days <= warn_days {
                        Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Cell::from(Span::styled(format!("{days} д"), style))
                }
                None => Cell::from("—"),
            });
        }
        if show_retries {
            cells.push(Cell::from(
                result.map_or_else(|| "—".into(), |result| result.retries.to_string()),
            ));
        }
        Row::new(cells)
    });

    let selected = app.selected_index(&visible);
    view.sites.select(selected);
    let table = Table::new(rows, widths)
        .header(Row::new(header).style(theme.heading()))
        .row_highlight_style(theme.selection())
        .highlight_symbol("> ")
        .column_spacing(1)
        .block(panel(theme, table_title(app, "Сайты", visible.len())));
    frame.render_stateful_widget(table, area, &mut view.sites);
    let body_rows = area.height.saturating_sub(3) as usize;
    render_scrollbar(frame, area, visible.len(), body_rows, view.sites.offset());
}

// ---------------------------------------------------------------------- details

fn label_line(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<LABEL_WIDTH$}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.into()),
    ])
}

fn ip_list(ips: &[String]) -> String {
    match ips.len() {
        0 => "нет ответа".into(),
        1..=3 => ips.join(", "),
        count => format!("{} и ещё {}", ips[..3].join(", "), count - 3),
    }
}

fn detail_lines(app: &App, site: &Site) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let result = app.result(site);
    let mut lines = Vec::new();
    let Some(result) = result else {
        lines.push(Line::from(Span::styled(
            "Ожидает первой проверки",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(label_line("Адрес", site.target.url.clone()));
        if !site.target.group_name.is_empty() {
            lines.push(label_line("Группа", site.target.group_name.clone()));
        }
        lines.push(label_line(
            "Интервал",
            format!("{} с", site.target.interval),
        ));
        lines.push(expect_text_line(site, None));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::raw("Проверка начнётся автоматически. "),
            Span::styled("R", theme.key()),
            Span::raw(" — проверить все сайты сейчас."),
        ]));
        return lines;
    };

    lines.push(Line::from(vec![
        Span::styled(result.status.clone(), status_style(theme, Some(result))),
        Span::raw(format!(" — {}", status_description(&result.status))),
    ]));
    if result.maintenance {
        lines.push(Line::from(Span::styled(
            "Идёт окно обслуживания: уведомления не отправляются, аптайм не учитывается.",
            Style::default().fg(theme.warn),
        )));
    }
    lines.push(Line::from(""));
    lines.push(label_line("Адрес", result.url.clone()));
    if !result.group_name.is_empty() {
        lines.push(label_line("Группа", result.group_name.clone()));
    }
    let code = if result.code.is_empty() {
        "—"
    } else {
        &result.code
    };
    lines.push(label_line(
        "HTTP",
        format!(
            "{code} · {} · повторов: {}",
            result.http_method, result.retries
        ),
    ));
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<LABEL_WIDTH$}", "Время ответа"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} мс", result.duration_ms),
            Style::default().fg(theme.duration(result.duration_ms)),
        ),
    ]));
    lines.push(label_line("IP (система)", ip_list(&result.system_ips)));
    lines.push(label_line("IP (DoH)", ip_list(&result.reference_ips)));
    let dns = if result.system_ips.is_empty() || result.reference_ips.is_empty() {
        "сравнение невозможно"
    } else if result.dns_anomaly {
        "расходится с DoH (для CDN это бывает нормой)"
    } else {
        "совпадает с DoH"
    };
    lines.push(label_line("DNS", dns));
    let icmp = match result.icmp_ok {
        Some(true) => "отвечает",
        Some(false) => "нет ответа",
        None => "не проверялся",
    };
    lines.push(label_line("ICMP", icmp));
    let proxy = if app.config().monitor_settings.proxy_url.is_empty() {
        "не настроен"
    } else if result.proxy_ok {
        "через прокси доступен"
    } else if result.is_available() {
        "не требовался"
    } else {
        "через прокси тоже недоступен"
    };
    lines.push(label_line("Прокси", proxy));
    lines.push(expect_text_line(site, Some(result)));
    let settings = &app.config().monitor_settings;
    if result.url.starts_with("https://") {
        lines.push(expiry_line(
            theme,
            "Сертификат",
            result.cert_expires,
            result.cert_days_left,
            i64::from(settings.cert_warn_days),
        ));
    }
    if settings.domain_check_enabled {
        lines.push(expiry_line(
            theme,
            "Домен",
            result.domain_expires,
            result.domain_days_left,
            i64::from(settings.domain_warn_days),
        ));
    }
    if site.target.slow_threshold_ms > 0 {
        lines.push(label_line(
            "Порог ответа",
            format!("{} мс", site.target.slow_threshold_ms),
        ));
    }
    if app.config().monitor_settings.uptime_enabled {
        let samples = app.uptime(site);
        let uptime = uptime_percent(samples).map_or_else(
            || "нет данных".into(),
            |value| {
                format!(
                    "{value:.1} % из {}",
                    plural(samples.len(), "замера", "замеров", "замеров")
                )
            },
        );
        lines.push(label_line("Аптайм 24 ч", uptime));
    }
    if let Some(time) = app.checked_at(site) {
        lines.push(label_line(
            "Проверено",
            format!(
                "{} · интервал {} с",
                time.format("%H:%M:%S"),
                site.target.interval
            ),
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Диагностика", theme.heading())));
    lines.push(Line::from(if result.details.is_empty() {
        "Дополнительных сведений нет.".to_string()
    } else {
        result.details.clone()
    }));
    lines
}

fn render_details_panel(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let lines = match app.selected_site() {
        Some(site) => detail_lines(app, site),
        None => vec![Line::from("Выберите сайт в списке.")],
    };
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            panel(theme, title("Подробности")).title_bottom(Line::from(vec![
                Span::styled(" Enter", theme.key()),
                Span::raw(" — во весь экран "),
            ])),
        ),
        area,
    );
}

fn render_details_popup(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let popup = centered_rect(
        84.min(area.width.saturating_sub(4)),
        26.min(area.height.saturating_sub(2)),
        area,
    );
    let lines = match app.selected_site() {
        Some(site) => detail_lines(app, site),
        None => vec![Line::from("Сайт не выбран.")],
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            modal_panel(theme, title("Подробности")).title_bottom(Line::from(vec![
                Span::styled(" ↑↓", theme.key()),
                Span::raw(" другой сайт  "),
                Span::styled("Esc", theme.key()),
                Span::raw(" закрыть "),
            ])),
        ),
        popup,
    );
}

// ---------------------------------------------------------------------- uptime

fn render_uptime(frame: &mut Frame<'_>, app: &App, view: &mut ViewState, area: Rect) {
    let theme = &app.theme;
    if !app.config().monitor_settings.uptime_enabled {
        let message = vec![
            Line::from(Span::styled(
                "История аптайма выключена",
                Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Включите её, чтобы видеть процент доступности и полосу событий"),
            Line::from("за последние 24 часа по каждому сайту."),
            Line::from(""),
            Line::from(vec![
                Span::styled("5", theme.key()),
                Span::raw(" Настройки → «История аптайма» → "),
                Span::styled("Enter", theme.key()),
                Span::raw(" → "),
                Span::styled("Ctrl+S", theme.key()),
            ]),
        ];
        let block = panel(theme, title("Аптайм"));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let height = (message.len() as u16).min(inner.height);
        let centered = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(height) / 2,
            inner.width,
            height,
        );
        frame.render_widget(
            Paragraph::new(message)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            centered,
        );
        return;
    }
    let visible = app.visible_sites();
    if visible.is_empty() {
        render_no_matches(frame, app, area, "Аптайм");
        return;
    }
    let history_width = area
        .width
        .saturating_sub(13 + 24 + 8 + 9 + 4 + 6 + 4)
        .max(8) as usize;
    let rows = visible.iter().map(|site| {
        let result = app.result(site);
        let samples = app.uptime(site);
        let percent = uptime_percent(samples);
        let percent_cell = match percent {
            None => Cell::from("нет данных"),
            Some(value) => {
                let color = if value >= 99.0 {
                    theme.ok
                } else if value >= 95.0 {
                    theme.warn
                } else {
                    theme.error
                };
                Cell::from(Span::styled(
                    format!("{value:.1} %"),
                    Style::default().fg(color),
                ))
            }
        };
        Row::new(vec![
            Cell::from(Span::styled(
                status_text(result),
                status_style(theme, result),
            )),
            Cell::from(site.target.url.clone()),
            percent_cell,
            Cell::from(samples.len().to_string()),
            Cell::from(history_bar(theme, samples, history_width)),
        ])
    });
    let widths = [
        Constraint::Length(13),
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(history_width as u16),
    ];
    view.uptime.select(app.selected_index(&visible));
    let legend = Line::from(vec![
        Span::styled(" █", Style::default().fg(theme.ok)),
        Span::raw(" доступен  "),
        Span::styled("▁", Style::default().fg(theme.error)),
        Span::raw(" сбой · новые справа "),
    ]);
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "Статус",
                "Адрес",
                "Аптайм",
                "Замеров",
                "Последние замеры",
            ])
            .style(theme.heading()),
        )
        .row_highlight_style(theme.selection())
        .highlight_symbol("> ")
        .block(
            panel(theme, table_title(app, "Аптайм за 24 часа", visible.len())).title_bottom(legend),
        );
    frame.render_stateful_widget(table, area, &mut view.uptime);
    render_scrollbar(
        frame,
        area,
        visible.len(),
        area.height.saturating_sub(3) as usize,
        view.uptime.offset(),
    );
}

/// Most recent `width` samples as a bar: tall block for success, low bar for failure.
/// The two glyphs differ in shape, so the bar also reads without colour.
fn history_bar(theme: &Theme, samples: &[bool], width: usize) -> Line<'static> {
    let start = samples.len().saturating_sub(width);
    let recent = &samples[start..];
    let mut spans = Vec::new();
    if recent.len() < width {
        spans.push(Span::raw(" ".repeat(width - recent.len())));
    }
    let mut index = 0;
    while index < recent.len() {
        let value = recent[index];
        let run = recent[index..]
            .iter()
            .take_while(|sample| **sample == value)
            .count();
        let (glyph, color) = if value {
            ("█", theme.ok)
        } else {
            ("▁", theme.error)
        };
        spans.push(Span::styled(glyph.repeat(run), Style::default().fg(color)));
        index += run;
    }
    Line::from(spans)
}

// ---------------------------------------------------------------------- events

fn level_label(level: NoticeLevel) -> &'static str {
    match level {
        NoticeLevel::Info => "инфо",
        NoticeLevel::Warning => "внимание",
        NoticeLevel::Error => "ошибка",
    }
}

fn render_events(frame: &mut Frame<'_>, app: &App, view: &mut ViewState, area: Rect) {
    let theme = &app.theme;
    if app.events.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Событий пока нет",
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("Здесь появятся сбои и восстановления сайтов, итоги проверок,"),
                Line::from("ошибки сохранения файлов и отправки уведомлений."),
            ])
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(panel(theme, title("События"))),
            area,
        );
        return;
    }
    let [list, detail] = Layout::vertical([Constraint::Min(5), Constraint::Length(5)]).areas(area);
    let today = Local::now().date_naive();
    let rows = app.events.iter().map(|entry| {
        let color = match entry.level {
            NoticeLevel::Info => ratatui::style::Color::Reset,
            NoticeLevel::Warning => theme.warn,
            NoticeLevel::Error => theme.error,
        };
        let time = if entry.time.date_naive() == today {
            entry.time.format("%H:%M:%S").to_string()
        } else {
            entry.time.format("%d.%m %H:%M").to_string()
        };
        Row::new(vec![
            Cell::from(time),
            Cell::from(Span::styled(
                level_label(entry.level),
                Style::default().fg(color),
            )),
            Cell::from(entry.text.clone()),
        ])
    });
    let selected = app.events_selected.min(app.events.len() - 1);
    view.events.select(Some(selected));
    let table = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(Row::new(vec!["Время", "Уровень", "Событие"]).style(theme.heading()))
    .row_highlight_style(theme.selection())
    .highlight_symbol("> ")
    .block(panel(
        theme,
        title(format!("События · {} · новые сверху", app.events.len())),
    ));
    frame.render_stateful_widget(table, list, &mut view.events);
    render_scrollbar(
        frame,
        list,
        app.events.len(),
        list.height.saturating_sub(3) as usize,
        view.events.offset(),
    );
    let entry = &app.events[selected];
    frame.render_widget(
        Paragraph::new(entry.text.clone())
            .wrap(Wrap { trim: true })
            .block(panel(
                theme,
                title(format!(
                    "{} · {}",
                    entry.time.format("%d.%m.%Y %H:%M:%S"),
                    level_label(entry.level)
                )),
            )),
        detail,
    );
}

// ---------------------------------------------------------------------- settings

fn render_settings(frame: &mut Frame<'_>, app: &App, view: &mut ViewState, area: Rect) {
    let theme = &app.theme;
    let [list_area, help_area] = if area.width >= 96 {
        Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(area)
    } else {
        Layout::vertical([Constraint::Min(6), Constraint::Length(9)]).areas(area)
    };

    let mut items = Vec::new();
    let mut selected_line = 0;
    let mut section = None;
    let label_width = 29;
    for (index, field) in SettingField::ALL.iter().enumerate() {
        if section != Some(field.section()) {
            section = Some(field.section());
            if index > 0 {
                items.push(ListItem::new(""));
            }
            items.push(ListItem::new(Line::from(Span::styled(
                field.section().label().to_uppercase(),
                theme.heading(),
            ))));
        }
        if index == app.settings_selected {
            selected_line = items.len();
        }
        let value = app.setting_value(*field);
        let changed = app.setting_changed(*field);
        let value_style = match value.as_str() {
            ON => Style::default().fg(theme.ok).add_modifier(Modifier::BOLD),
            OFF | NOT_SET => Style::default(),
            _ => Style::default().add_modifier(Modifier::BOLD),
        };
        items.push(ListItem::new(Line::from(vec![
            Span::raw(if changed { "* " } else { "  " }),
            Span::raw(format!("{:<label_width$}", field.label())),
            Span::styled(value, value_style),
        ])));
    }
    let total_lines = items.len();
    view.settings.select(Some(selected_line));
    let mut heading = String::from("Настройки");
    if app.settings_dirty() {
        heading.push_str(" · * изменено, Ctrl+S — сохранить");
    }
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(theme.selection())
            .block(panel(theme, title(heading))),
        list_area,
        &mut view.settings,
    );
    render_scrollbar(
        frame,
        list_area,
        total_lines,
        list_area.height.saturating_sub(2) as usize,
        view.settings.offset(),
    );

    let field = SettingField::ALL[app.settings_selected];
    let controls: Vec<(&str, String)> = match field.kind() {
        FieldKind::Number { min, max, step, .. } => vec![
            ("←→", format!("шаг {step}")),
            ("Enter", format!("ввести число от {min} до {max}")),
        ],
        FieldKind::Toggle => vec![("Enter / Space / ←→", "переключить".into())],
        FieldKind::Choice => vec![("←→ / Enter", "выбрать вариант".into())],
        FieldKind::Text => vec![("Enter", "изменить".into()), ("Del", "сбросить".into())],
        FieldKind::Secret => vec![
            ("Enter", "ввести новое значение".into()),
            ("Del", "удалить".into()),
        ],
    };
    let mut help = vec![
        Line::from(Span::styled(field.label(), theme.heading())),
        Line::from(field.description()),
        Line::from(""),
    ];
    for (key, label) in controls {
        help.push(Line::from(vec![
            Span::styled(key, theme.key()),
            Span::raw(format!(" — {label}")),
        ]));
    }
    help.push(Line::from(vec![
        Span::styled("Ctrl+S", theme.key()),
        Span::raw(" — сохранить,  "),
        Span::styled("Esc", theme.key()),
        Span::raw(" — выйти"),
    ]));
    if !app.config_writable {
        help.push(Line::from(""));
        help.push(Line::from(Span::styled(
            "config.json повреждён: сохранение отключено. Исправьте файл и нажмите Ctrl+R.",
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        )));
    }
    frame.render_widget(
        Paragraph::new(help)
            .wrap(Wrap { trim: true })
            .block(panel(theme, title("Параметр"))),
        help_area,
    );
}

// ---------------------------------------------------------------------- modals

fn render_help(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let popup = centered_rect(
        76.min(area.width.saturating_sub(4)),
        31.min(area.height.saturating_sub(2)),
        area,
    );
    let section = |name: &str| Line::from(Span::styled(name.to_string(), theme.heading()));
    let entry = |keys: &str, text: &str| {
        Line::from(vec![
            Span::styled(format!("{keys:<16}"), theme.key()),
            Span::raw(text.to_string()),
        ])
    };
    let text = vec![
        section("Навигация"),
        entry("1–5, Tab", "перейти в раздел (Shift+Tab — назад)"),
        entry("↑↓, J/K", "выбрать строку; PgUp/PgDn, Home/End — быстрее"),
        entry("Enter", "подробности о выбранном сайте"),
        entry("/", "фильтр по адресу, группе или статусу; Esc — сбросить"),
        Line::from(""),
        section("Сайты и проверки"),
        entry("R, F5", "проверить все сайты сейчас"),
        entry("P", "пауза / продолжение автопроверок"),
        entry("S", "сортировка: проблемы → адрес → время ответа"),
        entry("A", "добавить сайт"),
        entry("T", "текст, который должен быть в ответе сайта"),
        entry("D, Del", "удалить выбранный сайт (с подтверждением)"),
        entry("E", "сохранить текущие результаты в CSV"),
        Line::from(""),
        section("Настройки"),
        entry("←→, Enter", "изменить значение; Del — сбросить поле"),
        entry("Ctrl+S", "сохранить настройки в config.json"),
        entry("Ctrl+R", "перечитать config.json с диска"),
        Line::from(""),
        section("Общее"),
        entry("? / F1", "эта справка"),
        entry("Q, Ctrl+C", "выход"),
        Line::from(""),
        Line::from("Горячие клавиши работают и в русской раскладке."),
        Line::from("Статус всегда подписан текстом: цвет — лишь дополнительная подсказка."),
    ];
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(
            modal_panel(theme, title("Справка"))
                .title_bottom(Line::from(vec![Span::raw(" Любая клавиша — закрыть ")])),
        ),
        popup,
    );
}

fn render_input(frame: &mut Frame<'_>, app: &App, modal: &InputModal, area: Rect) {
    let theme = &app.theme;
    let (heading, prompt) = match &modal.purpose {
        InputPurpose::ExpectText(identity) => (
            "Ожидаемый текст ответа".to_string(),
            format!(
                "Ответ {identity} должен содержать этот текст, иначе статус станет CONTENT_MISMATCH. Регистр не важен. Пусто — не проверять."
            ),
        ),
        InputPurpose::AddSite => (
            "Добавить сайт".to_string(),
            "Адрес сайта. Схему можно не указывать: example.com станет https://example.com/."
                .to_string(),
        ),
        InputPurpose::Setting(field) => {
            let mut prompt = field.description().to_string();
            if let FieldKind::Number { min, max, .. } = field.kind() {
                prompt.push_str(&format!(" Целое число от {min} до {max}."));
            }
            (field.label().to_string(), prompt)
        }
    };
    let width = 76.min(area.width.saturating_sub(4));
    let inner_width = width.saturating_sub(4) as usize;
    let prompt_lines = prompt.chars().count().div_ceil(inner_width.max(1)) as u16;
    let error_lines = modal.error.as_ref().map_or(0, |error| {
        error.chars().count().div_ceil(inner_width.max(1)) as u16 + 1
    });
    let height = (prompt_lines + error_lines + 7).min(area.height.saturating_sub(2));
    let popup = centered_rect(width, height, area);

    // Horizontal window that keeps the cursor visible in long values.
    let field_width = inner_width.saturating_sub(3).max(1);
    let characters: Vec<char> = if modal.masked {
        vec!['•'; modal.input.len()]
    } else {
        modal.input.value().chars().collect()
    };
    let cursor = modal.input.cursor();
    let start = cursor.saturating_sub(field_width.saturating_sub(1));
    let before: String = characters[start..cursor].iter().collect();
    let at = characters.get(cursor).map_or(' ', |character| *character);
    let after: String = characters
        .iter()
        .skip(cursor + 1)
        .take(field_width.saturating_sub(before.chars().count() + 1))
        .collect();

    let mut lines = vec![
        Line::from(prompt),
        Line::from(""),
        Line::from(vec![
            Span::styled("> ", theme.key()),
            Span::styled(
                before.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(at.to_string(), theme.selection()),
            Span::styled(after, Style::default().add_modifier(Modifier::BOLD)),
        ]),
    ];
    if let Some(error) = &modal.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default()
                .fg(theme.error)
                .add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(""));
    let mut hint = vec![
        Span::styled("Enter", theme.key()),
        Span::raw(" — сохранить   "),
        Span::styled("Esc", theme.key()),
        Span::raw(" — отмена"),
    ];
    if modal.keep_existing {
        hint.push(Span::raw("   · пусто — оставить текущее"));
    }
    lines.push(Line::from(hint));

    frame.render_widget(Clear, popup);
    let block = modal_panel(theme, title(heading));
    let inner = block.inner(popup);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        popup,
    );
    let cursor_x = inner.x + 2 + before.chars().count() as u16;
    let cursor_y = inner.y + prompt_lines + 1;
    if cursor_y < inner.bottom() {
        frame.set_cursor_position((cursor_x.min(inner.right().saturating_sub(1)), cursor_y));
    }
}

fn render_confirm(frame: &mut Frame<'_>, app: &App, confirm: &Confirm, area: Rect) {
    let theme = &app.theme;
    let danger = Style::default()
        .fg(theme.error)
        .add_modifier(Modifier::BOLD);
    let (heading, lines) = match confirm {
        Confirm::RemoveSite { url, .. } => (
            "Удалить сайт?",
            vec![
                Line::from(Span::styled(
                    url.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(
                    "Сайт исчезнет из мониторинга и из config.json вместе с историей аптайма.",
                ),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Enter", danger),
                    Span::styled(" — удалить", danger),
                    Span::raw("      "),
                    Span::styled("Esc", theme.key()),
                    Span::raw(" — отмена"),
                ]),
            ],
        ),
        Confirm::UnsavedSettings(_) => (
            "Несохранённые изменения",
            vec![
                Line::from("Вы изменили настройки, но не сохранили их."),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Enter", theme.key()),
                    Span::raw(" — сохранить   "),
                    Span::styled("N", theme.key()),
                    Span::raw(" — не сохранять   "),
                    Span::styled("Esc", theme.key()),
                    Span::raw(" — остаться"),
                ]),
            ],
        ),
    };
    let width = 70.min(area.width.saturating_sub(4));
    let height = (lines.len() as u16 + 4).min(area.height.saturating_sub(2));
    let popup = centered_rect(width, height, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(modal_panel(theme, title(heading))),
        popup,
    );
}

fn render_toast(frame: &mut Frame<'_>, app: &App, text: &str, kind: ToastKind, body: Rect) {
    let theme = &app.theme;
    let (label, color) = match kind {
        ToastKind::Info => ("Инфо", theme.accent),
        ToastKind::Success => ("Готово", theme.ok),
        ToastKind::Warning => ("Внимание", theme.warn),
        ToastKind::Error => ("Ошибка", theme.error),
    };
    let max_width = body.width.saturating_sub(4).min(72);
    let content_width = max_width.saturating_sub(4).max(1) as usize;
    let text_width = text.chars().count();
    let width = (text_width.min(content_width) as u16 + 4).max(label.chars().count() as u16 + 6);
    let height = (text_width.div_ceil(content_width) as u16 + 2).min(6);
    let popup = Rect::new(
        body.right().saturating_sub(width + 1),
        body.bottom().saturating_sub(height),
        width,
        height,
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(Text::from(text.to_string()))
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(color))
                    .padding(Padding::horizontal(1))
                    .title(Span::styled(
                        format!(" {label} "),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )),
            ),
        popup,
    );
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Окно слишком маленькое",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("Нужно не меньше {MIN_WIDTH} × {MIN_HEIGHT}")),
        Line::from(format!("Сейчас {} × {}", area.width, area.height)),
        Line::from("Q — выход"),
    ];
    let height = (lines.len() as u16).min(area.height);
    let centered = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(height) / 2,
        area.width,
        height,
    );
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        centered,
    );
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::super::app::tests::{test_app, test_app_with};
    use super::*;
    use crate::monitor::ScanMessage;

    fn render_text(width: u16, height: u16, configure: impl FnOnce(&mut App)) -> String {
        let (mut app, _directory) = test_app();
        configure(&mut app);
        render_app(&mut app, width, height)
    }

    fn render_app(app: &mut App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn narrow_terminal_gets_usable_fallback() {
        let output = render_text(40, 10, |_| {});
        assert!(output.contains("Окно слишком маленькое"));
        assert!(output.contains("50 × 14"));
    }

    #[test]
    fn overview_shows_navigation_pending_sites_and_hints() {
        let output = render_text(110, 32, |_| {});
        assert!(output.contains("WAM"));
        assert!(output.contains("5 Настройки"));
        assert!(output.contains("Первая проверка: 3 сайта"));
        assert!(output.contains("ожидает"));
        assert!(output.contains("a.example"));
        assert!(output.contains("справка"));
    }

    #[test]
    fn every_page_renders_at_minimum_size() {
        for page in Page::ALL {
            let output = render_text(MIN_WIDTH, MIN_HEIGHT, |app| app.page = page);
            assert!(output.contains("WAM"), "{page:?}\n{output}");
        }
    }

    #[test]
    fn disabled_uptime_explains_how_to_enable_it() {
        let (mut app, _directory) = test_app_with(|config| {
            config.monitor_settings.uptime_enabled = false;
        });
        app.page = Page::Uptime;
        let output = render_app(&mut app, 100, 30);
        assert!(output.contains("История аптайма выключена"));
        assert!(output.contains("Ctrl+S"));
    }

    #[test]
    fn empty_site_list_points_to_adding_a_site() {
        let (mut app, _directory) = test_app_with(|config| config.websites.clear());
        for page in [Page::Overview, Page::Sites, Page::Uptime] {
            app.page = page;
            let output = render_app(&mut app, 100, 30);
            assert!(output.contains("Сайтов пока нет"), "{page:?}\n{output}");
        }
    }

    #[test]
    fn secrets_are_absent_from_settings_and_editor() {
        let output = render_text(110, 34, |app| {
            app.page = Page::Settings;
            app.settings_draft.webhooks.telegram_bot_token = "do-not-render-this-token".into();
            app.settings_selected = SettingField::ALL
                .iter()
                .position(|field| *field == SettingField::TelegramToken)
                .unwrap();
            app.begin_setting_input(SettingField::TelegramToken);
            for character in "typed-secret".chars() {
                app.handle_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
            }
        });
        assert!(!output.contains("do-not-render-this-token"));
        assert!(!output.contains("typed-secret"));
        assert!(output.contains("Telegram Bot Token"));
    }

    #[test]
    fn details_show_expiry_dates_expected_text_and_maintenance() {
        let output = render_text(120, 40, |app| {
            let mut config = app.config().clone();
            config.maintenance_windows = vec![crate::MaintenanceWindow {
                name: "бэкап".into(),
                days: Vec::new(),
                start: "00:00".into(),
                end: "00:00".into(),
                targets: vec!["b.example".into()],
            }];
            crate::set_expect_text(&mut config, "https://a.example/", "Корзина");
            app.monitor.set_config(config).unwrap();
            let mut ok = WebsiteResult::pending("https://a.example/");
            ok.status = "CERT_EXPIRING".into();
            ok.code = "200".into();
            ok.direct_ok = true;
            ok.content_ok = Some(true);
            ok.cert_expires = Some(chrono::Utc::now() + chrono::Duration::days(5));
            ok.cert_days_left = Some(5);
            let mut down = WebsiteResult::pending("https://b.example/");
            down.status = "TCP_TIMEOUT".into();
            for (identity, result) in [("https://a.example/", ok), ("https://b.example/", down)] {
                app.monitor.handle(ScanMessage::Result {
                    identity: identity.into(),
                    started: std::time::Instant::now(),
                    result: Box::new(result),
                });
            }
            app.page = Page::Sites;
            app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
            for character in "a.example".chars() {
                app.handle_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
            }
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        });
        assert!(output.contains("найден «Корзина»"), "{output}");
        assert!(output.contains("Сертификат"));
        assert!(output.contains("осталось 5 дней") || output.contains("осталось 4 дня"));

        let maintenance = render_text(120, 30, |app| {
            let mut config = app.config().clone();
            config.maintenance_windows = vec![crate::MaintenanceWindow {
                name: String::new(),
                days: Vec::new(),
                start: "00:00".into(),
                end: "00:00".into(),
                targets: Vec::new(),
            }];
            app.monitor.set_config(config).unwrap();
            let mut down = WebsiteResult::pending("https://b.example/");
            down.status = "TCP_TIMEOUT".into();
            app.monitor.handle(ScanMessage::Result {
                identity: "https://b.example/".into(),
                started: std::time::Instant::now(),
                result: Box::new(down),
            });
            app.page = Page::Sites;
        });
        assert!(maintenance.contains("ОБСЛУЖИВАНИЕ"), "{maintenance}");
    }

    #[test]
    fn history_bar_uses_distinct_glyphs() {
        let line = history_bar(&Theme::monochrome(), &[true, true, false, true], 6);
        let text: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert_eq!(text, "  ██▁█");
    }

    #[test]
    fn fit_adds_ellipsis() {
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abc", 4), "abc");
    }
}
