use std::cmp::Ordering;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use super::input::{InputAction, LineInput};
use super::theme::Theme;
use super::view::ViewState;
pub(crate) use crate::monitor::{CycleSummary, ScanProgress, Site, Summary, plural};
use crate::monitor::{Monitor, MonitorEvent, ScanMessage};
use crate::{
    Config, Health, Notice, NoticeLevel, WebsiteResult, add_website, export_csv_async,
    get_default_config, normalize_target_url, redact_proxy_url, remove_target, save_config,
    set_expect_text, status_description, try_load_config,
};

const MAX_EVENTS: usize = 500;
const PAGE_STEP: isize = 10;
const TOAST_DURATION: Duration = Duration::from_secs(4);
const ERROR_TOAST_DURATION: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiProfile {
    /// All panels: summary strip and a side panel with details on wide screens.
    Full,
    /// Same features in a compact layout with a slower redraw; for narrow windows and SSH/RDP.
    Lite,
}

impl UiProfile {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Lite => "LITE",
        }
    }

    pub(crate) const fn tick(self) -> Duration {
        match self {
            Self::Full => Duration::from_millis(250),
            Self::Lite => Duration::from_millis(1_000),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    Overview,
    Sites,
    Uptime,
    Events,
    Settings,
}

impl Page {
    pub(crate) const ALL: [Self; 5] = [
        Self::Overview,
        Self::Sites,
        Self::Uptime,
        Self::Events,
        Self::Settings,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Обзор",
            Self::Sites => "Сайты",
            Self::Uptime => "Аптайм",
            Self::Events => "События",
            Self::Settings => "Настройки",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|page| *page == self).unwrap_or(0)
    }

    const fn lists_sites(self) -> bool {
        matches!(self, Self::Overview | Self::Sites | Self::Uptime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SortMode {
    Status,
    Url,
    Duration,
}

impl SortMode {
    fn from_config(value: &str) -> Self {
        match value {
            "url" => Self::Url,
            "duration" => Self::Duration,
            _ => Self::Status,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Status => "проблемы сверху",
            Self::Url => "по адресу",
            Self::Duration => "медленные сверху",
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::Status => Self::Url,
            Self::Url => Self::Duration,
            Self::Duration => Self::Status,
        }
    }

    const fn config_value(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Url => "url",
            Self::Duration => "duration",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub(crate) struct Toast {
    pub(crate) text: String,
    pub(crate) kind: ToastKind,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingSection {
    Checks,
    Thresholds,
    History,
    Alerts,
    Network,
}

impl SettingSection {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Checks => "Проверки",
            Self::Thresholds => "Пороги и сроки",
            Self::History => "История и отчёты",
            Self::Alerts => "Уведомления",
            Self::Network => "Сеть",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldKind {
    Number {
        min: u64,
        max: u64,
        step: u64,
        unit: &'static str,
    },
    Toggle,
    Choice,
    Text,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingField {
    Interval,
    Timeout,
    Retries,
    Concurrency,
    BodyLimit,
    HeadFirst,
    Diagnostics,
    Ping,
    Sort,
    SlowThreshold,
    CertWarnDays,
    DomainCheck,
    DomainWarnDays,
    Uptime,
    Logging,
    LogPath,
    LogMaxSize,
    LogRotate,
    Csv,
    CsvPath,
    Webhooks,
    MinFailures,
    NotifyDown,
    NotifyRecovery,
    TelegramToken,
    TelegramChat,
    DiscordUrl,
    SlackUrl,
    Proxy,
    Doh,
}

impl SettingField {
    pub(crate) const ALL: [Self; 30] = [
        Self::Interval,
        Self::Timeout,
        Self::Retries,
        Self::Concurrency,
        Self::BodyLimit,
        Self::HeadFirst,
        Self::Diagnostics,
        Self::Ping,
        Self::Sort,
        Self::SlowThreshold,
        Self::CertWarnDays,
        Self::DomainCheck,
        Self::DomainWarnDays,
        Self::Uptime,
        Self::Logging,
        Self::LogPath,
        Self::LogMaxSize,
        Self::LogRotate,
        Self::Csv,
        Self::CsvPath,
        Self::Webhooks,
        Self::MinFailures,
        Self::NotifyDown,
        Self::NotifyRecovery,
        Self::TelegramToken,
        Self::TelegramChat,
        Self::DiscordUrl,
        Self::SlackUrl,
        Self::Proxy,
        Self::Doh,
    ];

    pub(crate) const fn section(self) -> SettingSection {
        match self {
            Self::Interval
            | Self::Timeout
            | Self::Retries
            | Self::Concurrency
            | Self::BodyLimit
            | Self::HeadFirst
            | Self::Diagnostics
            | Self::Ping
            | Self::Sort => SettingSection::Checks,
            Self::SlowThreshold | Self::CertWarnDays | Self::DomainCheck | Self::DomainWarnDays => {
                SettingSection::Thresholds
            }
            Self::Uptime
            | Self::Logging
            | Self::LogPath
            | Self::LogMaxSize
            | Self::LogRotate
            | Self::Csv
            | Self::CsvPath => SettingSection::History,
            Self::Webhooks
            | Self::MinFailures
            | Self::NotifyDown
            | Self::NotifyRecovery
            | Self::TelegramToken
            | Self::TelegramChat
            | Self::DiscordUrl
            | Self::SlackUrl => SettingSection::Alerts,
            Self::Proxy | Self::Doh => SettingSection::Network,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::SlowThreshold => "Порог медленного ответа",
            Self::CertWarnDays => "Предупреждать о сертификате",
            Self::DomainCheck => "Проверять срок домена",
            Self::DomainWarnDays => "Предупреждать о домене",
            Self::Interval => "Интервал проверки",
            Self::Timeout => "Таймаут запроса",
            Self::Retries => "Повторные попытки",
            Self::Concurrency => "Параллельные проверки",
            Self::BodyLimit => "Лимит тела ответа",
            Self::HeadFirst => "Сначала HEAD",
            Self::Diagnostics => "TCP/TLS-диагностика",
            Self::Ping => "ICMP-проверка",
            Self::Sort => "Сортировка при запуске",
            Self::Uptime => "История аптайма",
            Self::Logging => "Журнал JSONL",
            Self::LogPath => "Файл журнала",
            Self::LogMaxSize => "Размер журнала",
            Self::LogRotate => "Новый журнал каждый день",
            Self::Csv => "Автоэкспорт CSV",
            Self::CsvPath => "Файл CSV",
            Self::Webhooks => "Уведомления",
            Self::MinFailures => "Сбоев до уведомления",
            Self::NotifyDown => "Сообщать о сбое",
            Self::NotifyRecovery => "Сообщать о восстановлении",
            Self::TelegramToken => "Telegram Bot Token",
            Self::TelegramChat => "Telegram Chat ID",
            Self::DiscordUrl => "Discord Webhook URL",
            Self::SlackUrl => "Slack Webhook URL",
            Self::Proxy => "Контрольный прокси",
            Self::Doh => "DNS-over-HTTPS",
        }
    }

    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::SlowThreshold => {
                "Ответ медленнее порога помечается SLOW: сайт доступен, но это предупреждение. 0 — не проверять. Для отдельного сайта порог задаётся в config.json (slow_threshold_ms)."
            }
            Self::CertWarnDays => {
                "За сколько дней до окончания TLS-сертификата показывать CERT_EXPIRING. 0 — не предупреждать."
            }
            Self::DomainCheck => {
                "Узнавать дату окончания регистрации домена через RDAP или WHOIS. Запрос к реестру — не чаще раза в 12 часов на домен."
            }
            Self::DomainWarnDays => {
                "За сколько дней до окончания регистрации домена показывать DOMAIN_EXPIRING."
            }
            Self::Interval => {
                "Пауза между проверками сайтов из общего списка. У групп из config.json свой интервал."
            }
            Self::Timeout => {
                "Сколько ждать ответа на один сетевой запрос, прежде чем считать его неудачным."
            }
            Self::Retries => {
                "Повторы после временной ошибки (таймаут, 5xx, 429). Большие значения удлиняют цикл."
            }
            Self::Concurrency => "Сколько сайтов проверяется одновременно. Меньше — мягче к сети.",
            Self::BodyLimit => {
                "Сколько КБ ответа читать, чтобы распознать страницу-заглушку провайдера."
            }
            Self::HeadFirst => {
                "Экономит трафик, но отключает распознавание заглушек: у ответа на HEAD нет тела."
            }
            Self::Diagnostics => {
                "После сбоя отдельно проверять TCP и TLS, чтобы уточнить, на каком шаге он произошёл."
            }
            Self::Ping => "Дополнительный ICMP-сигнал (только Windows). Главный критерий — HTTP.",
            Self::Sort => "Порядок списка при запуске. Во время работы его переключает клавиша S.",
            Self::Uptime => {
                "Хранить результаты за последние 24 часа и показывать процент доступности."
            }
            Self::Logging => {
                "Дописывать результаты каждого цикла в журнал, по строке JSON на цикл."
            }
            Self::LogPath => "Относительный путь считается от папки программы.",
            Self::LogMaxSize => {
                "При превышении размера журнал переименовывается и начинается новый."
            }
            Self::LogRotate => {
                "Добавлять дату к имени журнала, чтобы каждый день был в своём файле."
            }
            Self::Csv => "Дописывать результаты каждого цикла в CSV-файл.",
            Self::CsvPath => "Относительный путь считается от папки программы.",
            Self::Webhooks => {
                "Отправлять сообщения в Telegram, Discord и Slack при сбое и восстановлении."
            }
            Self::MinFailures => {
                "Сколько неудачных проверок подряд нужно, чтобы отправить уведомление."
            }
            Self::NotifyDown => {
                "Отправлять сообщение, когда сайт недоступен заданное число раз подряд."
            }
            Self::NotifyRecovery => "Отправлять сообщение, когда сайт после сбоя снова отвечает.",
            Self::TelegramToken => {
                "Токен от @BotFather. Значение никогда не показывается, в том числе при вводе."
            }
            Self::TelegramChat => "ID чата или канала, куда бот пишет сообщения.",
            Self::DiscordUrl => "Адрес вебхука канала Discord. Значение никогда не показывается.",
            Self::SlackUrl => "Адрес Incoming Webhook в Slack. Значение никогда не показывается.",
            Self::Proxy => {
                "HTTP(S)- или SOCKS5-прокси для сравнения маршрутов. Пароль в интерфейсе скрыт."
            }
            Self::Doh => "HTTPS-резолвер для контрольного сравнения с системным DNS.",
        }
    }

    pub(crate) const fn kind(self) -> FieldKind {
        match self {
            Self::SlowThreshold => FieldKind::Number {
                min: 0,
                max: 600_000,
                step: 500,
                unit: "мс",
            },
            Self::CertWarnDays => FieldKind::Number {
                min: 0,
                max: 365,
                step: 1,
                unit: "дн.",
            },
            Self::DomainWarnDays => FieldKind::Number {
                min: 1,
                max: 365,
                step: 1,
                unit: "дн.",
            },
            Self::DomainCheck => FieldKind::Toggle,
            Self::Interval => FieldKind::Number {
                min: 1,
                max: 86_400,
                step: 5,
                unit: "с",
            },
            Self::Timeout => FieldKind::Number {
                min: 1,
                max: 300,
                step: 1,
                unit: "с",
            },
            Self::Retries => FieldKind::Number {
                min: 0,
                max: 5,
                step: 1,
                unit: "",
            },
            Self::Concurrency => FieldKind::Number {
                min: 1,
                max: 512,
                step: 1,
                unit: "",
            },
            Self::BodyLimit => FieldKind::Number {
                min: 1,
                max: 1_024,
                step: 8,
                unit: "КБ",
            },
            Self::LogMaxSize => FieldKind::Number {
                min: 1,
                max: 10_240,
                step: 1,
                unit: "МБ",
            },
            Self::MinFailures => FieldKind::Number {
                min: 1,
                max: 1_000,
                step: 1,
                unit: "",
            },
            Self::HeadFirst
            | Self::Diagnostics
            | Self::Ping
            | Self::Uptime
            | Self::Logging
            | Self::LogRotate
            | Self::Csv
            | Self::Webhooks
            | Self::NotifyDown
            | Self::NotifyRecovery => FieldKind::Toggle,
            Self::Sort => FieldKind::Choice,
            Self::LogPath | Self::CsvPath | Self::TelegramChat | Self::Proxy | Self::Doh => {
                FieldKind::Text
            }
            Self::TelegramToken | Self::DiscordUrl | Self::SlackUrl => FieldKind::Secret,
        }
    }

    /// Number fields where 0 means "do not check".
    pub(crate) const fn zero_disables(self) -> bool {
        matches!(self, Self::SlowThreshold | Self::CertWarnDays)
    }

    pub(crate) const fn is_secret(self) -> bool {
        matches!(self.kind(), FieldKind::Secret)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InputPurpose {
    Setting(SettingField),
    AddSite,
    /// Expected response text for the site with this identity.
    ExpectText(String),
}

#[derive(Debug, Clone)]
pub(crate) struct InputModal {
    pub(crate) purpose: InputPurpose,
    pub(crate) input: LineInput,
    pub(crate) error: Option<String>,
    /// Submitting an empty value keeps the stored one (used for secrets, which are never
    /// pre-filled).
    pub(crate) keep_existing: bool,
    pub(crate) masked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leave {
    Page(Page),
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Confirm {
    RemoveSite { identity: String, url: String },
    UnsavedSettings(Leave),
}

#[derive(Debug, Clone)]
pub(crate) enum Modal {
    Help,
    Details,
    Input(InputModal),
    Confirm(Confirm),
}

#[derive(Debug)]
pub(crate) enum Message {
    Scan(ScanMessage),
    Task { ok: bool, text: String, toast: bool },
}

#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    pub(crate) time: DateTime<Local>,
    pub(crate) level: NoticeLevel,
    pub(crate) text: String,
}

pub(crate) struct App {
    pub(crate) profile: UiProfile,
    pub(crate) page: Page,
    pub(crate) modal: Option<Modal>,
    pub(crate) monitor: Monitor,
    pub(crate) settings_draft: Config,
    pub(crate) config_path: PathBuf,
    /// `false` while config.json is unreadable: saving would replace the user's file with
    /// defaults, so every write is refused until the file is fixed and reloaded.
    pub(crate) config_writable: bool,
    pub(crate) theme: Theme,
    selected: Option<String>,
    pub(crate) settings_selected: usize,
    pub(crate) events_selected: usize,
    pub(crate) filter: String,
    pub(crate) filter_input: Option<LineInput>,
    pub(crate) sort_mode: SortMode,
    pub(crate) paused: bool,
    pub(crate) toast: Option<Toast>,
    pub(crate) events: VecDeque<LogEntry>,
    pub(crate) unread_problems: usize,
    pub(crate) should_quit: bool,
    pub(crate) view: ViewState,
    tx: mpsc::UnboundedSender<Message>,
    rx: Option<mpsc::UnboundedReceiver<Message>>,
}

impl App {
    pub(crate) fn new(
        profile: UiProfile,
        script_dir: PathBuf,
        config_path: PathBuf,
    ) -> Result<Self, String> {
        let (config, load_error) = match try_load_config(&config_path) {
            Ok(config) => (config, None),
            Err(error) => (get_default_config(), Some(error)),
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let mut app = Self {
            profile,
            page: Page::Overview,
            modal: None,
            settings_draft: config.clone(),
            config_path,
            config_writable: load_error.is_none(),
            theme: Theme::from_config(&config.color_theme),
            selected: None,
            settings_selected: 0,
            events_selected: 0,
            filter: String::new(),
            filter_input: None,
            sort_mode: SortMode::from_config(&config.monitor_settings.sorted),
            paused: false,
            toast: None,
            events: VecDeque::new(),
            unread_problems: 0,
            should_quit: false,
            view: ViewState::default(),
            tx,
            rx: Some(rx),
            monitor: Monitor::new(config, script_dir)?,
        };
        if let Some(error) = load_error {
            app.log(
                NoticeLevel::Error,
                format!(
                    "{error}. Работаю с настройками по умолчанию; изменения не сохраняются, пока файл не исправлен (Ctrl+R — перечитать)."
                ),
            );
            app.set_toast("config.json повреждён: см. «События»", ToastKind::Error);
        } else {
            let text = format!(
                "Запуск: {} из {}",
                plural(app.sites().len(), "сайт", "сайта", "сайтов"),
                app.config_path.display()
            );
            app.log(NoticeLevel::Info, text);
        }
        Ok(app)
    }

    pub(crate) fn take_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<Message>> {
        self.rx.take()
    }

    // ------------------------------------------------------------------ data views

    pub(crate) fn config(&self) -> &Config {
        self.monitor.config()
    }

    pub(crate) fn sites(&self) -> &[Site] {
        self.monitor.sites()
    }

    pub(crate) fn result(&self, site: &Site) -> Option<&WebsiteResult> {
        self.monitor.result(&site.identity)
    }

    pub(crate) fn checked_at(&self, site: &Site) -> Option<DateTime<Local>> {
        self.monitor.checked_at(&site.identity)
    }

    pub(crate) fn scan(&self) -> Option<ScanProgress> {
        self.monitor.scan()
    }

    pub(crate) fn last_cycle(&self) -> Option<CycleSummary> {
        self.monitor.last_cycle()
    }

    pub(crate) fn has_groups(&self) -> bool {
        self.sites()
            .iter()
            .any(|site| !site.target.group_name.is_empty())
    }

    fn matches_filter(&self, site: &Site, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        let target = &site.target;
        if target.url.to_lowercase().contains(needle)
            || target.group_name.to_lowercase().contains(needle)
        {
            return true;
        }
        match self.result(site) {
            Some(result) => {
                result.status.to_lowercase().contains(needle)
                    || result.code.to_lowercase().contains(needle)
                    || status_description(&result.status)
                        .to_lowercase()
                        .contains(needle)
                    || (result.maintenance && "обслуживание".contains(needle))
            }
            None => "ожидает".contains(needle),
        }
    }

    fn compare_sites(&self, left: &Site, right: &Site) -> Ordering {
        let by_url = || {
            left.target
                .url
                .cmp(&right.target.url)
                .then_with(|| left.target.group_name.cmp(&right.target.group_name))
        };
        let left_result = self.result(left);
        let right_result = self.result(right);
        match self.sort_mode {
            SortMode::Status => status_rank(left_result)
                .cmp(&status_rank(right_result))
                .then_with(by_url),
            SortMode::Url => by_url(),
            SortMode::Duration => {
                let duration = |result: Option<&WebsiteResult>| {
                    result.map_or(0, |result| result.duration_ms.saturating_add(1))
                };
                duration(right_result)
                    .cmp(&duration(left_result))
                    .then_with(by_url)
            }
        }
    }

    /// Sites after the filter, in display order.
    pub(crate) fn visible_sites(&self) -> Vec<&Site> {
        let needle = self.filter.trim().to_lowercase();
        let mut sites: Vec<&Site> = self
            .sites()
            .iter()
            .filter(|site| self.matches_filter(site, &needle))
            .collect();
        sites.sort_by(|left, right| self.compare_sites(left, right));
        sites
    }

    /// Index of the selection inside `visible`; selection follows the site, not the row,
    /// so it does not jump when results re-sort the list during a scan.
    pub(crate) fn selected_index(&self, visible: &[&Site]) -> Option<usize> {
        if visible.is_empty() {
            return None;
        }
        Some(
            self.selected
                .as_ref()
                .and_then(|identity| visible.iter().position(|site| &site.identity == identity))
                .unwrap_or(0),
        )
    }

    pub(crate) fn selected_site(&self) -> Option<&Site> {
        let visible = self.visible_sites();
        self.selected_index(&visible).map(|index| visible[index])
    }

    pub(crate) fn summary(&self) -> Summary {
        self.monitor.summary()
    }

    pub(crate) fn uptime(&self, site: &Site) -> &[bool] {
        self.monitor.uptime(&site.identity)
    }

    /// Time until the next site is due; `None` while paused.
    pub(crate) fn next_check(&self) -> Option<Duration> {
        (!self.paused).then(|| self.monitor.next_due())
    }

    pub(crate) fn settings_dirty(&self) -> bool {
        serde_json::to_value(self.config()).ok() != serde_json::to_value(&self.settings_draft).ok()
    }

    // ------------------------------------------------------------------ scanning

    pub(crate) fn tick(&mut self) {
        if self
            .toast
            .as_ref()
            .is_some_and(|toast| toast.expires_at <= Instant::now())
        {
            self.toast = None;
        }
        if !self.paused && self.scan().is_none() && self.next_check() == Some(Duration::ZERO) {
            self.start_scan(false);
        }
    }

    pub(crate) fn start_scan(&mut self, manual: bool) {
        if let Some(scan) = self.scan() {
            if manual {
                self.set_toast(
                    &format!("Проверка уже идёт: {} из {}", scan.done, scan.total),
                    ToastKind::Info,
                );
            }
            return;
        }
        let tx = self.tx.clone();
        self.monitor.start_scan(manual, move |message| {
            let _ = tx.send(Message::Scan(message));
        });
    }

    pub(crate) fn handle_message(&mut self, message: Message) {
        match message {
            Message::Scan(message) => {
                for event in self.monitor.handle(message) {
                    self.handle_event(event);
                }
            }
            Message::Task { ok, text, toast } => {
                let level = if ok {
                    NoticeLevel::Info
                } else {
                    NoticeLevel::Error
                };
                if toast || !ok {
                    let kind = if ok {
                        ToastKind::Success
                    } else {
                        ToastKind::Error
                    };
                    self.set_toast(&text, kind);
                }
                self.log(level, text);
            }
        }
    }

    fn handle_event(&mut self, event: MonitorEvent) {
        let text = event.text();
        match &event {
            MonitorEvent::AlertThreshold { .. } => self.set_toast(&text, ToastKind::Error),
            MonitorEvent::CycleFinished(cycle) if cycle.manual => {
                let kind = if cycle.failed == 0 {
                    ToastKind::Success
                } else {
                    ToastKind::Warning
                };
                self.set_toast(&text, kind);
            }
            _ => {}
        }
        // The threshold toast repeats a failure that is already in the log.
        if !matches!(event, MonitorEvent::AlertThreshold { .. }) {
            self.log(event.level(), text);
        }
    }

    pub(crate) fn handle_notice(&mut self, notice: Notice) {
        let kind = match notice.level {
            NoticeLevel::Info => ToastKind::Info,
            NoticeLevel::Warning => ToastKind::Warning,
            NoticeLevel::Error => ToastKind::Error,
        };
        self.set_toast(&notice.message, kind);
        self.log(notice.level, notice.message);
    }

    // ------------------------------------------------------------------ keyboard

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if let Some(Modal::Input(modal)) = &mut self.modal {
            modal.input.insert_str(text);
            modal.error = None;
        } else if let Some(input) = &mut self.filter_input {
            input.insert_str(text);
            self.filter = input.value().to_string();
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.modal.is_some() {
            self.handle_modal_key(key);
            return;
        }
        if self.filter_input.is_some() {
            self.handle_filter_key(key);
            return;
        }
        let key = latin_hotkey(key);
        if self.page == Page::Settings && self.handle_settings_key(key) {
            return;
        }
        self.handle_global_key(key);
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        let Some(input) = &mut self.filter_input else {
            return;
        };
        match input.handle_key(key) {
            InputAction::Submit => self.filter_input = None,
            InputAction::Cancel => {
                self.filter_input = None;
                self.filter.clear();
            }
            InputAction::Changed => self.filter = input.value().to_string(),
            InputAction::None => {}
        }
    }

    fn handle_global_key(&mut self, key: KeyEvent) {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('r') if control => self.reload_config(),
            KeyCode::Char('q') => self.request_leave(Leave::Quit),
            KeyCode::Char('?') | KeyCode::F(1) => self.modal = Some(Modal::Help),
            KeyCode::Char(digit @ '1'..='5') => {
                let index = digit as usize - '1' as usize;
                self.request_leave(Leave::Page(Page::ALL[index]));
            }
            KeyCode::Tab => self.cycle_page(1),
            KeyCode::BackTab => self.cycle_page(-1),
            KeyCode::Char('r') | KeyCode::F(5) => self.start_scan(true),
            KeyCode::Char('p') => self.toggle_pause(),
            _ if self.page == Page::Settings => {}
            KeyCode::Right => self.cycle_page(1),
            KeyCode::Left => self.cycle_page(-1),
            KeyCode::Char('s') => {
                self.sort_mode = self.sort_mode.next();
                self.set_toast(
                    &format!("Сортировка: {}", self.sort_mode.label()),
                    ToastKind::Info,
                );
            }
            KeyCode::Char('/') => {
                self.filter_input = Some(LineInput::new(&self.filter, 128));
            }
            KeyCode::Esc if !self.filter.is_empty() => self.filter.clear(),
            KeyCode::Char('e') => self.export_now(),
            KeyCode::Char('a') => self.open_add_site(),
            KeyCode::Char('t') if self.page.lists_sites() => self.open_expect_text(),
            KeyCode::Char('d') | KeyCode::Delete if self.page.lists_sites() => {
                self.confirm_remove_selected();
            }
            KeyCode::Enter if self.page.lists_sites() && self.selected_site().is_some() => {
                self.modal = Some(Modal::Details);
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::PageUp => self.move_cursor(-PAGE_STEP),
            KeyCode::PageDown => self.move_cursor(PAGE_STEP),
            KeyCode::Home => self.move_cursor(isize::MIN / 2),
            KeyCode::End => self.move_cursor(isize::MAX / 2),
            _ => {}
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        let Some(modal) = self.modal.take() else {
            return;
        };
        match modal {
            Modal::Help => {}
            Modal::Details => match latin_hotkey(key).code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_cursor(-1);
                    self.modal = Some(Modal::Details);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_cursor(1);
                    self.modal = Some(Modal::Details);
                }
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {}
                _ => self.modal = Some(Modal::Details),
            },
            Modal::Input(mut modal) => match modal.input.handle_key(key) {
                InputAction::Submit => {
                    if let Err(error) = self.submit_input(&modal) {
                        modal.error = Some(error);
                        self.modal = Some(Modal::Input(modal));
                    }
                }
                InputAction::Cancel => {}
                InputAction::Changed => {
                    modal.error = None;
                    self.modal = Some(Modal::Input(modal));
                }
                InputAction::None => self.modal = Some(Modal::Input(modal)),
            },
            Modal::Confirm(confirm) => self.handle_confirm_key(confirm, latin_hotkey(key)),
        }
    }

    fn handle_confirm_key(&mut self, confirm: Confirm, key: KeyEvent) {
        match (confirm, key.code) {
            (Confirm::RemoveSite { identity, url }, KeyCode::Enter | KeyCode::Char('y')) => {
                self.remove_site(&identity, &url);
            }
            (Confirm::UnsavedSettings(leave), KeyCode::Enter | KeyCode::Char('y')) => {
                if self.save_settings() {
                    self.perform_leave(leave);
                }
            }
            (Confirm::UnsavedSettings(leave), KeyCode::Char('n')) => {
                self.settings_draft = self.config().clone();
                self.log(NoticeLevel::Info, "Изменения настроек отменены".into());
                self.perform_leave(leave);
            }
            (_, KeyCode::Esc | KeyCode::Char('n')) => {}
            (confirm, _) => self.modal = Some(Modal::Confirm(confirm)),
        }
    }

    /// Returns `true` when the key was consumed by the settings page.
    fn handle_settings_key(&mut self, key: KeyEvent) -> bool {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let field = SettingField::ALL[self.settings_selected];
        match key.code {
            KeyCode::Char('s') if control => {
                if self.settings_dirty() {
                    self.save_settings();
                } else {
                    self.set_toast("Изменений нет — сохранять нечего", ToastKind::Info);
                }
            }
            KeyCode::Esc => self.request_leave(Leave::Page(Page::Overview)),
            KeyCode::Up | KeyCode::Char('k') => self.move_setting(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_setting(1),
            KeyCode::PageUp => self.move_setting(-PAGE_STEP),
            KeyCode::PageDown => self.move_setting(PAGE_STEP),
            KeyCode::Home => self.settings_selected = 0,
            KeyCode::End => self.settings_selected = SettingField::ALL.len() - 1,
            KeyCode::Left => self.adjust_setting(field, -1),
            KeyCode::Right => self.adjust_setting(field, 1),
            KeyCode::Enter | KeyCode::Char(' ') => match field.kind() {
                FieldKind::Toggle | FieldKind::Choice => self.adjust_setting(field, 1),
                _ => self.begin_setting_input(field),
            },
            KeyCode::Delete | KeyCode::Backspace => self.reset_setting(field),
            _ => return false,
        }
        true
    }

    // ------------------------------------------------------------------ navigation

    fn move_cursor(&mut self, delta: isize) {
        if self.page == Page::Events {
            let last = self.events.len().saturating_sub(1);
            self.events_selected = offset(self.events_selected, delta, last);
            return;
        }
        let identity = {
            let visible = self.visible_sites();
            self.selected_index(&visible).map(|current| {
                let next = offset(current, delta, visible.len() - 1);
                visible[next].identity.clone()
            })
        };
        self.selected = identity;
    }

    fn move_setting(&mut self, delta: isize) {
        self.settings_selected = offset(self.settings_selected, delta, SettingField::ALL.len() - 1);
    }

    fn cycle_page(&mut self, delta: isize) {
        let count = Page::ALL.len() as isize;
        let next = (self.page.index() as isize + delta).rem_euclid(count) as usize;
        self.request_leave(Leave::Page(Page::ALL[next]));
    }

    fn request_leave(&mut self, leave: Leave) {
        if leave == Leave::Page(self.page) {
            return;
        }
        if self.page == Page::Settings && self.settings_dirty() {
            self.modal = Some(Modal::Confirm(Confirm::UnsavedSettings(leave)));
            return;
        }
        self.perform_leave(leave);
    }

    fn perform_leave(&mut self, leave: Leave) {
        match leave {
            Leave::Quit => self.should_quit = true,
            Leave::Page(page) => {
                if page == Page::Settings {
                    self.settings_draft = self.config().clone();
                }
                if page == Page::Events {
                    self.unread_problems = 0;
                    self.events_selected = 0;
                }
                self.page = page;
            }
        }
    }

    fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        let text = if self.paused {
            "Автопроверки на паузе. R — проверить вручную, P — продолжить"
        } else {
            "Автопроверки продолжены"
        };
        self.set_toast(text, ToastKind::Info);
    }

    // ------------------------------------------------------------------ sites

    fn open_add_site(&mut self) {
        self.modal = Some(Modal::Input(InputModal {
            purpose: InputPurpose::AddSite,
            input: LineInput::new("", 2_048),
            error: None,
            keep_existing: false,
            masked: false,
        }));
    }

    fn add_site(&mut self, raw: &str) -> Result<(), String> {
        let url = normalize_target_url(raw)?;
        let duplicate = self.sites().iter().any(|site| {
            site.target.group_name.is_empty()
                && normalize_target_url(&site.target.url).is_ok_and(|existing| existing == url)
        });
        if duplicate {
            return Err("Этот адрес уже отслеживается.".into());
        }
        let mut config = self.config().clone();
        add_website(&mut config, &url);
        let saved = self.write_config(&config)?;
        self.apply_config(saved, false);
        self.selected = Some(url.clone());
        if !self.filter.is_empty() {
            self.filter.clear();
        }
        self.log(NoticeLevel::Info, format!("Добавлен сайт {url}"));
        self.set_toast(
            &format!("Добавлен {url}. Первая проверка начнётся автоматически."),
            ToastKind::Success,
        );
        Ok(())
    }

    fn open_expect_text(&mut self) {
        let Some(site) = self.selected_site() else {
            return;
        };
        let modal = InputModal {
            purpose: InputPurpose::ExpectText(site.identity.clone()),
            input: LineInput::new(&site.target.expect_text, 256),
            error: None,
            keep_existing: false,
            masked: false,
        };
        self.modal = Some(Modal::Input(modal));
    }

    fn set_site_expect_text(&mut self, identity: &str, text: &str) -> Result<(), String> {
        let mut config = self.config().clone();
        if !set_expect_text(&mut config, identity, text) {
            return Err("Сайт больше не найден в конфигурации.".into());
        }
        let saved = self.write_config(&config)?;
        self.apply_config(saved, false);
        // The verdict depends on the new text, so the site is re-checked right away.
        self.monitor.reset_schedule();
        let message = if text.trim().is_empty() {
            format!("Проверка текста отключена для {identity}")
        } else {
            format!("{identity}: ответ должен содержать «{}»", text.trim())
        };
        self.log(NoticeLevel::Info, message.clone());
        self.set_toast(&message, ToastKind::Success);
        Ok(())
    }

    fn confirm_remove_selected(&mut self) {
        let Some(site) = self.selected_site() else {
            return;
        };
        if self.sites().len() == 1 {
            self.set_toast(
                "Это последний сайт. Сначала добавьте другой (A), затем удалите этот.",
                ToastKind::Warning,
            );
            return;
        }
        self.modal = Some(Modal::Confirm(Confirm::RemoveSite {
            identity: site.identity.clone(),
            url: site.target.url.clone(),
        }));
    }

    fn remove_site(&mut self, identity: &str, url: &str) {
        let mut config = self.config().clone();
        if !remove_target(&mut config, identity) {
            self.set_toast("Сайт уже удалён из конфигурации", ToastKind::Warning);
            return;
        }
        match self.write_config(&config) {
            Ok(saved) => self.apply_config(saved, false),
            Err(error) => {
                self.set_toast(&error, ToastKind::Error);
                self.log(NoticeLevel::Error, error);
                return;
            }
        }
        self.log(NoticeLevel::Info, format!("Удалён сайт {url}"));
        self.set_toast(&format!("Удалён {url}"), ToastKind::Success);
    }

    fn export_now(&mut self) {
        let results: Vec<WebsiteResult> = self
            .visible_sites()
            .into_iter()
            .filter_map(|site| self.result(site).cloned())
            .collect();
        if results.is_empty() {
            self.set_toast(
                "Экспортировать пока нечего: дождитесь первой проверки или нажмите R",
                ToastKind::Info,
            );
            return;
        }
        let config = self.config().clone();
        let history = self.monitor.uptime_history().clone();
        let script_dir = self.monitor.script_dir().to_path_buf();
        let tx = self.tx.clone();
        self.set_toast("Сохраняем CSV…", ToastKind::Info);
        tokio::spawn(async move {
            let outcome = export_csv_async(&results, &config, &history, &script_dir).await;
            let (ok, text) = match outcome {
                Ok(path) => (
                    true,
                    format!(
                        "CSV сохранён: {} ({})",
                        path.display(),
                        plural(results.len(), "строка", "строки", "строк")
                    ),
                ),
                Err(error) => (false, error),
            };
            let _ = tx.send(Message::Task {
                ok,
                text,
                toast: true,
            });
        });
    }

    // ------------------------------------------------------------------ configuration

    /// Persists `config` and returns what was actually written (sanitized).
    fn write_config(&self, config: &Config) -> Result<Config, String> {
        if !self.config_writable {
            return Err(
                "config.json повреждён, поэтому изменения не сохраняются. Исправьте файл и нажмите Ctrl+R."
                    .into(),
            );
        }
        save_config(config, &self.config_path)
    }

    fn apply_config(&mut self, config: Config, reset_view: bool) {
        if reset_view {
            self.sort_mode = SortMode::from_config(&config.monitor_settings.sorted);
        }
        self.theme = Theme::from_config(&config.color_theme);
        self.settings_draft = config.clone();
        if let Err(error) = self.monitor.set_config(config) {
            self.set_toast(&error, ToastKind::Error);
            self.log(NoticeLevel::Error, error);
        }
    }

    pub(crate) fn save_settings(&mut self) -> bool {
        match self.write_config(&self.settings_draft) {
            Ok(saved) => self.apply_config(saved, true),
            Err(error) => {
                self.set_toast(&error, ToastKind::Error);
                self.log(NoticeLevel::Error, error);
                return false;
            }
        }
        // New timeouts, proxy or diagnostics apply to every site, so all of them are re-checked.
        self.monitor.reset_schedule();
        self.log(NoticeLevel::Info, "Настройки сохранены".into());
        self.set_toast(
            "Настройки сохранены. Сайты будут перепроверены с новыми параметрами.",
            ToastKind::Success,
        );
        true
    }

    fn reload_config(&mut self) {
        if self.page == Page::Settings && self.settings_dirty() {
            self.set_toast(
                "Сначала сохраните (Ctrl+S) или отмените (Esc) изменения настроек",
                ToastKind::Warning,
            );
            return;
        }
        match try_load_config(&self.config_path) {
            Ok(config) => {
                self.config_writable = true;
                self.apply_config(config, true);
                self.monitor.reset_schedule();
                self.log(NoticeLevel::Info, "Конфигурация перечитана с диска".into());
                self.set_toast(
                    "Конфигурация перечитана. Сайты будут перепроверены.",
                    ToastKind::Success,
                );
            }
            Err(error) => {
                self.set_toast(
                    "Не удалось перечитать config.json: см. «События»",
                    ToastKind::Error,
                );
                self.log(NoticeLevel::Error, error);
            }
        }
    }

    // ------------------------------------------------------------------ settings fields

    pub(crate) fn begin_setting_input(&mut self, field: SettingField) {
        let config = &self.settings_draft;
        let (value, keep_existing) = match field {
            SettingField::TelegramToken => (
                String::new(),
                !config.webhooks.telegram_bot_token.is_empty(),
            ),
            SettingField::DiscordUrl => (
                String::new(),
                !config.webhooks.discord_webhook_url.is_empty(),
            ),
            SettingField::SlackUrl => {
                (String::new(), !config.webhooks.slack_webhook_url.is_empty())
            }
            SettingField::Proxy => {
                let proxy = &config.monitor_settings.proxy_url;
                // A stored proxy password is never put back on screen.
                let has_password = reqwest::Url::parse(proxy)
                    .ok()
                    .is_some_and(|url| url.password().is_some());
                if has_password {
                    (String::new(), true)
                } else {
                    (proxy.clone(), false)
                }
            }
            SettingField::LogPath => (config.monitor.log_file_path.clone(), false),
            SettingField::CsvPath => (config.csv_export.file_path.clone(), false),
            SettingField::TelegramChat => (config.webhooks.telegram_chat_id.clone(), false),
            SettingField::Doh => (config.monitor_settings.doh_server.clone(), false),
            _ => match self.number_value(field) {
                Some(number) => (number.to_string(), false),
                None => return,
            },
        };
        self.modal = Some(Modal::Input(InputModal {
            purpose: InputPurpose::Setting(field),
            input: LineInput::new(&value, 512),
            error: None,
            keep_existing,
            masked: field.is_secret(),
        }));
    }

    fn submit_input(&mut self, modal: &InputModal) -> Result<(), String> {
        let value = modal.input.value().trim().to_string();
        match modal.purpose.clone() {
            InputPurpose::AddSite => self.add_site(&value),
            InputPurpose::ExpectText(identity) => self.set_site_expect_text(&identity, &value),
            InputPurpose::Setting(_) if value.is_empty() && modal.keep_existing => Ok(()),
            InputPurpose::Setting(field) => self.set_setting_text(field, value),
        }
    }

    fn set_setting_text(&mut self, field: SettingField, value: String) -> Result<(), String> {
        if let FieldKind::Number { min, max, .. } = field.kind() {
            let number = value
                .parse::<u64>()
                .ok()
                .filter(|number| (min..=max).contains(number))
                .ok_or_else(|| format!("Введите целое число от {min} до {max}."))?;
            self.set_number(field, number);
            return Ok(());
        }
        let draft = &mut self.settings_draft;
        match field {
            SettingField::LogPath | SettingField::CsvPath if value.is_empty() => {
                return Err("Укажите имя файла, например logs/monitor.log.".into());
            }
            SettingField::LogPath => draft.monitor.log_file_path = value,
            SettingField::CsvPath => draft.csv_export.file_path = value,
            SettingField::TelegramToken => draft.webhooks.telegram_bot_token = value,
            SettingField::TelegramChat => draft.webhooks.telegram_chat_id = value,
            SettingField::DiscordUrl | SettingField::SlackUrl => {
                if !value.is_empty() && !is_https_url(&value) {
                    return Err(
                        "Нужен адрес, начинающийся с https://. Скопируйте его из настроек канала."
                            .into(),
                    );
                }
                if field == SettingField::DiscordUrl {
                    draft.webhooks.discord_webhook_url = value;
                } else {
                    draft.webhooks.slack_webhook_url = value;
                }
            }
            SettingField::Proxy => {
                if !value.is_empty() && reqwest::Proxy::all(&value).is_err() {
                    return Err("Прокси не распознан. Пример: socks5h://127.0.0.1:1080 или http://host:3128.".into());
                }
                draft.monitor_settings.proxy_url = value;
            }
            SettingField::Doh => {
                if !is_https_url(&value) {
                    return Err(
                        "Нужен HTTPS-адрес, например https://cloudflare-dns.com/dns-query.".into(),
                    );
                }
                draft.monitor_settings.doh_server = value;
            }
            _ => {}
        }
        Ok(())
    }

    fn reset_setting(&mut self, field: SettingField) {
        let defaults = get_default_config();
        let draft = &mut self.settings_draft;
        match field {
            SettingField::TelegramToken => draft.webhooks.telegram_bot_token.clear(),
            SettingField::TelegramChat => draft.webhooks.telegram_chat_id.clear(),
            SettingField::DiscordUrl => draft.webhooks.discord_webhook_url.clear(),
            SettingField::SlackUrl => draft.webhooks.slack_webhook_url.clear(),
            SettingField::Proxy => draft.monitor_settings.proxy_url.clear(),
            SettingField::LogPath => draft.monitor.log_file_path = defaults.monitor.log_file_path,
            SettingField::CsvPath => draft.csv_export.file_path = defaults.csv_export.file_path,
            SettingField::Doh => {
                draft.monitor_settings.doh_server = defaults.monitor_settings.doh_server;
            }
            _ => return,
        }
        self.set_toast(
            &format!("«{}» сброшено. Ctrl+S — сохранить", field.label()),
            ToastKind::Info,
        );
    }

    pub(crate) fn number_value(&self, field: SettingField) -> Option<u64> {
        number_of(&self.settings_draft, field)
    }

    fn set_number(&mut self, field: SettingField, value: u64) {
        let config = &mut self.settings_draft;
        let settings = &mut config.monitor_settings;
        let small = |value: u64| u32::try_from(value).unwrap_or(u32::MAX);
        match field {
            SettingField::Interval => settings.interval = value,
            SettingField::Timeout => settings.timeout = value,
            SettingField::Retries => settings.retries_max = small(value),
            SettingField::Concurrency => settings.max_concurrency = value as usize,
            SettingField::BodyLimit => settings.response_body_limit_kb = value as usize,
            SettingField::LogMaxSize => config.monitor.log_max_size_mb = value,
            SettingField::MinFailures => config.webhooks.min_failures_before_alert = small(value),
            SettingField::SlowThreshold => settings.slow_threshold_ms = value,
            SettingField::CertWarnDays => settings.cert_warn_days = small(value),
            SettingField::DomainWarnDays => settings.domain_warn_days = small(value),
            _ => {}
        }
    }

    fn toggle_value(&mut self, field: SettingField) -> Option<&mut bool> {
        let config = &mut self.settings_draft;
        Some(match field {
            SettingField::HeadFirst => &mut config.monitor_settings.use_head_first,
            SettingField::Diagnostics => &mut config.monitor_settings.diagnostics_enabled,
            SettingField::Ping => &mut config.monitor_settings.ping_enabled,
            SettingField::Uptime => &mut config.monitor_settings.uptime_enabled,
            SettingField::Logging => &mut config.monitor.logging_enabled,
            SettingField::LogRotate => &mut config.monitor.log_rotate_daily,
            SettingField::Csv => &mut config.csv_export.enabled,
            SettingField::Webhooks => &mut config.webhooks.enabled,
            SettingField::NotifyDown => &mut config.webhooks.notify_on_down,
            SettingField::NotifyRecovery => &mut config.webhooks.notify_on_recovery,
            SettingField::DomainCheck => &mut config.monitor_settings.domain_check_enabled,
            _ => return None,
        })
    }

    pub(crate) fn adjust_setting(&mut self, field: SettingField, direction: i8) {
        match field.kind() {
            FieldKind::Number { min, max, step, .. } => {
                let Some(current) = self.number_value(field) else {
                    return;
                };
                let next = if direction < 0 {
                    current.saturating_sub(step).max(min)
                } else {
                    current.saturating_add(step).min(max)
                };
                self.set_number(field, next);
            }
            FieldKind::Toggle => {
                if let Some(value) = self.toggle_value(field) {
                    *value = !*value;
                }
            }
            FieldKind::Choice => {
                let settings = &mut self.settings_draft.monitor_settings;
                let mut mode = SortMode::from_config(&settings.sorted);
                let steps = if direction < 0 { 2 } else { 1 };
                for _ in 0..steps {
                    mode = mode.next();
                }
                settings.sorted = mode.config_value().into();
            }
            // Arrows never open an editor by surprise; Enter does.
            FieldKind::Text | FieldKind::Secret => {}
        }
    }

    pub(crate) fn setting_value(&self, field: SettingField) -> String {
        display_value(&self.settings_draft, field)
    }

    /// Whether the draft differs from the saved configuration for this field.
    pub(crate) fn setting_changed(&self, field: SettingField) -> bool {
        let saved = self.config();
        display_value(&self.settings_draft, field) != display_value(saved, field)
            || (field.is_secret()
                && secret_of(&self.settings_draft, field) != secret_of(saved, field))
    }

    // ------------------------------------------------------------------ feedback

    pub(crate) fn set_toast(&mut self, text: &str, kind: ToastKind) {
        let duration = if kind == ToastKind::Error {
            ERROR_TOAST_DURATION
        } else {
            TOAST_DURATION
        };
        self.toast = Some(Toast {
            text: text.into(),
            kind,
            expires_at: Instant::now() + duration,
        });
    }

    fn log(&mut self, level: NoticeLevel, text: String) {
        if level != NoticeLevel::Info && self.page != Page::Events {
            self.unread_problems += 1;
        }
        if self.page == Page::Events && self.events_selected > 0 {
            // Keep the entry under the cursor in place while new ones arrive on top.
            self.events_selected += 1;
        }
        self.events.push_front(LogEntry {
            time: Local::now(),
            level,
            text,
        });
        self.events.truncate(MAX_EVENTS);
    }
}

pub(crate) const ON: &str = "ВКЛ";
pub(crate) const OFF: &str = "ВЫКЛ";
pub(crate) const NOT_SET: &str = "не задано";

fn number_of(config: &Config, field: SettingField) -> Option<u64> {
    let settings = &config.monitor_settings;
    Some(match field {
        SettingField::Interval => settings.interval,
        SettingField::Timeout => settings.timeout,
        SettingField::Retries => u64::from(settings.retries_max),
        SettingField::Concurrency => settings.max_concurrency as u64,
        SettingField::BodyLimit => settings.response_body_limit_kb as u64,
        SettingField::LogMaxSize => config.monitor.log_max_size_mb,
        SettingField::MinFailures => u64::from(config.webhooks.min_failures_before_alert),
        SettingField::SlowThreshold => settings.slow_threshold_ms,
        SettingField::CertWarnDays => u64::from(settings.cert_warn_days),
        SettingField::DomainWarnDays => u64::from(settings.domain_warn_days),
        _ => return None,
    })
}

fn toggle_of(config: &Config, field: SettingField) -> bool {
    match field {
        SettingField::HeadFirst => config.monitor_settings.use_head_first,
        SettingField::Diagnostics => config.monitor_settings.diagnostics_enabled,
        SettingField::Ping => config.monitor_settings.ping_enabled,
        SettingField::Uptime => config.monitor_settings.uptime_enabled,
        SettingField::Logging => config.monitor.logging_enabled,
        SettingField::LogRotate => config.monitor.log_rotate_daily,
        SettingField::Csv => config.csv_export.enabled,
        SettingField::Webhooks => config.webhooks.enabled,
        SettingField::NotifyDown => config.webhooks.notify_on_down,
        SettingField::NotifyRecovery => config.webhooks.notify_on_recovery,
        SettingField::DomainCheck => config.monitor_settings.domain_check_enabled,
        _ => false,
    }
}

fn secret_of(config: &Config, field: SettingField) -> &str {
    match field {
        SettingField::TelegramToken => &config.webhooks.telegram_bot_token,
        SettingField::DiscordUrl => &config.webhooks.discord_webhook_url,
        SettingField::SlackUrl => &config.webhooks.slack_webhook_url,
        _ => "",
    }
}

/// Value as shown in the settings list. Secrets are reduced to their length.
fn display_value(config: &Config, field: SettingField) -> String {
    match field.kind() {
        FieldKind::Number { unit, .. } => {
            let value = number_of(config, field).unwrap_or_default();
            if value == 0 && field.zero_disables() {
                OFF.into()
            } else if unit.is_empty() {
                value.to_string()
            } else {
                format!("{value} {unit}")
            }
        }
        FieldKind::Toggle => toggle_label(toggle_of(config, field)).into(),
        FieldKind::Choice => SortMode::from_config(&config.monitor_settings.sorted)
            .label()
            .into(),
        FieldKind::Secret => secret_label(secret_of(config, field)),
        FieldKind::Text => {
            let value = match field {
                SettingField::LogPath => config.monitor.log_file_path.clone(),
                SettingField::CsvPath => config.csv_export.file_path.clone(),
                SettingField::TelegramChat => config.webhooks.telegram_chat_id.clone(),
                SettingField::Proxy => redact_proxy_url(&config.monitor_settings.proxy_url),
                _ => config.monitor_settings.doh_server.clone(),
            };
            if value.is_empty() {
                NOT_SET.into()
            } else {
                value
            }
        }
    }
}

fn is_https_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some())
}

fn offset(current: usize, delta: isize, last: usize) -> usize {
    current.saturating_add_signed(delta).min(last)
}

fn status_rank(result: Option<&WebsiteResult>) -> u8 {
    match result.map(WebsiteResult::health) {
        Some(Health::Down) => 0,
        Some(Health::Warning) => 1,
        Some(Health::Up) => 2,
        None => 3,
    }
}

fn toggle_label(value: bool) -> &'static str {
    if value { ON } else { OFF }
}

pub(crate) fn secret_label(value: &str) -> String {
    if value.is_empty() {
        NOT_SET.into()
    } else {
        format!("задан ({} симв.)", value.chars().count())
    }
}

/// Hotkeys work on the Russian ЙЦУКЕН layout too: the physical key is what matters.
fn latin_hotkey(mut key: KeyEvent) -> KeyEvent {
    if let KeyCode::Char(character) = key.code {
        const RU: &str = "йцукенгшщзфывапролдячсмить.,";
        const EN: &str = "qwertyuiopasdfghjklzxcvbnm/?";
        let lower = character.to_lowercase().next().unwrap_or(character);
        let mapped = RU
            .chars()
            .position(|candidate| candidate == lower)
            .and_then(|index| EN.chars().nth(index))
            .unwrap_or(lower);
        if mapped.is_ascii_alphabetic() || mapped != lower {
            key.code = KeyCode::Char(mapped);
        }
    }
    key
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn test_app() -> (App, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let mut config = get_default_config();
        config.websites = vec![
            "https://a.example/".into(),
            "https://b.example/".into(),
            "https://c.example/".into(),
        ];
        save_config(&config, &config_path).unwrap();
        let app = App::new(UiProfile::Full, directory.path().to_path_buf(), config_path).unwrap();
        (app, directory)
    }

    /// Feeds a finished check into the app as if a scan had produced it.
    pub(crate) fn inject(app: &mut App, url: &str, status: &str, duration_ms: u64) {
        let mut result = WebsiteResult::pending(url);
        result.status = status.into();
        result.code = "200".into();
        result.duration_ms = duration_ms;
        result.direct_ok = status == "OK";
        app.handle_message(Message::Scan(ScanMessage::Result {
            identity: url.into(),
            started: Instant::now(),
            result: Box::new(result),
        }));
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(app: &mut App, text: &str) {
        for character in text.chars() {
            app.handle_key(key(KeyCode::Char(character)));
        }
    }

    #[test]
    fn secret_labels_never_contain_secret() {
        assert_eq!(secret_label("super-secret-token"), "задан (18 симв.)");
    }

    #[test]
    fn russian_layout_hotkeys_map_to_latin() {
        assert_eq!(
            latin_hotkey(key(KeyCode::Char('к'))).code,
            KeyCode::Char('r')
        );
        assert_eq!(
            latin_hotkey(key(KeyCode::Char('Й'))).code,
            KeyCode::Char('q')
        );
        assert_eq!(
            latin_hotkey(key(KeyCode::Char('.'))).code,
            KeyCode::Char('/')
        );
        assert_eq!(
            latin_hotkey(key(KeyCode::Char('1'))).code,
            KeyCode::Char('1')
        );
    }

    #[test]
    fn failures_sort_first_and_selection_follows_the_site() {
        let (mut app, _directory) = test_app();
        app.selected = Some("https://c.example/".into());
        inject(&mut app, "https://a.example/", "OK", 10);
        inject(&mut app, "https://c.example/", "TCP_TIMEOUT", 10);

        let visible = app.visible_sites();
        assert_eq!(visible[0].identity, "https://c.example/");
        assert_eq!(
            visible[2].identity, "https://b.example/",
            "unchecked sites go last"
        );
        assert_eq!(app.selected_index(&visible), Some(0));
    }

    #[test]
    fn filter_matches_status_description() {
        let (mut app, _directory) = test_app();
        inject(&mut app, "https://b.example/", "DNS_ERROR", 0);
        app.filter = "dns".into();
        assert_eq!(app.visible_sites().len(), 1);
        app.filter = "ожидает".into();
        assert_eq!(app.visible_sites().len(), 2);
    }

    #[test]
    fn failure_is_logged_once_and_threshold_raises_a_toast() {
        let (mut app, _directory) = test_app();
        let mut config = app.config().clone();
        config.webhooks.min_failures_before_alert = 2;
        app.apply_config(config, false);

        inject(&mut app, "https://a.example/", "TCP_TIMEOUT", 0);
        assert!(app.toast.is_none());
        assert!(app.events.front().unwrap().text.contains("недоступен"));
        inject(&mut app, "https://a.example/", "TCP_TIMEOUT", 0);
        assert!(app.toast.as_ref().unwrap().text.contains("2 проверки"));
    }

    #[test]
    fn adding_a_site_persists_and_selects_it() {
        let (mut app, _directory) = test_app();
        app.handle_key(key(KeyCode::Char('a')));
        type_text(&mut app, "new.example/health");
        app.handle_key(key(KeyCode::Enter));

        assert!(app.modal.is_none(), "{:?}", app.modal);
        assert_eq!(
            app.selected_site().unwrap().identity,
            "https://new.example/health"
        );
        let saved = try_load_config(&app.config_path).unwrap();
        assert!(
            saved
                .websites
                .contains(&"https://new.example/health".into())
        );
    }

    #[test]
    fn invalid_site_keeps_the_dialog_open_with_an_error() {
        let (mut app, _directory) = test_app();
        app.handle_key(key(KeyCode::Char('a')));
        type_text(&mut app, "ftp://files.example");
        app.handle_key(key(KeyCode::Enter));

        let Some(Modal::Input(modal)) = &app.modal else {
            panic!("dialog closed");
        };
        assert!(modal.error.as_deref().unwrap().contains("ftp"));
    }

    #[test]
    fn removing_a_site_requires_confirmation() {
        let (mut app, _directory) = test_app();
        app.selected = Some("https://b.example/".into());
        app.handle_key(key(KeyCode::Char('d')));
        assert!(matches!(app.modal, Some(Modal::Confirm(_))));
        app.handle_key(key(KeyCode::Enter));

        assert_eq!(app.sites().len(), 2);
        let saved = try_load_config(&app.config_path).unwrap();
        assert!(!saved.websites.contains(&"https://b.example/".into()));
    }

    #[test]
    fn expected_text_is_edited_from_the_site_list() {
        let (mut app, _directory) = test_app();
        app.selected = Some("https://b.example/".into());
        app.handle_key(key(KeyCode::Char('t')));
        type_text(&mut app, "Добро пожаловать");
        app.handle_key(key(KeyCode::Enter));

        assert!(app.modal.is_none(), "{:?}", app.modal);
        let saved = try_load_config(&app.config_path).unwrap();
        let entry = saved
            .websites
            .iter()
            .find(|site| site.url == "https://b.example/")
            .unwrap();
        assert_eq!(entry.expect_text, "Добро пожаловать");
        assert_eq!(
            app.selected_site().unwrap().target.expect_text,
            "Добро пожаловать"
        );
    }

    #[test]
    fn leaving_dirty_settings_asks_first() {
        let (mut app, _directory) = test_app();
        app.handle_key(key(KeyCode::Char('5')));
        assert_eq!(app.page, Page::Settings);
        app.handle_key(key(KeyCode::Right));
        assert!(app.settings_dirty());

        app.handle_key(key(KeyCode::Char('1')));
        assert_eq!(app.page, Page::Settings);
        assert!(matches!(
            app.modal,
            Some(Modal::Confirm(Confirm::UnsavedSettings(_)))
        ));

        app.handle_key(key(KeyCode::Char('n')));
        assert_eq!(app.page, Page::Overview);
        assert!(!app.settings_dirty());
    }

    #[test]
    fn numeric_setting_accepts_typed_value_and_rejects_out_of_range() {
        let (mut app, _directory) = test_app();
        app.handle_key(key(KeyCode::Char('5')));
        app.handle_key(key(KeyCode::Enter));
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        type_text(&mut app, "999999");
        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(&app.modal, Some(Modal::Input(modal)) if modal.error.is_some()));

        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        type_text(&mut app, "3600");
        app.handle_key(key(KeyCode::Enter));
        assert!(app.modal.is_none());
        assert_eq!(app.settings_draft.monitor_settings.interval, 3_600);
    }

    #[test]
    fn zero_threshold_is_shown_as_disabled() {
        let (mut app, _directory) = test_app();
        app.settings_draft.monitor_settings.slow_threshold_ms = 0;
        assert_eq!(app.setting_value(SettingField::SlowThreshold), OFF);
        app.settings_draft.monitor_settings.slow_threshold_ms = 2_500;
        assert_eq!(app.setting_value(SettingField::SlowThreshold), "2500 мс");
    }

    #[test]
    fn empty_secret_input_keeps_the_stored_value() {
        let (mut app, _directory) = test_app();
        app.settings_draft.webhooks.telegram_bot_token = "stored".into();
        app.begin_setting_input(SettingField::TelegramToken);
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.settings_draft.webhooks.telegram_bot_token, "stored");
    }

    #[test]
    fn corrupt_config_is_never_overwritten_by_the_ui() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        std::fs::write(&config_path, "{ broken").unwrap();
        let mut app = App::new(
            UiProfile::Full,
            directory.path().to_path_buf(),
            config_path.clone(),
        )
        .unwrap();

        assert!(!app.config_writable);
        assert!(app.add_site("https://new.example").is_err());
        assert_eq!(std::fs::read_to_string(config_path).unwrap(), "{ broken");
    }

    #[tokio::test]
    async fn scan_cycle_updates_results_events_and_schedule() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let _ = stream.read(&mut buffer).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nWelcome",
                        )
                        .await;
                });
            }
        });

        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let mut config = get_default_config();
        config.websites = vec![crate::WebsiteEntry {
            expect_text: "welcome".into(),
            ..crate::WebsiteEntry::new(format!("http://{address}/"))
        }];
        config.monitor_settings.ping_enabled = false;
        config.monitor_settings.timeout = 2;
        config.monitor_settings.doh_server = "https://invalid.invalid/dns-query".into();
        config.monitor_settings.domain_check_enabled = false;
        config.monitor_settings.uptime_enabled = true;
        save_config(&config, &config_path).unwrap();
        let mut app =
            App::new(UiProfile::Full, directory.path().to_path_buf(), config_path).unwrap();
        let mut messages = app.take_receiver().unwrap();

        app.tick();
        assert!(
            app.scan().is_some(),
            "a never-checked site is due immediately"
        );
        loop {
            let message = tokio::time::timeout(Duration::from_secs(10), messages.recv())
                .await
                .unwrap()
                .unwrap();
            let finished = matches!(message, Message::Scan(ScanMessage::Finished));
            app.handle_message(message);
            if finished {
                break;
            }
        }

        assert!(app.scan().is_none());
        let site = app.sites()[0].clone();
        let result = app.result(&site).unwrap();
        assert_eq!(result.status, "OK", "{result:?}");
        assert_eq!(result.content_ok, Some(true));
        assert_eq!(app.uptime(&site), &[true]);
        assert_eq!(app.summary().up, 1);
        assert!(app.next_check().unwrap() > Duration::from_secs(50));
        assert!(
            app.events
                .front()
                .unwrap()
                .text
                .starts_with("Проверено 1 сайт")
        );
    }
}
