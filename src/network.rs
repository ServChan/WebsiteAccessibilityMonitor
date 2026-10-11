use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use futures_util::StreamExt;
use reqwest::header::{ACCEPT, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Client, Method, Response, Url};
use serde::Deserialize;
use tokio::net::{TcpStream, lookup_host};

use crate::expiry::{DomainExpiry, certificate_not_after, days_until};
use crate::model::{Config, MonitorTarget, WebsiteResult};

const RETRY_DELAYS_MS: [u64; 3] = [250, 750, 1_500];
const DOH_BODY_LIMIT: usize = 256 * 1024;
const PING_TIMEOUT_MS: u32 = 2_000;
/// Body read for sites with an expected text, which may sit below the first screen.
const CONTENT_BODY_LIMIT: usize = 1024 * 1024;
const USER_AGENT_VALUE: &str = concat!("WAM/", env!("CARGO_PKG_VERSION"));

/// Phrases that only appear on ISP/regulator block pages. Generic words such as
/// "заблокирован" or "единый реестр" are deliberately absent: they occur on ordinary
/// pages (news, account pages) and turned healthy sites into false "HTTP_STUB" failures.
const STUB_MARKERS: &[&str] = &[
    "доступ к запрашиваемому ресурсу ограничен",
    "доступ к информационному ресурсу ограничен",
    "доступ к ресурсу ограничен на основании",
    "внесен в единый реестр",
    "внесён в единый реестр",
    "включен в единый реестр",
    "внесен в реестр запрещенных",
    "внесён в реестр запрещённых",
    "информация запрещена к распространению",
    "eais.rkn.gov.ru",
    "blocklist.rkn.gov.ru",
    "blocked by roskomnadzor",
    "blocked by rkn",
];

fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers
}

/// Client for the primary check. It never uses a system or configured proxy, otherwise the
/// "direct vs. proxy" comparison would compare a route with itself. TLS info is kept so the
/// certificate expiry can be read from the response.
pub fn build_direct_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .tls_info(true)
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .connect_timeout(Duration::from_secs(timeout_secs.max(1)))
        .default_headers(default_headers())
        .redirect(reqwest::redirect::Policy::limited(10))
        .pool_max_idle_per_host(64)
        .pool_idle_timeout(Duration::from_secs(120))
        .no_proxy()
        .build()
}

/// Client routed through `proxy_url`; with an empty URL it behaves like the direct client.
pub fn build_proxied_client(proxy_url: &str, timeout_secs: u64) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .connect_timeout(Duration::from_secs(timeout_secs.max(1)))
        .default_headers(default_headers())
        .redirect(reqwest::redirect::Policy::limited(10))
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(Duration::from_secs(60))
        .no_proxy();
    if !proxy_url.trim().is_empty() {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url.trim())?);
    }
    builder.build()
}

/// Host suitable for resolvers and sockets: IPv6 literals lose their URL brackets
/// (`[::1]` -> `::1`), which `lookup_host` would otherwise reject.
fn socket_host(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

/// System resolver lookup with a hard timeout: `getaddrinfo` can block far longer than the
/// configured request timeout when the local DNS server does not answer.
pub async fn resolve_system_all(host: &str, timeout: Duration) -> Vec<String> {
    let mut ips: Vec<_> = match tokio::time::timeout(timeout, lookup_host((host, 0))).await {
        Ok(Ok(addresses)) => addresses.map(|address| address.ip().to_string()).collect(),
        _ => Vec::new(),
    };
    ips.sort_unstable();
    ips.dedup();
    ips
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    answer_type: u16,
    data: String,
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status", default)]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

async fn read_limited(response: Response, limit: usize) -> Result<Vec<u8>, reqwest::Error> {
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if bytes.len() >= limit {
            break;
        }
    }
    Ok(bytes)
}

async fn query_doh(
    client: &Client,
    host: &str,
    server: &str,
    record_type: &str,
    timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    let mut url = Url::parse(server).map_err(|error| error.to_string())?;
    url.query_pairs_mut()
        .append_pair("name", host)
        .append_pair("type", record_type);
    let response = client
        .get(url)
        .header(ACCEPT, "application/dns-json")
        .timeout(timeout)
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;
    let body = read_limited(response, DOH_BODY_LIMIT)
        .await
        .map_err(|error| error.to_string())?;
    let response: DohResponse = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    if response.status != 0 && response.status != 3 {
        return Err(format!("DoH status {}", response.status));
    }
    Ok(response
        .answer
        .into_iter()
        .filter(|answer| matches!(answer.answer_type, 1 | 28))
        .filter_map(|answer| answer.data.parse().ok())
        .collect())
}

pub async fn resolve_doh_all(
    client: &Client,
    host: &str,
    doh_server: &str,
    timeout: Duration,
) -> Vec<String> {
    if host.parse::<IpAddr>().is_ok() {
        return vec![host.to_string()];
    }
    let (ipv4, ipv6) = tokio::join!(
        query_doh(client, host, doh_server, "A", timeout),
        query_doh(client, host, doh_server, "AAAA", timeout)
    );
    let mut ips: Vec<_> = ipv4
        .unwrap_or_default()
        .into_iter()
        .chain(ipv6.unwrap_or_default())
        .map(|ip| ip.to_string())
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn socket_addresses(ips: &[String], port: u16) -> Vec<SocketAddr> {
    ips.iter()
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

/// Tries every resolved address in turn, bounded by one overall timeout.
pub async fn check_tcp_endpoint(
    addresses: &[SocketAddr],
    timeout: Duration,
) -> Result<Duration, String> {
    if addresses.is_empty() {
        return Err("No IP addresses found".into());
    }
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addresses)).await {
        Ok(Ok(_)) => Ok(start.elapsed()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("timeout".into()),
    }
}

/// TCP connect followed by a TLS handshake with SNI set to `host`.
pub async fn check_tls_endpoint(
    host: &str,
    addresses: &[SocketAddr],
    timeout: Duration,
) -> Result<Duration, String> {
    if addresses.is_empty() {
        return Err("No IP addresses found".into());
    }
    let start = Instant::now();
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addresses))
        .await
        .map_err(|_| "TCP timeout".to_string())?
        .map_err(|error| format!("TCP connect failed: {error}"))?;
    let connector = native_tls::TlsConnector::builder()
        .build()
        .map_err(|error| error.to_string())?;
    tokio::time::timeout(
        timeout,
        tokio_native_tls::TlsConnector::from(connector).connect(host, stream),
    )
    .await
    .map_err(|_| "TLS timeout".to_string())?
    .map_err(|error| error.to_string())?;
    Ok(start.elapsed())
}

/// ICMP echo. `Some(true)` — reply, `Some(false)` — no reply, `None` — unavailable here.
#[cfg(windows)]
pub fn ping_host(address: IpAddr, timeout_ms: u32) -> Option<bool> {
    let mut pinger = winping::Pinger::new().ok()?;
    pinger.set_timeout(timeout_ms);
    let mut buffer = winping::Buffer::new();
    Some(pinger.send(address, &mut buffer).is_ok())
}

/// ICMP needs raw sockets (root) outside Windows, so it is reported as unavailable.
#[cfg(not(windows))]
pub fn ping_host(_address: IpAddr, _timeout_ms: u32) -> Option<bool> {
    None
}

pub fn looks_like_stub(body: &str) -> bool {
    let body = body.to_lowercase();
    STUB_MARKERS.iter().any(|marker| body.contains(marker))
}

/// The body prefix is cut at an arbitrary byte, usually inside a multi-byte character;
/// strict UTF-8 decoding would then reject the whole prefix and hide the block page.
fn body_looks_like_stub(bytes: &[u8]) -> bool {
    looks_like_stub(&String::from_utf8_lossy(bytes))
}

/// `Display` of the error and all its sources: readable, unlike `{:?}`.
pub fn describe_error(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut current = Some(error);
    while let Some(error) = current {
        let text = error.to_string();
        if parts.last().is_none_or(|last| !last.contains(&text)) {
            parts.push(text);
        }
        current = error.source();
    }
    parts.join(": ")
}

fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..=504).contains(&status)
}

fn apply_headers(
    mut request: reqwest::RequestBuilder,
    headers: &HashMap<String, String>,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            request = request.header(name, value);
        }
    }
    request
}

fn method_name(method: &Method) -> &'static str {
    if *method == Method::HEAD {
        "HEAD"
    } else {
        "GET"
    }
}

struct HttpResponseOutcome {
    status: u16,
    method: &'static str,
    retries: u32,
    duration: Duration,
    /// Bounded body prefix; empty for HEAD.
    body: Vec<u8>,
    cert_not_after: Option<DateTime<Utc>>,
}

struct HttpFailureOutcome {
    error: reqwest::Error,
    method: &'static str,
    retries: u32,
    duration: Duration,
}

/// How much of the body to read: enough for block-page markers, and more when the site
/// has an expected text that may sit further down the page.
fn body_limit(target: &MonitorTarget, config: &Config) -> usize {
    let limit = config
        .monitor_settings
        .response_body_limit_kb
        .saturating_mul(1024);
    if target.expect_text.is_empty() {
        limit
    } else {
        limit.max(CONTENT_BODY_LIMIT)
    }
}

fn peer_certificate_expiry(response: &Response) -> Option<DateTime<Utc>> {
    response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .and_then(certificate_not_after)
}

async fn direct_http(
    client: &Client,
    url: &Url,
    target: &MonitorTarget,
    config: &Config,
) -> Result<HttpResponseOutcome, HttpFailureOutcome> {
    let started = Instant::now();
    // HEAD has no body, so a content check needs GET.
    let mut method = if config.monitor_settings.use_head_first && target.expect_text.is_empty() {
        Method::HEAD
    } else {
        Method::GET
    };
    let attempts = config.monitor_settings.retries_max + 1;
    let body_limit = body_limit(target, config);
    for attempt in 0..attempts {
        let last_attempt = attempt + 1 >= attempts;
        loop {
            let response =
                apply_headers(client.request(method.clone(), url.clone()), &target.headers)
                    .send()
                    .await;
            match response {
                Ok(response) => {
                    let status = response.status().as_u16();
                    // A server without HEAD support is not a failed attempt.
                    if method == Method::HEAD && matches!(status, 405 | 501) {
                        method = Method::GET;
                        continue;
                    }
                    if retryable_status(status) && !last_attempt {
                        // Drain a bounded body before reusing the pooled connection. Without this,
                        // an HTTP/1.1 server closing after a 5xx can make the retry fail on a stale socket.
                        let _ = read_limited(response, body_limit.min(64 * 1024)).await;
                        break;
                    }
                    let cert_not_after = peer_certificate_expiry(&response);
                    let body = if method == Method::GET {
                        match read_limited(response, body_limit).await {
                            Ok(bytes) => bytes,
                            Err(_) if !last_attempt => break,
                            Err(error) => {
                                return Err(HttpFailureOutcome {
                                    error,
                                    method: "GET",
                                    retries: attempt,
                                    duration: started.elapsed(),
                                });
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    return Ok(HttpResponseOutcome {
                        status,
                        method: method_name(&method),
                        retries: attempt,
                        duration: started.elapsed(),
                        body,
                        cert_not_after,
                    });
                }
                Err(error) => {
                    let retryable = error.is_timeout()
                        || error.is_connect()
                        || error.is_request()
                        || error
                            .status()
                            .is_some_and(|status| retryable_status(status.as_u16()));
                    if !retryable || last_attempt {
                        return Err(HttpFailureOutcome {
                            error,
                            method: method_name(&method),
                            retries: attempt,
                            duration: started.elapsed(),
                        });
                    }
                    break;
                }
            }
        }
        let delay = RETRY_DELAYS_MS
            .get(attempt as usize)
            .copied()
            .unwrap_or(1_500);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    unreachable!("attempt loop always returns on its final iteration")
}

fn error_has(error: &str, needles: &[&str]) -> bool {
    let error = error.to_lowercase();
    needles.iter().any(|needle| error.contains(needle))
}

fn set_failure(result: &mut WebsiteResult, status: &str, code: &str, kind: &str, details: String) {
    result.status = status.into();
    result.code = code.into();
    result.error_type = kind.into();
    result.details = details;
}

async fn diagnose_transport(
    result: &mut WebsiteResult,
    url: &Url,
    host: &str,
    request_error: &reqwest::Error,
    timeout: Duration,
    proxy_ok: bool,
) {
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = socket_addresses(&result.system_ips, port);
    match check_tcp_endpoint(&addresses, timeout).await {
        Err(error) if error_has(&error, &["timeout", "timed out"]) => set_failure(
            result,
            if proxy_ok { "TCP_BLOCK" } else { "TCP_TIMEOUT" },
            "T/O",
            "TCP",
            format!("TCP {host}:{port}: {error}"),
        ),
        Err(error) if error_has(&error, &["reset", "abort"]) => set_failure(
            result,
            "TCP_RESET",
            "RST",
            "TCP",
            format!("TCP {host}:{port}: {error}"),
        ),
        Err(error) => set_failure(
            result,
            "CONN_ERROR",
            "ERR",
            "TCP",
            format!("TCP {host}:{port}: {error}"),
        ),
        Ok(_) if url.scheme() == "https" => {
            match check_tls_endpoint(host, &addresses, timeout).await {
                Err(error) if error_has(&error, &["timeout", "timed out", "reset", "abort"]) => {
                    let code = if error_has(&error, &["reset", "abort"]) {
                        "RST"
                    } else {
                        "T/O"
                    };
                    set_failure(
                        result,
                        if proxy_ok { "TLS_BLOCK" } else { "TLS_ERROR" },
                        code,
                        "TLS",
                        format!("TLS {host}:{port}: {error}"),
                    );
                }
                Err(error) => set_failure(result, "SSL_ERROR", "SSL", "TLS", error),
                Ok(_) => classify_http_failure(result, request_error, proxy_ok),
            }
        }
        Ok(_) => classify_http_failure(result, request_error, proxy_ok),
    }
}

fn classify_http_failure(result: &mut WebsiteResult, error: &reqwest::Error, proxy_ok: bool) {
    let details = describe_error(error);
    if error.is_timeout() {
        let status = if proxy_ok {
            "HTTP_BLOCK"
        } else {
            "HTTP_TIMEOUT"
        };
        set_failure(result, status, "T/O", "HTTP", details);
    } else if error.is_redirect() {
        set_failure(result, "REDIRECT_LOOP", "3xx", "REDIRECT", details);
    } else {
        let status = if proxy_ok { "HTTP_BLOCK" } else { "CONN_ERROR" };
        set_failure(result, status, "ERR", "NETWORK", details);
    }
}

fn append_detail(result: &mut WebsiteResult, text: &str) {
    if !result.details.is_empty() {
        result.details.push_str("; ");
    }
    result.details.push_str(text);
}

async fn record_ping(
    result: &mut WebsiteResult,
    task: Option<tokio::task::JoinHandle<Option<bool>>>,
) {
    let Some(task) = task else {
        return;
    };
    let grace = Duration::from_millis(u64::from(PING_TIMEOUT_MS) + 1_000);
    result.icmp_ok = match tokio::time::timeout(grace, task).await {
        Ok(Ok(value)) => value,
        _ => None,
    };
    if result.icmp_ok == Some(false) {
        append_detail(result, "ICMP Echo не получил ответа");
    }
}

fn url_error(mut result: WebsiteResult, details: &str) -> WebsiteResult {
    set_failure(&mut result, "URL_ERROR", "ERR", "URL", details.into());
    result
}

fn days_phrase(days: i64) -> String {
    let count = days.unsigned_abs();
    let word = match (count % 10, count % 100) {
        (1, 11) => "дней",
        (1, _) => "день",
        (2..=4, 12..=14) => "дней",
        (2..=4, _) => "дня",
        _ => "дней",
    };
    format!("{count} {word}")
}

/// Downgrades an `OK` result to a warning status and records why. A worse status set
/// earlier (an HTTP warning code, a failure) is kept; the reason is still recorded.
fn add_warning(result: &mut WebsiteResult, status: &str, text: &str) {
    if result.status == "OK" {
        result.status = status.into();
    }
    append_detail(result, text);
}

/// Applies the expected-text check to a successful response.
fn check_content(result: &mut WebsiteResult, target: &MonitorTarget, body: &[u8]) {
    if target.expect_text.is_empty() {
        return;
    }
    let found = String::from_utf8_lossy(body)
        .to_lowercase()
        .contains(&target.expect_text.to_lowercase());
    result.content_ok = Some(found);
    if !found {
        let code = result.code.clone();
        set_failure(
            result,
            "CONTENT_MISMATCH",
            &code,
            "CONTENT",
            format!(
                "В первых {} КБ ответа нет текста «{}»",
                body.len().div_ceil(1024),
                target.expect_text
            ),
        );
    }
}

/// Certificate, domain and response-time warnings for an available site.
fn apply_thresholds(result: &mut WebsiteResult, target: &MonitorTarget, config: &Config) {
    let settings = &config.monitor_settings;
    if let Some(days) = result.cert_days_left
        && settings.cert_warn_days > 0
        && days <= i64::from(settings.cert_warn_days)
    {
        add_warning(
            result,
            "CERT_EXPIRING",
            &format!("TLS-сертификат истекает через {}", days_phrase(days)),
        );
    }
    if let Some(days) = result.domain_days_left
        && settings.domain_check_enabled
        && days <= i64::from(settings.domain_warn_days)
    {
        let text = if days < 0 {
            format!("регистрация домена истекла {} назад", days_phrase(days))
        } else {
            format!("регистрация домена истекает через {}", days_phrase(days))
        };
        add_warning(result, "DOMAIN_EXPIRING", &text);
    }
    if target.slow_threshold_ms > 0 && result.duration_ms > target.slow_threshold_ms {
        add_warning(
            result,
            "SLOW",
            &format!(
                "ответ за {} мс при пороге {} мс",
                result.duration_ms, target.slow_threshold_ms
            ),
        );
    }
}

/// HTTP clients and caches shared by all checks. Cheap to clone.
#[derive(Clone)]
pub struct Checker {
    inner: Arc<CheckerInner>,
}

struct CheckerInner {
    direct: Client,
    proxy: Option<Client>,
    domains: DomainExpiry,
}

impl Checker {
    /// Builds the direct client and, when `proxy_url` is set, the control-route client.
    pub fn new(config: &Config) -> Result<Self, String> {
        let timeout = config.monitor_settings.timeout;
        let direct = build_direct_client(timeout)
            .map_err(|error| format!("Не удалось создать HTTP-клиент: {error}"))?;
        let proxy_url = config.monitor_settings.proxy_url.trim();
        let proxy = if proxy_url.is_empty() {
            None
        } else {
            Some(
                build_proxied_client(proxy_url, timeout)
                    .map_err(|error| format!("Не удалось настроить прокси: {error}"))?,
            )
        };
        Ok(Self {
            inner: Arc::new(CheckerInner {
                direct,
                proxy,
                domains: DomainExpiry::default(),
            }),
        })
    }

    /// The direct (proxy-free) client, also suitable for auxiliary requests.
    pub fn client(&self) -> &Client {
        &self.inner.direct
    }

    async fn proxy_accessible(&self, url: &Url, target: &MonitorTarget, config: &Config) -> bool {
        let Some(client) = &self.inner.proxy else {
            return false;
        };
        let Ok(response) = apply_headers(client.get(url.clone()), &target.headers)
            .send()
            .await
        else {
            return false;
        };
        let status = response.status().as_u16();
        let acceptable = config.monitor_settings.valid_status_codes.contains(&status)
            || config.monitor_settings.warn_status_codes.contains(&status);
        if !acceptable {
            return false;
        }
        match read_limited(response, body_limit(target, config)).await {
            Ok(bytes) => !body_looks_like_stub(&bytes),
            Err(_) => false,
        }
    }

    async fn domain_expiry(
        &self,
        host: &str,
        config: &Config,
        timeout: Duration,
    ) -> Option<DateTime<Utc>> {
        if !config.monitor_settings.domain_check_enabled {
            return None;
        }
        self.inner
            .domains
            .lookup(&self.inner.direct, host, timeout)
            .await?
            .ok()
    }

    /// Full diagnostic check of one target: DNS (system vs. DoH), HTTP with retries,
    /// block-page and expected-text checks, certificate/domain expiry and response-time
    /// thresholds; on failure, TCP/TLS probing plus an optional proxy comparison.
    pub async fn check(&self, target: &MonitorTarget, config: &Config) -> WebsiteResult {
        let mut result = WebsiteResult::pending(&target.url);
        result.group_name = target.group_name.clone();
        let Ok(url) = Url::parse(&target.url) else {
            return url_error(result, "Не удалось разобрать URL");
        };
        if !matches!(url.scheme(), "http" | "https") {
            return url_error(result, "Поддерживаются только HTTP и HTTPS");
        }
        let Some(host) = socket_host(&url) else {
            return url_error(result, "В URL нет имени хоста");
        };
        let client = &self.inner.direct;

        let timeout = Duration::from_secs(config.monitor_settings.timeout.max(1));
        let (system_ips, reference_ips, domain_expires) = tokio::join!(
            resolve_system_all(&host, timeout),
            resolve_doh_all(client, &host, &config.monitor_settings.doh_server, timeout),
            self.domain_expiry(&host, config, timeout)
        );
        result.domain_expires = domain_expires;
        result.domain_days_left = domain_expires.map(days_until);
        result.dns_anomaly = !system_ips.is_empty()
            && !reference_ips.is_empty()
            && system_ips.iter().all(|ip| !reference_ips.contains(ip));
        result.system_ips = system_ips;
        result.reference_ips = reference_ips;

        if result.system_ips.is_empty() {
            result.proxy_ok = self.proxy_accessible(&url, target, config).await;
            let has_reference = !result.reference_ips.is_empty();
            let status = if result.proxy_ok && has_reference {
                "DNS_BLOCK"
            } else {
                "DNS_ERROR"
            };
            let details = if !has_reference {
                "Системный DNS и контрольный DoH не вернули адресов; вывод о блокировке невозможен"
            } else if result.proxy_ok {
                "Системный DNS не ответил, контрольный DoH и доступ через прокси успешны"
            } else {
                "Системный DNS не ответил, контрольный DoH вернул адреса; блокировка не подтверждена альтернативным маршрутом"
            };
            set_failure(&mut result, status, "DNS", "DNS", details.into());
            if let Some(days) = result.domain_days_left.filter(|days| *days < 0) {
                append_detail(
                    &mut result,
                    &format!("регистрация домена истекла {} назад", days_phrase(days)),
                );
            }
            return result;
        }
        result.ip = result.system_ips[0].clone();

        let ping_task = config
            .monitor_settings
            .ping_enabled
            .then(|| result.ip.parse::<IpAddr>().ok())
            .flatten()
            .map(|address| {
                tokio::task::spawn_blocking(move || ping_host(address, PING_TIMEOUT_MS))
            });

        match direct_http(client, &url, target, config).await {
            Ok(outcome) => {
                result.duration_ms = outcome.duration.as_millis() as u64;
                result.retries = outcome.retries;
                result.http_method = outcome.method.into();
                result.code = outcome.status.to_string();
                result.cert_expires = outcome.cert_not_after;
                result.cert_days_left = outcome.cert_not_after.map(days_until);
                let settings = &config.monitor_settings;
                let valid = settings.valid_status_codes.contains(&outcome.status);
                let warning = settings.warn_status_codes.contains(&outcome.status);
                if outcome.status == 451 || body_looks_like_stub(&outcome.body) {
                    result.status = "HTTP_STUB".into();
                    result.error_type = "HTTP".into();
                    result.details = if outcome.status == 451 {
                        "HTTP 451: ограничение может быть задано сайтом, CDN или провайдером"
                    } else {
                        "В ограниченном фрагменте ответа найдены признаки страницы-заглушки"
                    }
                    .into();
                    result.proxy_ok = self.proxy_accessible(&url, target, config).await;
                    if result.proxy_ok {
                        result.status = "HTTP_BLOCK".into();
                        append_detail(
                            &mut result,
                            "через настроенный прокси ресурс отвечает без заглушки",
                        );
                    }
                } else if valid {
                    result.status = "OK".into();
                    result.direct_ok = true;
                    check_content(&mut result, target, &outcome.body);
                    if result.status == "OK" && result.dns_anomaly {
                        result.details = "Наборы адресов системного DNS и DoH не пересекаются; для CDN это может быть нормой".into();
                    }
                } else if warning {
                    result.status = "WARN".into();
                    result.direct_ok = true;
                    result.error_type = "HTTP".into();
                    result.details =
                        format!("HTTP {} входит в список предупреждений", outcome.status);
                } else {
                    result.status = "HTTP_ERROR".into();
                    result.error_type = "HTTP".into();
                    result.details = format!(
                        "HTTP {} не входит в список допустимых кодов",
                        outcome.status
                    );
                    result.proxy_ok = self.proxy_accessible(&url, target, config).await;
                }
                if result.is_available() {
                    apply_thresholds(&mut result, target, config);
                }
            }
            Err(outcome) => {
                result.duration_ms = outcome.duration.as_millis() as u64;
                result.retries = outcome.retries;
                result.http_method = outcome.method.into();
                result.proxy_ok = self.proxy_accessible(&url, target, config).await;
                let proxy_ok = result.proxy_ok;
                let error = outcome.error.without_url();
                if config.monitor_settings.diagnostics_enabled {
                    diagnose_transport(&mut result, &url, &host, &error, timeout, proxy_ok).await;
                } else {
                    classify_http_failure(&mut result, &error, proxy_ok);
                }
            }
        }
        record_ping(&mut result, ping_task).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn serve(
        listener: TcpListener,
        responses: Vec<&'static str>,
        counter: Arc<AtomicUsize>,
        per_connection: bool,
    ) {
        let mut stream = None;
        for response in responses {
            if per_connection || stream.is_none() {
                stream = Some(listener.accept().await.unwrap().0);
            }
            let socket = stream.as_mut().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            counter.fetch_add(1, Ordering::SeqCst);
            socket.write_all(response.as_bytes()).await.unwrap();
            if per_connection || response.contains("Connection: close") {
                socket.shutdown().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    async fn spawn_server(
        bind: &str,
        responses: Vec<&'static str>,
        per_connection: bool,
    ) -> Option<(String, Arc<AtomicUsize>)> {
        let listener = TcpListener::bind(bind).await.ok()?;
        let address = listener.local_addr().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        tokio::spawn(serve(
            listener,
            responses,
            Arc::clone(&counter),
            per_connection,
        ));
        Some((format!("http://{address}/"), counter))
    }

    async fn test_server(responses: Vec<&'static str>) -> (String, Arc<AtomicUsize>) {
        spawn_server("127.0.0.1:0", responses, false).await.unwrap()
    }

    async fn test_server_per_connection(
        responses: Vec<&'static str>,
    ) -> (String, Arc<AtomicUsize>) {
        spawn_server("127.0.0.1:0", responses, true).await.unwrap()
    }

    async fn check(url: &str, config: &Config) -> WebsiteResult {
        let checker = Checker::new(config).unwrap();
        checker
            .check(&MonitorTarget::from_url(url, config), config)
            .await
    }

    fn test_config() -> Config {
        let mut config = crate::get_default_config();
        config.monitor_settings.timeout = 2;
        config.monitor_settings.ping_enabled = false;
        config.monitor_settings.doh_server = "https://invalid.invalid/dns-query".into();
        config.monitor_settings.domain_check_enabled = false;
        config
    }

    #[test]
    fn detects_known_blockpage_marker_case_insensitively() {
        assert!(looks_like_stub("ДОСТУП К ЗАПРАШИВАЕМОМУ РЕСУРСУ ОГРАНИЧЕН"));
        assert!(!looks_like_stub("Обычная страница сайта"));
    }

    #[test]
    fn ordinary_pages_mentioning_blocking_are_not_stubs() {
        assert!(!looks_like_stub(
            "Ваш аккаунт заблокирован. Сведения из единый реестр субъектов МСП."
        ));
    }

    #[test]
    fn stub_detection_survives_a_cut_multibyte_character() {
        let marker = "доступ к запрашиваемому ресурсу ограничен";
        let mut body = format!("{marker}{}", "я".repeat(600));
        let cut = 1_024;
        if body.is_char_boundary(cut) {
            body.insert(0, 'x');
        }
        assert!(!body.is_char_boundary(cut));
        assert!(std::str::from_utf8(&body.as_bytes()[..cut]).is_err());
        assert!(body_looks_like_stub(&body.as_bytes()[..cut]));
    }

    #[test]
    fn ipv6_literal_loses_url_brackets() {
        let url = Url::parse("http://[::1]:8080/health").unwrap();
        assert_eq!(socket_host(&url).as_deref(), Some("::1"));
    }

    #[test]
    fn error_description_is_readable() {
        let error = std::io::Error::other("connection refused");
        assert_eq!(describe_error(&error), "connection refused");
    }

    #[tokio::test]
    async fn head_not_supported_falls_back_to_get_without_retry_budget() {
        let (url, requests) = test_server(vec![
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ])
        .await;
        let mut config = test_config();
        config.monitor_settings.use_head_first = true;
        config.monitor_settings.retries_max = 0;
        let result = check(&url, &config).await;

        assert_eq!(result.status, "OK", "{result:?}");
        assert_eq!(result.http_method, "GET");
        assert_eq!(result.retries, 0);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retryable_http_status_is_retried() {
        let (url, requests) = test_server_per_connection(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ])
        .await;
        let mut config = test_config();
        config.monitor_settings.retries_max = 1;
        config.monitor_settings.diagnostics_enabled = false;
        let result = check(&url, &config).await;

        assert_eq!(result.status, "OK", "{result:?}");
        assert_eq!(result.retries, 1);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn reads_only_a_bounded_response_prefix() {
        let body = "доступ к запрашиваемому ресурсу ограничен";
        let response = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}{}",
                body.len() + 100_000,
                body,
                "x".repeat(100_000)
            )
            .into_boxed_str(),
        );
        let (url, _) = test_server(vec![response]).await;
        let mut config = test_config();
        config.monitor_settings.response_body_limit_kb = 1;
        let result = check(&url, &config).await;

        assert_eq!(result.status, "HTTP_STUB");
    }

    #[tokio::test]
    async fn non_listed_status_is_an_http_error_with_explanation() {
        let (url, _) = test_server(vec![
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ])
        .await;
        let result = check(&url, &test_config()).await;

        assert_eq!(result.status, "HTTP_ERROR");
        assert_eq!(result.code, "404");
        assert!(result.details.contains("404"));
    }

    /// Serves one fixed response per connection after an optional delay.
    async fn slow_server(delay: Duration, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let _ = stream.read(&mut buffer).await;
                    tokio::time::sleep(delay).await;
                    let response = format!(
                        "HTTP/1.1 200 OK
Content-Length: {}
Connection: close

{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{address}/")
    }

    #[tokio::test]
    async fn missing_expected_text_is_a_content_mismatch() {
        let url = slow_server(Duration::ZERO, "<h1>Maintenance</h1>").await;
        let config = test_config();
        let mut target = MonitorTarget::from_url(&url, &config);
        target.expect_text = "Welcome".into();

        let result = Checker::new(&config).unwrap().check(&target, &config).await;

        assert_eq!(result.status, "CONTENT_MISMATCH", "{result:?}");
        assert_eq!(result.content_ok, Some(false));
        assert!(!result.is_available());
        assert!(result.details.contains("Welcome"));
    }

    #[tokio::test]
    async fn expected_text_forces_get_and_matches_case_insensitively() {
        let url = slow_server(Duration::ZERO, "<h1>WELCOME back</h1>").await;
        let mut config = test_config();
        config.monitor_settings.use_head_first = true;
        let mut target = MonitorTarget::from_url(&url, &config);
        target.expect_text = "welcome".into();

        let result = Checker::new(&config).unwrap().check(&target, &config).await;

        assert_eq!(result.status, "OK", "{result:?}");
        assert_eq!(result.http_method, "GET");
        assert_eq!(result.content_ok, Some(true));
    }

    #[tokio::test]
    async fn slow_response_is_a_warning_not_a_failure() {
        let url = slow_server(Duration::from_millis(150), "ok").await;
        let config = test_config();
        let mut target = MonitorTarget::from_url(&url, &config);
        target.slow_threshold_ms = 50;

        let result = Checker::new(&config).unwrap().check(&target, &config).await;

        assert_eq!(result.status, "SLOW", "{result:?}");
        assert!(result.is_available());
        assert!(result.details.contains("порог"));
    }

    #[test]
    fn expiring_certificate_and_domain_are_warnings() {
        let config = test_config();
        let mut target = MonitorTarget::from_url("https://a.example/", &config);
        target.slow_threshold_ms = 0;
        let mut result = WebsiteResult::pending("https://a.example/");
        result.status = "OK".into();
        result.cert_days_left = Some(3);
        let mut config = config;
        config.monitor_settings.domain_check_enabled = true;
        result.domain_days_left = Some(-2);

        apply_thresholds(&mut result, &target, &config);

        assert_eq!(result.status, "CERT_EXPIRING");
        assert!(result.details.contains("3 дня"), "{}", result.details);
        assert!(
            result.details.contains("истекла 2 дня назад"),
            "{}",
            result.details
        );
    }

    #[tokio::test]
    async fn ipv6_literal_url_is_checked() {
        let Some((url, _)) = spawn_server(
            "[::1]:0",
            vec!["HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"],
            false,
        )
        .await
        else {
            return; // No IPv6 loopback on this machine.
        };
        let result = check(&url, &test_config()).await;

        assert_eq!(result.status, "OK", "{result:?}");
        assert_eq!(result.ip, "::1");
    }
}
