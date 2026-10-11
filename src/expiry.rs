//! Expiry dates: TLS certificate `notAfter` and domain registration.
//!
//! Domain data comes from RDAP (the registry endpoint is taken from the IANA bootstrap file)
//! with a WHOIS fallback for zones without RDAP, such as `.ru` and `.рф`. Results are cached
//! per registrable domain because registries rate-limit and the date changes rarely.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use reqwest::Client;
use reqwest::header::ACCEPT;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;

const IANA_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";
const IANA_WHOIS: &str = "whois.iana.org";
const SUCCESS_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const FAILURE_TTL: Duration = Duration::from_secs(60 * 60);
const RESPONSE_LIMIT: usize = 1024 * 1024;

/// Second-level public suffixes under which registrations happen one label deeper.
/// A compact subset of the Public Suffix List that covers the common cases.
const SECOND_LEVEL_SUFFIXES: &[&str] = &[
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "msk.su", "spb.su", "com.ua",
    "org.ua", "net.ua", "kiev.ua", "com.by", "com.kz", "org.kz", "co.uk", "org.uk", "ac.uk",
    "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "com.br", "com.cn", "com.tr",
    "co.za", "co.in", "co.il", "com.mx", "com.ar", "co.nz", "com.sg", "com.hk", "com.tw",
];

// ---------------------------------------------------------------------- certificates

/// Reads one DER TLV: `(tag, content, rest)`.
fn der_element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let first = *data.get(1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        let length = bytes
            .iter()
            .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
        (length, 2 + count)
    };
    let content = data.get(header..header.checked_add(length)?)?;
    Some((tag, content, &data[header + length..]))
}

fn der_time(tag: u8, content: &[u8]) -> Option<DateTime<Utc>> {
    let text = std::str::from_utf8(content).ok()?.trim_end_matches('Z');
    let full = match tag {
        // UTCTime: YYMMDDHHMMSS; years 50..99 are 19xx (RFC 5280).
        0x17 => {
            let year: u32 = text.get(..2)?.parse().ok()?;
            let century = if year >= 50 { "19" } else { "20" };
            format!("{century}{text}")
        }
        // GeneralizedTime: YYYYMMDDHHMMSS.
        0x18 => text.to_string(),
        _ => return None,
    };
    NaiveDateTime::parse_from_str(full.get(..14)?, "%Y%m%d%H%M%S")
        .ok()
        .map(|time| time.and_utc())
}

/// `notAfter` of a DER-encoded X.509 certificate.
pub fn certificate_not_after(der: &[u8]) -> Option<DateTime<Utc>> {
    let (_, certificate, _) = der_element(der)?;
    let (_, tbs, _) = der_element(certificate)?;
    let mut rest = tbs;
    // Optional explicit version tag [0].
    if rest.first() == Some(&0xa0) {
        rest = der_element(rest)?.2;
    }
    // serialNumber, signature algorithm, issuer.
    for _ in 0..3 {
        rest = der_element(rest)?.2;
    }
    let (_, validity, _) = der_element(rest)?;
    let (_, _, after_not_before) = der_element(validity)?;
    let (tag, not_after, _) = der_element(after_not_before)?;
    der_time(tag, not_after)
}

/// Whole days left until `expires` (negative once it has passed).
pub fn days_until(expires: DateTime<Utc>) -> i64 {
    (expires - Utc::now()).num_days()
}

// ---------------------------------------------------------------------- domains

/// The domain a registrar sells, e.g. `api.shop.example.co.uk` -> `example.co.uk`.
/// `None` for IP addresses and single-label hosts.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let keep = if labels.len() >= 3 && SECOND_LEVEL_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    Some(labels[labels.len() - keep..].join("."))
}

/// Parses the date formats seen in RDAP and WHOIS answers.
pub fn parse_registry_date(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if let Ok(time) = DateTime::parse_from_rfc3339(value) {
        return Some(time.with_timezone(&Utc));
    }
    for format in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(time) = NaiveDateTime::parse_from_str(value, format) {
            return Some(time.and_utc());
        }
    }
    let token = value.split_whitespace().next()?;
    if token != value
        && let Some(time) = parse_registry_date(token)
    {
        return Some(time);
    }
    for format in ["%Y-%m-%d", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d", "%d-%b-%Y"] {
        if let Ok(date) = NaiveDate::parse_from_str(token, format) {
            return date.and_hms_opt(0, 0, 0).map(|time| time.and_utc());
        }
    }
    None
}

/// Expiry date from a WHOIS answer. Field names differ between registries.
pub fn parse_whois_expiry(text: &str) -> Option<DateTime<Utc>> {
    const KEYS: &[&str] = &[
        "registry expiry date",
        "registrar registration expiration date",
        "expiration date",
        "expiry date",
        "expires on",
        "expire date",
        "paid-till",
        "expires",
        "expire",
        "valid until",
        "renewal date",
    ];
    let fields: Vec<(String, &str)> = text
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_lowercase(), value.trim()))
        })
        .collect();
    KEYS.iter().find_map(|wanted| {
        fields
            .iter()
            .filter(|(key, _)| key == wanted)
            .find_map(|(_, value)| parse_registry_date(value))
    })
}

#[derive(Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    action: String,
    #[serde(rename = "eventDate")]
    date: String,
}

#[derive(Deserialize)]
struct RdapDomain {
    #[serde(default)]
    events: Vec<RdapEvent>,
}

pub fn parse_rdap_expiry(body: &[u8]) -> Option<DateTime<Utc>> {
    let domain: RdapDomain = serde_json::from_slice(body).ok()?;
    domain
        .events
        .iter()
        .find(|event| event.action.eq_ignore_ascii_case("expiration"))
        .and_then(|event| parse_registry_date(&event.date))
}

#[derive(Deserialize)]
struct Bootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

fn rdap_base_for(bootstrap: &Bootstrap, tld: &str) -> Option<String> {
    bootstrap
        .services
        .iter()
        .find(|(zones, _)| zones.iter().any(|zone| zone.eq_ignore_ascii_case(tld)))
        .and_then(|(_, urls)| {
            urls.iter()
                .find(|url| url.starts_with("https://"))
                .or_else(|| urls.first())
                .cloned()
        })
}

async fn read_body(response: reqwest::Response) -> Result<Vec<u8>, String> {
    let response = response
        .error_for_status()
        .map_err(|error| error.without_url().to_string())?;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.without_url().to_string())?;
        body.extend_from_slice(&chunk);
        if body.len() > RESPONSE_LIMIT {
            return Err("слишком большой ответ".into());
        }
    }
    Ok(body)
}

async fn whois(server: &str, query: &str, timeout: Duration) -> Result<String, String> {
    let exchange = async {
        let mut stream = TcpStream::connect((server, 43))
            .await
            .map_err(|error| format!("WHOIS {server}: {error}"))?;
        stream
            .write_all(format!("{query}\r\n").as_bytes())
            .await
            .map_err(|error| format!("WHOIS {server}: {error}"))?;
        let mut answer = Vec::new();
        stream
            .take(RESPONSE_LIMIT as u64)
            .read_to_end(&mut answer)
            .await
            .map_err(|error| format!("WHOIS {server}: {error}"))?;
        Ok(String::from_utf8_lossy(&answer).into_owned())
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| format!("WHOIS {server}: таймаут"))?
}

type Lookup = Result<DateTime<Utc>, String>;

struct CacheEntry {
    created: Instant,
    cell: Arc<OnceCell<Lookup>>,
}

impl CacheEntry {
    fn expired(&self) -> bool {
        let ttl = match self.cell.get() {
            Some(Ok(_)) => SUCCESS_TTL,
            Some(Err(_)) => FAILURE_TTL,
            None => return false,
        };
        self.created.elapsed() >= ttl
    }
}

/// Shared, single-flight cache of domain expiry lookups.
#[derive(Default)]
pub struct DomainExpiry {
    entries: Mutex<HashMap<String, CacheEntry>>,
    bootstrap: OnceCell<Bootstrap>,
    whois_servers: Mutex<HashMap<String, String>>,
}

impl DomainExpiry {
    /// Expiry of the registrable domain behind `host`; `None` when the host is not a domain.
    pub async fn lookup(&self, client: &Client, host: &str, timeout: Duration) -> Option<Lookup> {
        let domain = registrable_domain(host)?;
        let cell = {
            let mut entries = self.entries.lock().ok()?;
            let entry = entries.entry(domain.clone()).or_insert_with(|| CacheEntry {
                created: Instant::now(),
                cell: Arc::new(OnceCell::new()),
            });
            if entry.expired() {
                *entry = CacheEntry {
                    created: Instant::now(),
                    cell: Arc::new(OnceCell::new()),
                };
            }
            Arc::clone(&entry.cell)
        };
        Some(
            cell.get_or_init(|| self.fetch(client, &domain, timeout))
                .await
                .clone(),
        )
    }

    async fn fetch(&self, client: &Client, domain: &str, timeout: Duration) -> Lookup {
        let tld = domain.rsplit('.').next().unwrap_or(domain);
        let rdap = match self.rdap_base(client, tld, timeout).await {
            Some(base) => Some(self.rdap(client, &base, domain, timeout).await),
            None => None,
        };
        match rdap {
            Some(Ok(expires)) => Ok(expires),
            Some(Err(rdap_error)) => self
                .whois_expiry(domain, tld, timeout)
                .await
                .map_err(|whois_error| format!("RDAP: {rdap_error}; {whois_error}")),
            None => self.whois_expiry(domain, tld, timeout).await,
        }
    }

    async fn rdap_base(&self, client: &Client, tld: &str, timeout: Duration) -> Option<String> {
        let bootstrap = self
            .bootstrap
            .get_or_try_init(|| async {
                let response = client
                    .get(IANA_BOOTSTRAP)
                    .timeout(timeout)
                    .send()
                    .await
                    .map_err(|error| error.without_url().to_string())?;
                let body = read_body(response).await?;
                serde_json::from_slice::<Bootstrap>(&body).map_err(|error| error.to_string())
            })
            .await
            .ok()?;
        rdap_base_for(bootstrap, tld)
    }

    async fn rdap(
        &self,
        client: &Client,
        base: &str,
        domain: &str,
        timeout: Duration,
    ) -> Result<DateTime<Utc>, String> {
        let url = format!("{}/domain/{domain}", base.trim_end_matches('/'));
        let response = client
            .get(url)
            .header(ACCEPT, "application/rdap+json")
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        let body = read_body(response).await?;
        parse_rdap_expiry(&body).ok_or_else(|| "в ответе нет даты окончания".into())
    }

    async fn whois_server(&self, tld: &str, timeout: Duration) -> Result<String, String> {
        if let Some(server) = self
            .whois_servers
            .lock()
            .ok()
            .and_then(|servers| servers.get(tld).cloned())
        {
            return Ok(server);
        }
        let answer = whois(IANA_WHOIS, tld, timeout).await?;
        let server = answer
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| matches!(key.trim(), "whois" | "refer"))
            .map(|(_, value)| value.trim().to_string())
            .filter(|server| !server.is_empty())
            .ok_or_else(|| format!("для зоны .{tld} не найден WHOIS-сервер"))?;
        if let Ok(mut servers) = self.whois_servers.lock() {
            servers.insert(tld.to_string(), server.clone());
        }
        Ok(server)
    }

    async fn whois_expiry(&self, domain: &str, tld: &str, timeout: Duration) -> Lookup {
        let server = self.whois_server(tld, timeout).await?;
        let answer = whois(&server, domain, timeout).await?;
        parse_whois_expiry(&answer).ok_or_else(|| format!("WHOIS {server}: нет даты окончания"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
        out
    }

    fn certificate(not_after: (u8, &str)) -> Vec<u8> {
        let validity = [
            tlv(0x17, b"250101000000Z"),
            tlv(not_after.0, not_after.1.as_bytes()),
        ]
        .concat();
        let tbs = [
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[0x01, 0x23]),
            tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48])),
            tlv(0x30, &[0x55; 200]), // long issuer forces a two-byte length
            tlv(0x30, &validity),
        ]
        .concat();
        tlv(
            0x30,
            &[tlv(0x30, &tbs), tlv(0x30, &[]), tlv(0x03, &[0])].concat(),
        )
    }

    #[test]
    fn reads_not_after_from_utc_and_generalized_time() {
        let utc = certificate_not_after(&certificate((0x17, "270315120000Z"))).unwrap();
        assert_eq!(utc.to_rfc3339(), "2027-03-15T12:00:00+00:00");
        let generalized = certificate_not_after(&certificate((0x18, "20510101000000Z"))).unwrap();
        assert_eq!(generalized.to_rfc3339(), "2051-01-01T00:00:00+00:00");
    }

    #[test]
    fn malformed_certificate_is_rejected() {
        assert_eq!(certificate_not_after(&[0x30, 0x05, 0x01]), None);
        assert_eq!(certificate_not_after(&[]), None);
    }

    #[test]
    fn registrable_domain_handles_subdomains_and_second_level_zones() {
        assert_eq!(
            registrable_domain("api.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("shop.example.com.ru").as_deref(),
            Some("example.com.ru")
        );
        assert_eq!(
            registrable_domain("xn--80ak6aa92e.xn--p1ai").as_deref(),
            Some("xn--80ak6aa92e.xn--p1ai")
        );
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("::1"), None);
        assert_eq!(registrable_domain("localhost"), None);
    }

    #[test]
    fn parses_ru_whois_paid_till() {
        let answer = "domain:        EXAMPLE.RU\nstate:         REGISTERED, DELEGATED\ncreated:       2001-01-01T00:00:00Z\npaid-till:     2027-03-15T21:00:00Z\n";
        assert_eq!(
            parse_whois_expiry(answer).unwrap().to_rfc3339(),
            "2027-03-15T21:00:00+00:00"
        );
    }

    #[test]
    fn parses_icann_whois_and_textual_dates() {
        let answer = "Domain Name: EXAMPLE.COM\r\nRegistry Expiry Date: 2026-08-13T04:00:00Z\r\n";
        assert_eq!(
            parse_whois_expiry(answer).unwrap().to_rfc3339(),
            "2026-08-13T04:00:00+00:00"
        );
        assert_eq!(
            parse_registry_date("15-Mar-2027").unwrap().to_rfc3339(),
            "2027-03-15T00:00:00+00:00"
        );
        assert_eq!(parse_whois_expiry("nothing useful"), None);
    }

    #[test]
    fn parses_rdap_expiration_event() {
        let body = br#"{"events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
        ]}"#;
        assert_eq!(
            parse_rdap_expiry(body).unwrap().to_rfc3339(),
            "2026-08-13T04:00:00+00:00"
        );
    }

    #[test]
    fn bootstrap_maps_zone_to_https_endpoint() {
        let bootstrap: Bootstrap = serde_json::from_str(
            r#"{"services": [[["com", "net"], ["http://rdap.example/", "https://rdap.example/"]]]}"#,
        )
        .unwrap();
        assert_eq!(
            rdap_base_for(&bootstrap, "NET").as_deref(),
            Some("https://rdap.example/")
        );
        assert_eq!(rdap_base_for(&bootstrap, "ru"), None);
    }
}
