//! Prometheus text exposition of the monitor state and a minimal HTTP endpoint for it.

use std::fmt::Write as _;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::monitor::Monitor;
use crate::{Health, status_health, uptime_percent};

/// Latest rendered metrics, shared between the monitor loop and the HTTP server.
pub type Snapshot = Arc<RwLock<String>>;

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

struct Family {
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    samples: Vec<(String, f64)>,
}

impl Family {
    const fn new(name: &'static str, kind: &'static str, help: &'static str) -> Self {
        Self {
            name,
            kind,
            help,
            samples: Vec::new(),
        }
    }

    fn push(&mut self, labels: &str, value: f64) {
        self.samples.push((labels.to_string(), value));
    }

    fn write(&self, out: &mut String) {
        if self.samples.is_empty() {
            return;
        }
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} {}", self.name, self.kind);
        for (labels, value) in &self.samples {
            if labels.is_empty() {
                let _ = writeln!(out, "{} {value}", self.name);
            } else {
                let _ = writeln!(out, "{}{{{labels}}} {value}", self.name);
            }
        }
    }
}

/// Renders every metric in the Prometheus text format (version 0.0.4).
pub fn render(monitor: &Monitor) -> String {
    let mut build = Family::new("wam_build_info", "gauge", "Версия WAM.");
    build.push(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION")), 1.0);
    let mut sites = Family::new("wam_sites", "gauge", "Число отслеживаемых сайтов.");
    sites.push("", monitor.sites().len() as f64);
    let mut up = Family::new(
        "wam_up",
        "gauge",
        "1, если сайт доступен (OK или предупреждение), иначе 0. Окна обслуживания не учитываются.",
    );
    let mut status = Family::new(
        "wam_status",
        "gauge",
        "Текущий диагностический статус сайта (значение всегда 1).",
    );
    let mut maintenance = Family::new(
        "wam_maintenance",
        "gauge",
        "1, если последняя проверка пришлась на окно обслуживания.",
    );
    let mut response = Family::new(
        "wam_response_time_seconds",
        "gauge",
        "Время HTTP-ответа последней проверки.",
    );
    let mut code = Family::new(
        "wam_http_status_code",
        "gauge",
        "HTTP-код последнего ответа.",
    );
    let mut content = Family::new(
        "wam_content_match",
        "gauge",
        "1, если ожидаемый текст найден в ответе, 0 — если нет.",
    );
    let mut cert = Family::new(
        "wam_cert_expiry_timestamp_seconds",
        "gauge",
        "Окончание срока TLS-сертификата (Unix time).",
    );
    let mut domain = Family::new(
        "wam_domain_expiry_timestamp_seconds",
        "gauge",
        "Окончание регистрации домена (Unix time).",
    );
    let mut checked = Family::new(
        "wam_last_check_timestamp_seconds",
        "gauge",
        "Время последней проверки (Unix time).",
    );
    let mut uptime = Family::new(
        "wam_uptime_ratio",
        "gauge",
        "Доля успешных проверок за последние 24 часа (без окон обслуживания).",
    );
    let mut checks = Family::new(
        "wam_checks_total",
        "counter",
        "Число проверок с момента запуска по результату.",
    );

    for site in monitor.sites() {
        let labels = format!(
            "url=\"{}\",group=\"{}\"",
            escape_label(&site.target.url),
            escape_label(&site.target.group_name)
        );
        let counts = monitor.counts(&site.identity);
        checks.push(&format!("{labels},result=\"ok\""), counts.ok as f64);
        checks.push(&format!("{labels},result=\"failed\""), counts.failed as f64);
        if let Some(percent) = uptime_percent(monitor.uptime(&site.identity)) {
            uptime.push(&labels, percent / 100.0);
        }
        let Some(result) = monitor.result(&site.identity) else {
            continue;
        };
        let available = status_health(&result.status) != Health::Down;
        up.push(&labels, f64::from(u8::from(available)));
        status.push(
            &format!("{labels},status=\"{}\"", escape_label(&result.status)),
            1.0,
        );
        maintenance.push(&labels, f64::from(u8::from(result.maintenance)));
        if result.direct_ok {
            response.push(&labels, result.duration_ms as f64 / 1000.0);
        }
        if let Ok(value) = result.code.parse::<u16>() {
            code.push(&labels, f64::from(value));
        }
        if let Some(found) = result.content_ok {
            content.push(&labels, f64::from(u8::from(found)));
        }
        if let Some(expires) = result.cert_expires {
            cert.push(&labels, expires.timestamp() as f64);
        }
        if let Some(expires) = result.domain_expires {
            domain.push(&labels, expires.timestamp() as f64);
        }
        if let Some(time) = monitor.checked_at(&site.identity) {
            checked.push(&labels, time.timestamp() as f64);
        }
    }

    let mut cycle_duration = Family::new(
        "wam_last_cycle_duration_seconds",
        "gauge",
        "Длительность последнего цикла проверок.",
    );
    let mut cycle_time = Family::new(
        "wam_last_cycle_timestamp_seconds",
        "gauge",
        "Время завершения последнего цикла (Unix time).",
    );
    if let Some(cycle) = monitor.last_cycle() {
        cycle_duration.push("", cycle.duration.as_secs_f64());
        cycle_time.push("", cycle.finished_at.timestamp() as f64);
    }

    let mut out = String::new();
    for family in [
        &build,
        &sites,
        &up,
        &status,
        &maintenance,
        &response,
        &code,
        &content,
        &cert,
        &domain,
        &checked,
        &uptime,
        &checks,
        &cycle_duration,
        &cycle_time,
    ] {
        family.write(&mut out);
    }
    out
}

fn response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    )
}

async fn handle_connection(mut stream: TcpStream, snapshot: Snapshot) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let read_head = async {
        while !request.windows(4).any(|window| window == b"\r\n\r\n") && request.len() < 8 * 1024 {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => request.extend_from_slice(&buffer[..read]),
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(5), read_head)
        .await
        .is_err()
    {
        return;
    }
    let head = String::from_utf8_lossy(&request);
    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();
    let reply = match (method, path) {
        ("GET", "/metrics") => {
            let body = snapshot.read().map(|text| text.clone()).unwrap_or_default();
            response("200 OK", "text/plain; version=0.0.4; charset=utf-8", &body)
        }
        ("GET", "/health") => response("200 OK", "text/plain; charset=utf-8", "ok\n"),
        ("GET", "/") => response(
            "200 OK",
            "text/plain; charset=utf-8",
            "WebsiteAccessibilityMonitor\n/metrics - метрики Prometheus\n/health - проверка работы\n",
        ),
        ("GET", _) => response("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
        _ => response(
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n",
        ),
    };
    let _ = stream.write_all(reply.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Serves `/metrics`, `/health` and `/` until the task is dropped.
pub async fn serve(listener: TcpListener, snapshot: Snapshot) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        tokio::spawn(handle_connection(stream, Arc::clone(&snapshot)));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::monitor::ScanMessage;
    use crate::{WebsiteResult, get_default_config};

    #[test]
    fn labels_are_escaped() {
        assert_eq!(escape_label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn renders_site_metrics() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = get_default_config();
        config.websites = vec!["https://a.example/".into()];
        let mut monitor =
            crate::monitor::Monitor::new(config, directory.path().to_path_buf()).unwrap();
        let mut result = WebsiteResult::pending("https://a.example/");
        result.status = "SLOW".into();
        result.code = "200".into();
        result.duration_ms = 4_200;
        result.direct_ok = true;
        result.cert_expires = chrono::DateTime::from_timestamp(1_800_000_000, 0);
        monitor.handle(ScanMessage::Result {
            identity: "https://a.example/".into(),
            started: Instant::now(),
            result: Box::new(result),
        });

        let text = render(&monitor);

        let labels = r#"url="https://a.example/",group="""#;
        assert!(text.contains(&format!("wam_up{{{labels}}} 1")), "{text}");
        assert!(text.contains(&format!("wam_status{{{labels},status=\"SLOW\"}} 1")));
        assert!(text.contains(&format!("wam_response_time_seconds{{{labels}}} 4.2")));
        assert!(text.contains(&format!(
            "wam_cert_expiry_timestamp_seconds{{{labels}}} 1800000000"
        )));
        assert!(text.contains(&format!("wam_checks_total{{{labels},result=\"ok\"}} 1")));
        assert!(text.contains("# TYPE wam_checks_total counter"));
        assert!(
            !text.contains("wam_domain_expiry"),
            "empty families are omitted"
        );
    }

    #[tokio::test]
    async fn http_endpoint_serves_snapshot_and_rejects_unknown_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let snapshot: Snapshot = Arc::new(RwLock::new("wam_sites 3\n".into()));
        tokio::spawn(serve(listener, snapshot));
        let client = reqwest::Client::new();

        let metrics = client
            .get(format!("http://{address}/metrics"))
            .send()
            .await
            .unwrap();
        assert!(
            metrics.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/plain; version=0.0.4")
        );
        assert_eq!(metrics.text().await.unwrap(), "wam_sites 3\n");
        let missing = client
            .get(format!("http://{address}/nope"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);
    }
}
