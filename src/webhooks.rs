use std::time::Duration;

use futures_util::future::{BoxFuture, FutureExt, join_all};
use reqwest::Client;

use crate::model::Config;
use crate::notice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    Down,
    Recovered,
}

impl AlertKind {
    const fn title(self) -> &'static str {
        match self {
            Self::Down => "Сайт недоступен",
            Self::Recovered => "Сайт восстановлен",
        }
    }

    const fn discord_color(self) -> u32 {
        match self {
            Self::Down => 0xD7_26_3D,
            Self::Recovered => 0x2E_A0_43,
        }
    }
}

/// Webhook URLs and the Telegram bot token are secrets. `reqwest::Error` prints the request
/// URL, so it is stripped before the error reaches the UI or a log.
async fn post_json(client: &Client, url: &str, payload: serde_json::Value, service: &str) {
    if let Err(error) = try_post_json(client, url, payload, service).await {
        notice::error(error);
    }
}

async fn try_post_json(
    client: &Client,
    url: &str,
    payload: serde_json::Value,
    service: &str,
) -> Result<(), String> {
    match client.post(url).json(&payload).send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(format!(
            "{service}: webhook ответил HTTP {}. Проверьте адрес и права бота.",
            response.status()
        )),
        Err(error) => Err(format!(
            "{service}: не удалось отправить уведомление: {}",
            error.without_url()
        )),
    }
}

pub async fn send_telegram_webhook(client: &Client, bot_token: &str, chat_id: &str, message: &str) {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": message,
        "disable_web_page_preview": true
    });
    post_json(client, &url, payload, "Telegram").await;
}

pub async fn send_discord_webhook(client: &Client, url: &str, kind: AlertKind, message: &str) {
    let payload = serde_json::json!({
        "embeds": [{
            "title": kind.title(),
            "description": message,
            "color": kind.discord_color()
        }]
    });
    post_json(client, url, payload, "Discord").await;
}

pub async fn send_slack_webhook(client: &Client, url: &str, message: &str) {
    post_json(client, url, serde_json::json!({ "text": message }), "Slack").await;
}

/// Sends `message` to every configured channel concurrently, bounded by a shared timeout.
pub async fn send_all_webhooks(client: &Client, config: &Config, kind: AlertKind, message: &str) {
    let hooks = &config.webhooks;
    if !hooks.enabled {
        return;
    }
    let mut sends: Vec<BoxFuture<'_, ()>> = Vec::new();
    if !hooks.telegram_bot_token.is_empty() && !hooks.telegram_chat_id.is_empty() {
        sends.push(
            send_telegram_webhook(
                client,
                &hooks.telegram_bot_token,
                &hooks.telegram_chat_id,
                message,
            )
            .boxed(),
        );
    }
    if !hooks.discord_webhook_url.is_empty() {
        sends.push(send_discord_webhook(client, &hooks.discord_webhook_url, kind, message).boxed());
    }
    if !hooks.slack_webhook_url.is_empty() {
        sends.push(send_slack_webhook(client, &hooks.slack_webhook_url, message).boxed());
    }
    if sends.is_empty() {
        notice::warn("Уведомления включены, но ни один канал не настроен");
        return;
    }
    if tokio::time::timeout(Duration::from_secs(15), join_all(sends))
        .await
        .is_err()
    {
        notice::error("Отправка уведомлений превысила общий таймаут 15 секунд");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transport_errors_do_not_leak_the_bot_token() {
        let client = Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap();
        // Port 9 on localhost refuses connections immediately.
        let error = try_post_json(
            &client,
            "http://127.0.0.1:9/botSECRET-TOKEN/sendMessage",
            serde_json::json!({}),
            "Telegram",
        )
        .await
        .unwrap_err();

        assert!(!error.contains("SECRET-TOKEN"), "{error}");
    }
}
