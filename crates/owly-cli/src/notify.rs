//! Desktop notifications (`org.freedesktop.Notifications`) for `owly receive`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use futures_util::StreamExt;
use owly_airdrop::proto::messages::Offer;
use zbus::zvariant::Value;

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// A connection to the session notification daemon (`org.freedesktop.Notifications`).
pub struct Notifier {
    proxy: NotificationsProxy<'static>,
}

/// An active Accept/Decline prompt notification awaiting user interaction.
pub struct PendingPrompt {
    proxy: NotificationsProxy<'static>,
    id: u32,
    actions: ActionInvokedStream,
    actions_done: bool,
    closed: NotificationClosedStream,
    closed_done: bool,
}

impl Notifier {
    pub async fn connect() -> Result<Self, String> {
        let conn = zbus::Connection::session()
            .await
            .map_err(|e| format!("session D-Bus: {e}"))?;
        let proxy = NotificationsProxy::new(&conn)
            .await
            .map_err(|e| format!("org.freedesktop.Notifications: {e}"))?;
        Ok(Self { proxy })
    }

    pub async fn notify_info(&self, summary: &str, body: &str, timeout: Duration) {
        let summary = escape_markup(&sanitize_text(summary, 120));
        let body = escape_markup(&sanitize_text(body, 300));
        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let _ = self
            .proxy
            .notify(
                "owly",
                0,
                "network-wireless",
                &summary,
                &body,
                &[],
                HashMap::new(),
                timeout_ms,
            )
            .await;
    }

    pub async fn prompt_request(
        &self,
        sender: &str,
        model: &str,
        offer: &Offer,
        timeout: Duration,
    ) -> Result<PendingPrompt, String> {
        let actions = self
            .proxy
            .receive_action_invoked()
            .await
            .map_err(|e| format!("ActionInvoked stream: {e}"))?;
        let closed = self
            .proxy
            .receive_notification_closed()
            .await
            .map_err(|e| format!("NotificationClosed stream: {e}"))?;
        let summary = escape_markup(&format!("AirDrop from {}", sanitize_text(sender, 64)));
        let body = escape_markup(&format_offer_summary(sender, model, offer));
        let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let id = self
            .proxy
            .notify(
                "owly",
                0,
                "network-wireless",
                &summary,
                &body,
                &["accept", "Accept", "decline", "Decline"],
                HashMap::new(),
                timeout_ms,
            )
            .await
            .map_err(|e| format!("Notify: {e}"))?;
        Ok(PendingPrompt {
            proxy: self.proxy.clone(),
            id,
            actions,
            actions_done: false,
            closed,
            closed_done: false,
        })
    }
}

impl PendingPrompt {
    pub async fn wait(&mut self) -> Option<bool> {
        while !self.actions_done || !self.closed_done {
            tokio::select! {
                ev = self.actions.next(), if !self.actions_done => {
                    match ev {
                        Some(sig) => {
                            if let Ok(args) = sig.args()
                                && args.id == self.id
                                && let Some(decision) = parse_action_key(&args.action_key)
                            {
                                return Some(decision);
                            }
                        }
                        None => self.actions_done = true,
                    }
                }
                ev = self.closed.next(), if !self.closed_done => {
                    match ev {
                        Some(sig) => {
                            if let Ok(args) = sig.args() && args.id == self.id {
                                return Some(false);
                            }
                        }
                        None => self.closed_done = true,
                    }
                }
            }
        }
        None
    }

    pub async fn close(self) {
        let _ = self.proxy.close_notification(self.id).await;
    }
}

/// SEC-4: strips control characters and caps length before handing untrusted
/// sender metadata to the desktop notification daemon.
pub fn sanitize_text(input: &str, max_chars: usize) -> String {
    let mut cleaned = String::with_capacity(input.len().min(max_chars));
    let mut prev_space = true;
    for ch in input.chars() {
        let normalized = if ch.is_control() { ' ' } else { ch };
        if normalized.is_whitespace() {
            if !prev_space {
                cleaned.push(' ');
                prev_space = true;
            }
        } else {
            cleaned.push(normalized);
            prev_space = false;
        }
    }
    let trimmed = cleaned.trim();
    let count = trimmed.chars().count();
    if count <= max_chars {
        return trimmed.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    let mut truncated: String = trimmed.chars().take(max_chars.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

/// Notification bodies support XML-like markup. Escape all remotely supplied
/// text so a sender cannot inject links, images, or misleading formatting.
pub fn escape_markup(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\'' => escaped.push_str("&apos;"),
            '"' => escaped.push_str("&quot;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub fn format_offer_summary(sender: &str, model: &str, offer: &Offer) -> String {
    let model = sanitize_text(model, 48);
    let from = if model.is_empty() {
        sanitize_text(sender, 48)
    } else {
        format!("{} ({model})", sanitize_text(sender, 48))
    };
    let what = match offer {
        Offer::Files(files) => match files.as_slice() {
            [] => "no files".to_string(),
            [only] => match only.size {
                Some(bytes) => format!("{} ({bytes} bytes)", sanitize_text(&only.name, 80)),
                None => sanitize_text(&only.name, 80),
            },
            many => format!(
                "{} files (first: {})",
                many.len(),
                sanitize_text(&many[0].name, 60)
            ),
        },
        Offer::Urls(urls) => match urls.as_slice() {
            [] => "link".to_string(),
            [only] => format!("link: {}", sanitize_text(only, 120)),
            many => format!(
                "{} links (first: {})",
                many.len(),
                sanitize_text(&many[0], 80)
            ),
        },
    };
    sanitize_text(&format!("{from}: {what}"), 240)
}

pub fn format_received_summary(paths: &[PathBuf]) -> String {
    match paths {
        [] => "AirDrop received".to_string(),
        [only] => {
            let name = only
                .file_name()
                .and_then(|n| n.to_str())
                .map_or_else(|| only.display().to_string(), str::to_string);
            let name = sanitize_text(&name, 80);
            match std::fs::metadata(only) {
                Ok(m) if m.is_file() => format!("Saved {name} ({} bytes)", m.len()),
                _ => format!("Saved {name}"),
            }
        }
        many => format!("Saved {} files", many.len()),
    }
}

pub fn parse_action_key(key: &str) -> Option<bool> {
    match key {
        "accept" => Some(true),
        "decline" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use owly_airdrop::proto::messages::AskFile;

    use super::*;

    #[test]
    fn sanitize_text_strips_controls_and_truncates() {
        assert_eq!(sanitize_text("  hi\x1b[31m\nthere\t ", 40), "hi [31m there");
        assert_eq!(sanitize_text("abcdef", 4), "abc…");
        assert_eq!(sanitize_text("abcd", 4), "abcd");
    }

    #[test]
    fn escape_markup_renders_sender_input_as_text() {
        assert_eq!(
            escape_markup(r#"<a href="https://evil.example">photo & link</a>"#),
            "&lt;a href=&quot;https://evil.example&quot;&gt;photo &amp; link&lt;/a&gt;"
        );
    }

    #[test]
    fn format_offer_summary_handles_files_and_urls() {
        let single = Offer::Files(vec![AskFile {
            name: "photo.jpg".into(),
            file_type: "public.jpeg".into(),
            size: Some(1234),
            bom_path: "./photo.jpg".into(),
            is_directory: false,
        }]);
        assert_eq!(
            format_offer_summary("iPhone", "iPhone16,2", &single),
            "iPhone (iPhone16,2): photo.jpg (1234 bytes)"
        );

        let multi = Offer::Files(vec![
            AskFile {
                name: "one\x07.png".into(),
                file_type: "public.png".into(),
                size: None,
                bom_path: "./one.png".into(),
                is_directory: false,
            },
            AskFile {
                name: "two.png".into(),
                file_type: "public.png".into(),
                size: None,
                bom_path: "./two.png".into(),
                is_directory: false,
            },
        ]);
        assert_eq!(
            format_offer_summary("iPad", "", &multi),
            "iPad: 2 files (first: one .png)"
        );

        let urls = Offer::Urls(vec!["https://example.com/\x1b".into()]);
        assert_eq!(
            format_offer_summary("Mac", "Mac15,9", &urls),
            "Mac (Mac15,9): link: https://example.com/"
        );
    }

    #[test]
    fn format_received_summary_reports_single_and_multiple_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("IMG_0001.jpg");
        std::fs::write(&file, b"hello world").unwrap();
        assert_eq!(
            format_received_summary(std::slice::from_ref(&file)),
            "Saved IMG_0001.jpg (11 bytes)"
        );
        assert_eq!(
            format_received_summary(&[file, dir.path().join("two.jpg")]),
            "Saved 2 files"
        );
        assert_eq!(format_received_summary(&[]), "AirDrop received");
    }

    #[test]
    fn parse_action_key_matches_accept_and_decline() {
        assert_eq!(parse_action_key("accept"), Some(true));
        assert_eq!(parse_action_key("decline"), Some(false));
        assert_eq!(parse_action_key("default"), None);
    }
}
