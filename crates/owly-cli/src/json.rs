//! The CLI's opt-in JSON Lines interface for desktop frontends.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;

use owly_airdrop::driver::receiver::{ReceiverEvent, Request};
use owly_airdrop::proto::messages::Offer;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::mpsc;

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Ready,
    Receiver {
        id: String,
        name: String,
        address: String,
    },
    Request {
        id: u64,
        sender: String,
        items: Vec<String>,
        timeout: u64,
    },
    Withdrawn {
        id: u64,
    },
    Received {
        id: u64,
        paths: Vec<PathBuf>,
    },
    Urls {
        id: u64,
        urls: Vec<String>,
    },
    Failed {
        id: u64,
        reason: String,
    },
}

/// Complete and flush each line so a pipe reader can respond immediately.
pub fn write_event(output: &mut impl Write, event: &Event) -> io::Result<()> {
    serde_json::to_writer(&mut *output, event).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::InvalidData),
            error,
        )
    })?;
    output.write_all(b"\n")?;
    output.flush()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: u64,
    accept: bool,
}

/// Diagnostics stay on stderr. Returning drops unanswered requests (a decline).
/// Keeping input/output injectable lets tests exercise the actual pipe loop.
pub async fn receive(
    mut events: mpsc::Receiver<ReceiverEvent>,
    input: impl AsyncBufRead + Unpin,
    mut output: impl Write,
) -> io::Result<()> {
    let mut pending: HashMap<u64, Request> = HashMap::new();
    let mut lines = input.lines();
    write_event(&mut output, &Event::Ready)?;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()) };
                match serde_json::from_str::<Decision>(&line) {
                    Ok(answer) => {
                        if let Some(request) = pending.remove(&answer.id) {
                            if answer.accept { request.accept(); } else { request.decline(); }
                        }
                    }
                    Err(error) => eprintln!("invalid decision: {error}"),
                }
            }
            event = events.recv() => {
                let Some(event) = event else { return Ok(()) };
                let event = match event {
                    ReceiverEvent::Discovered { .. } => continue,
                    ReceiverEvent::Request(request) => {
                        let items = match &request.ask.offer {
                            Offer::Files(files) => files.iter().map(|file| file.name.clone()).collect(),
                            Offer::Urls(urls) => urls.clone(),
                        };
                        let event = Event::Request {
                            id: request.id,
                            sender: request.ask.sender_computer_name.clone(),
                            items,
                            timeout: owly_airdrop::proto::receiver::ASK_TIMEOUT.as_secs(),
                        };
                        pending.insert(request.id, request);
                        event
                    }
                    ReceiverEvent::Withdrawn { id } => {
                        pending.remove(&id);
                        Event::Withdrawn { id }
                    }
                    ReceiverEvent::Received { id, paths } => {
                        pending.remove(&id);
                        Event::Received { id, paths }
                    }
                    ReceiverEvent::Urls { id, urls } => {
                        pending.remove(&id);
                        Event::Urls { id, urls }
                    }
                    ReceiverEvent::Failed { id, reason } => {
                        pending.remove(&id);
                        Event::Failed { id, reason }
                    }
                };
                write_event(&mut output, &event)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;
    use tokio::io::{AsyncWriteExt, BufReader};

    #[test]
    fn decisions_require_an_id_and_an_explicit_boolean() {
        let decision: Decision = serde_json::from_str(r#"{"id":7,"accept":false}"#).unwrap();
        assert_eq!(decision.id, 7);
        assert!(!decision.accept);
        for invalid in [
            r#"{"accept":true}"#,
            r#"{"id":7}"#,
            r#"{"id":7,"accept":"yes"}"#,
            r#"{"id":-1,"accept":true}"#,
            r#"{"id":7,"accept":true,"extra":1}"#,
        ] {
            assert!(serde_json::from_str::<Decision>(invalid).is_err());
        }
    }

    #[test]
    fn events_escape_untrusted_names_and_flush_complete_lines() {
        struct Output {
            bytes: Vec<u8>,
            flushes: usize,
        }
        impl Write for Output {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let mut output = Output {
            bytes: Vec::new(),
            flushes: 0,
        };
        let name = "Jane's \"iPhone\"\nnext line";
        write_event(
            &mut output,
            &Event::Receiver {
                id: "abc".into(),
                name: name.into(),
                address: "[fe80::1%4]:8770".into(),
            },
        )
        .unwrap();
        assert_eq!(output.flushes, 1);
        assert_eq!(output.bytes.iter().filter(|b| **b == b'\n').count(), 1);
        let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert_eq!(
            value,
            json!({"event":"receiver","id":"abc","name":name,"address":"[fe80::1%4]:8770"})
        );
    }

    #[test]
    fn closed_output_is_reported_instead_of_panicking_or_hiding_failure() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(
            write_event(&mut Closed, &Event::Ready).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    struct Lines(mpsc::UnboundedSender<serde_json::Value>, Vec<u8>);
    impl Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.1.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            let value = serde_json::from_slice(&self.1)?;
            self.0
                .send(value)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.1.clear();
            Ok(())
        }
    }

    #[tokio::test]
    async fn receiver_reports_results_and_ends_when_events_close() {
        let (tx, rx) = mpsc::channel(8);
        tx.send(ReceiverEvent::Withdrawn { id: 1 }).await.unwrap();
        tx.send(ReceiverEvent::Received {
            id: 2,
            paths: vec![PathBuf::from("/tmp/a b.txt")],
        })
        .await
        .unwrap();
        tx.send(ReceiverEvent::Urls {
            id: 3,
            urls: vec!["https://example.org".into()],
        })
        .await
        .unwrap();
        tx.send(ReceiverEvent::Failed {
            id: 4,
            reason: "upload failed\nclosed".into(),
        })
        .await
        .unwrap();
        drop(tx);
        let (_keep_input_open, input) = tokio::io::duplex(256);
        let mut bytes = Vec::new();
        receive(rx, BufReader::new(input), &mut bytes)
            .await
            .unwrap();
        let values: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            values,
            vec![
                json!({"event":"ready"}),
                json!({"event":"withdrawn","id":1}),
                json!({"event":"received","id":2,"paths":["/tmp/a b.txt"]}),
                json!({"event":"urls","id":3,"urls":["https://example.org"]}),
                json!({"event":"failed","id":4,"reason":"upload failed\nclosed"})
            ]
        );
    }

    #[tokio::test]
    async fn closing_stdin_stops_an_otherwise_live_receiver() {
        let (_tx, rx) = mpsc::channel(1);
        let mut output = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), receive(rx, &b""[..], &mut output))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output, b"{\"event\":\"ready\"}\n");
    }

    // Use an actual driver Request, whose private reply channel is owned by the
    // TLS driver. No test-only constructor or change to the library is needed.
    async fn exercise_request(action: &str) {
        use owly_airdrop::driver::{
            receiver::{Options, Receiver},
            sender::{Payload, Sender},
            tls::Identity,
        };
        use owly_airdrop::proto::{
            receiver::Config,
            sender::{Config as SenderConfig, Outcome},
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::generate().unwrap();
        let mut config = Config::new("receiver");
        if action == "timeout" {
            config.ask_timeout = Duration::from_millis(100);
        }
        let (driver, mut driver_events) = Receiver::bind(
            "[::1]:0".parse().unwrap(),
            &identity,
            Options::new(config, dir.path().into()),
        )
        .await
        .unwrap();
        let addr = driver.local_addr().unwrap();
        let driver_task = tokio::spawn(driver.run());
        let sender_task = tokio::spawn(async move {
            Sender::new(SenderConfig::new("sender", "0123456789ab"))
                .unwrap()
                .send(
                    addr,
                    &Payload::Urls(vec!["https://example.org".into()]),
                    0,
                    None,
                )
                .await
                .unwrap()
        });
        let request = loop {
            if let ReceiverEvent::Request(request) = driver_events.recv().await.unwrap() {
                break request;
            }
        };
        let id = request.id;
        let (tx, rx) = mpsc::channel(4);
        tx.send(ReceiverEvent::Request(request)).await.unwrap();
        let (mut input, reader) = tokio::io::duplex(1024);
        let (lines, mut output) = mpsc::unbounded_channel();
        let frontend = tokio::spawn(receive(
            rx,
            BufReader::new(reader),
            Lines(lines, Vec::new()),
        ));
        assert_eq!(output.recv().await.unwrap(), json!({"event":"ready"}));
        let event = output.recv().await.unwrap();
        assert_eq!(
            event,
            json!({"event":"request","id":id,"sender":"sender","items":["https://example.org"],"timeout":15})
        );
        match action {
            "accept" | "decline" => {
                // Bad and unrelated decisions must not answer this request.
                input
                    .write_all(b"not json\n{\"id\":99999,\"accept\":true}\n")
                    .await
                    .unwrap();
                input
                    .write_all(
                        format!("{{\"id\":{id},\"accept\":{}}}\n", action == "accept").as_bytes(),
                    )
                    .await
                    .unwrap();
                // A duplicate decision must not reverse the first answer.
                input
                    .write_all(
                        format!("{{\"id\":{id},\"accept\":{}}}\n", action != "accept").as_bytes(),
                    )
                    .await
                    .unwrap();
            }
            "withdraw" => {
                tx.send(ReceiverEvent::Withdrawn { id }).await.unwrap();
                assert_eq!(
                    output.recv().await.unwrap(),
                    json!({"event":"withdrawn","id":id})
                );
                input
                    .write_all(format!("{{\"id\":{id},\"accept\":true}}\n").as_bytes())
                    .await
                    .unwrap();
            }
            "timeout" => {
                let withdrawn = driver_events.recv().await.unwrap();
                assert!(
                    matches!(withdrawn, ReceiverEvent::Withdrawn { id: withdrawn_id } if withdrawn_id == id)
                );
                tx.send(withdrawn).await.unwrap();
                assert_eq!(
                    output.recv().await.unwrap(),
                    json!({"event":"withdrawn","id":id})
                );
            }
            "eof" => {
                drop(input);
            }
            _ => unreachable!(),
        }
        let outcome = sender_task.await.unwrap();
        assert_eq!(
            outcome,
            if action == "accept" {
                Outcome::Delivered
            } else {
                Outcome::Declined
            }
        );
        frontend.abort();
        driver_task.abort();
    }

    #[tokio::test]
    async fn decisions_answer_only_pending_requests_and_eof_declines() {
        for action in ["accept", "decline", "withdraw", "timeout", "eof"] {
            tokio::time::timeout(Duration::from_secs(5), exercise_request(action))
                .await
                .unwrap();
        }
    }
}
