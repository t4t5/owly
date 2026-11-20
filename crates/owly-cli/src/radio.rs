//! `owly radio up` and `owly radio peers`, as clients of owlyd.

use std::process::ExitCode;

use crate::wifi;
use futures_util::StreamExt;
use owlyd::api::{self, LinkInfo, RadioProxy};
use tokio::signal::unix::{SignalKind, signal};

pub async fn connect(bus: Option<&str>) -> Result<RadioProxy<'static>, String> {
    let conn = api::connect(bus).await.map_err(|e| unreachable(&e))?;
    api::radio(&conn).await.map_err(|e| unreachable(&e))
}

fn unreachable(e: &zbus::Error) -> String {
    format!("owlyd can't be reached ({e}). `systemctl enable --now owlyd` starts it.")
}

/// The exit code for an API error: 3 to try again later, else 4.
pub fn exit_code(e: &zbus::Error) -> (u8, String) {
    match api::api_error(e) {
        Some(("NotNow" | "Busy", m)) => (3, m),
        Some((_, m)) => (4, m),
        None if api::unreachable(e) => (4, unreachable(e)),
        None => (4, e.to_string()),
    }
}

/// Takes the radio and holds it until Ctrl-C, SIGTERM, the duration or
/// the link's end.
pub async fn up(bus: Option<&str>, duration: u32, json: bool) -> Result<ExitCode, String> {
    // Cached, for the stream of peer changes.
    let conn = api::connect(bus).await.map_err(|e| unreachable(&e))?;
    let radio = RadioProxy::new(&conn).await.map_err(|e| unreachable(&e))?;
    let mut states = radio
        .receive_radio_state()
        .await
        .map_err(|e| unreachable(&e))?;
    eprintln!("bringing the radio up...");
    let wifi = wifi::active();
    let (lease, link) = match radio.acquire(duration).await {
        Ok(l) => l,
        Err(e) => {
            let (code, say) = exit_code(&e);
            eprintln!("owly: {say}");
            return Ok(ExitCode::from(code));
        }
    };
    if let Some(l) = LinkInfo::from_dict(&link) {
        eprintln!(
            "{} is up: {}%{} ({}). Ctrl-C takes it down.",
            l.interface, l.address, l.interface, l.mac
        );
        if let Some(a) = l.announce {
            eprintln!(
                "receivers on it announce {} times {} ms apart, every {} s (MDNS-7)",
                a.count,
                a.interval.as_millis(),
                a.pause.as_secs()
            );
        }
    }
    if json
        && let Err(error) =
            crate::json::write_event(&mut std::io::stdout(), &crate::json::Event::Ready)
    {
        // A frontend that closed its output pipe must not leave a lease held.
        let _ = radio.release(lease).await;
        wifi::restore(wifi).await;
        return Err(error.to_string());
    }
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut peers = radio.receive_peers_changed().await;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = term.recv() => break,
            Some(change) = peers.next() => {
                if let Ok(now) = change.get().await {
                    let lines: Vec<_> = now.iter().filter_map(api::peer_line).collect();
                    eprintln!("peers: {}", if lines.is_empty() { "none".into() } else { lines.join(", ") });
                }
            }
            Some(s) = states.next() => {
                let Ok(a) = s.args() else { continue };
                if a.lease == lease && a.state == "idle" {
                    eprintln!("owly: the radio went down: {}", a.reason);
                    wifi::restore(wifi).await;
                    return Ok(ExitCode::from(1));
                }
            }
        }
    }
    eprintln!("giving the radio back...");
    radio.release(lease).await.map_err(|e| e.to_string())?;
    wifi::restore(wifi).await;
    Ok(ExitCode::SUCCESS)
}

pub async fn peers(bus: Option<&str>) -> Result<ExitCode, String> {
    let radio = connect(bus).await?;
    let state = radio.current_state().await.map_err(|e| unreachable(&e))?;
    if state != "up" {
        eprintln!("owly: the radio isn't up");
        return Ok(ExitCode::from(4));
    }
    for line in radio
        .peers()
        .await
        .map_err(|e| e.to_string())?
        .iter()
        .filter_map(api::peer_line)
    {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}
