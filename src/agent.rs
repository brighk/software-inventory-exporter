use crate::{
    config::Config,
    model::Inventory,
    protocol::{Host, MAX_BODY, Submission},
};
use anyhow::{Context, Result, bail};
use clap::Args;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Args)]
pub struct Options {
    /// API origin, e.g. http://127.0.0.1:9899 (HTTP allowed only on loopback).
    #[arg(long)]
    server: String,
    /// Stable provisioned identity; must match the server credentials file.
    #[arg(long)]
    host_id: String,
    #[arg(long)]
    hostname: String,
    /// Distribution ID, e.g. arch or macos (not package-manager name).
    #[arg(long)]
    os: String,
    /// Distribution release, e.g. rolling for Arch.
    #[arg(long)]
    os_version: String,
    #[arg(long, default_value = "agent-state.json")]
    state: PathBuf,
    /// Submit one snapshot (or retry a pending snapshot), then exit.
    #[arg(long)]
    once: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentState {
    host_id: String,
    server: String,
    last_sequence: i64,
    pending: Option<Submission>,
}

fn save(path: &Path, state: &AgentState) -> Result<()> {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

async fn acknowledge(mut response: reqwest::Response, sequence: i64) -> Result<()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 4096 {
            bail!("oversized server acknowledgment; pending snapshot retained");
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .context("invalid server acknowledgment; pending snapshot retained")?;
    if value["accepted"] != true || value["sequence"].as_i64() != Some(sequence) {
        bail!("unexpected server acknowledgment; pending snapshot retained");
    }
    Ok(())
}

pub async fn run(options: Options, config: Config) -> Result<()> {
    let origin = reqwest::Url::parse(&options.server)?;
    let loopback = origin.host_str().is_some_and(|h| {
        h == "localhost"
            || h == "[::1]"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(origin.scheme() == "https" || origin.scheme() == "http" && loopback)
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!(
            "server must be an HTTPS origin (or HTTP loopback), without credentials, path, query or fragment"
        );
    }
    let host = Host {
        id: options.host_id,
        hostname: options.hostname,
        os: options.os,
        os_version: options.os_version,
        architecture: std::env::consts::ARCH.into(),
    };
    Submission {
        protocol_version: 1,
        host: host.clone(),
        sequence: 1,
        inventory: Inventory {
            schema_version: 1,
            initial_scan_complete: true,
            ..Inventory::default()
        },
    }
    .validate()?;
    let token = std::env::var("INVENTORY_TOKEN")
        .context("set INVENTORY_TOKEN to this host's upload credential")?;
    if token.len() < 32 {
        bail!("INVENTORY_TOKEN must be at least 32 characters");
    }
    let mut bearer = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
    bearer.set_sensitive(true);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let endpoint = origin.join("v1/inventory")?;
    let mut lock = options.state.as_os_str().to_os_string();
    lock.push(".lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(lock))?;
    lock.try_lock_exclusive()
        .context("another agent is using this state file")?;
    let mut state = match fs::read(&options.state) {
        Ok(bytes) => serde_json::from_slice::<AgentState>(&bytes)
            .context("invalid agent state; do not reset the sequence")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => AgentState {
            host_id: host.id.clone(),
            server: origin.to_string(),
            last_sequence: 0,
            pending: None,
        },
        Err(e) => return Err(e.into()),
    };
    if state.host_id != host.id || state.server != origin.as_str() || state.last_sequence < 0 {
        bail!("state belongs to a different host/server or has an invalid sequence");
    }
    if let Some(pending) = &state.pending {
        pending.validate()?;
        if pending.host.id != host.id
            || Some(pending.sequence) != state.last_sequence.checked_add(1)
        {
            bail!("inconsistent pending submission");
        }
    }
    loop {
        if state.pending.is_none() {
            let mut inventory = Inventory {
                schema_version: 1,
                ..Inventory::default()
            };
            crate::scan(&mut inventory, &config).await;
            let submission = Submission {
                protocol_version: 1,
                host: host.clone(),
                sequence: state
                    .last_sequence
                    .checked_add(1)
                    .context("sequence exhausted")?,
                inventory,
            };
            submission.validate()?;
            if serde_json::to_vec(&submission)?.len() > MAX_BODY {
                bail!("submission exceeds server's 32 MiB limit");
            }
            state.pending = Some(submission);
            save(&options.state, &state)?;
        }
        let pending = state
            .pending
            .as_ref()
            .expect("pending saved before transmission");
        let response = client
            .post(endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, bearer.clone())
            .json(pending)
            .send()
            .await;
        let failed_collectors = pending.inventory.collectors.values().any(|c| !c.success);
        match response {
            Ok(response) if response.status().is_success() => {
                acknowledge(response, pending.sequence).await?;
                state.last_sequence = pending.sequence;
                state.pending = None;
                save(&options.state, &state)?;
                eprintln!("Submitted inventory sequence {}", state.last_sequence);
                if options.once {
                    if failed_collectors {
                        bail!("inventory delivered, but one or more collectors failed");
                    }
                    return Ok(());
                }
            }
            Ok(response) => {
                let status = response.status();
                if options.once || status.is_client_error() {
                    bail!("submission returned {status}; pending snapshot retained");
                }
                eprintln!("Submission returned {status}; pending snapshot retained for retry");
            }
            Err(error) => {
                if options.once {
                    return Err(error).context("submission failed; pending snapshot retained");
                }
                eprintln!("Submission failed; pending snapshot retained for retry: {error}");
            }
        }
        tokio::time::sleep(Duration::from_secs(config.interval_seconds)).await;
    }
}
