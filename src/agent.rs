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

/// Maximum wait before retrying a pending snapshot after a failed delivery.
const RETRY_SECONDS: u64 = 300;

#[derive(Args)]
pub struct Options {
    /// API origin, e.g. http://127.0.0.1:9899 (HTTP allowed only on loopback).
    #[arg(long)]
    server: String,
    /// Stable provisioned identity; must match the server credentials file.
    #[arg(long)]
    host_id: String,
    /// Defaults to the kernel hostname.
    #[arg(long)]
    hostname: Option<String>,
    /// Distribution ID, e.g. arch or macos (not package-manager name).
    /// Defaults to ID from /etc/os-release; ID_LIKE is deliberately ignored.
    #[arg(long)]
    os: Option<String>,
    /// Distribution release. Defaults to VERSION_ID from /etc/os-release, or
    /// "rolling" when the file has no VERSION_ID (as on Arch).
    #[arg(long)]
    os_version: Option<String>,
    #[arg(long, default_value = "agent-state.json")]
    state: PathBuf,
    /// Submit one snapshot (or retry a pending snapshot), then exit.
    #[arg(long)]
    once: bool,
    /// PEM file with additional CA certificates to trust for the server's HTTPS
    /// certificate (e.g. an internal or self-signed CA). System roots stay trusted.
    #[arg(long)]
    ca_cert: Option<PathBuf>,
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

fn kernel_hostname() -> Result<String> {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success
    // when the name fits, and we cap the read at the first NUL or the buffer end.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("gethostname; pass --hostname");
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).context("non-UTF-8 hostname; pass --hostname")
}

/// Parses the os-release(5) KEY=value format, including simple quoting.
fn parse_os_release(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.trim().split_once('='))
        .filter(|(key, _)| !key.starts_with('#'))
        .map(|(key, value)| {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            (
                key.to_string(),
                value.replace("\\\"", "\"").replace("\\\\", "\\"),
            )
        })
        .collect()
}

fn os_release(path: &Path) -> Result<std::collections::HashMap<String, String>> {
    let text = match fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::read_to_string("/usr/lib/os-release")?
        }
        other => other?,
    };
    Ok(parse_os_release(&text))
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
    let release = match (&options.os, &options.os_version) {
        (Some(_), Some(_)) => Default::default(),
        _ => os_release(Path::new("/etc/os-release"))
            .context("cannot detect OS; pass --os and --os-version")?,
    };
    let host = Host {
        id: options.host_id,
        hostname: match options.hostname {
            Some(name) => name,
            None => kernel_hostname()?,
        },
        os: match options.os {
            Some(os) => os,
            None => release
                .get("ID")
                .cloned()
                .context("os-release has no ID; pass --os")?,
        },
        os_version: options.os_version.unwrap_or_else(|| {
            release
                .get("VERSION_ID")
                .cloned()
                .unwrap_or_else(|| "rolling".into())
        }),
        architecture: std::env::consts::ARCH.into(),
    };
    eprintln!(
        "Agent host {}: hostname={} os={} os_version={} arch={}",
        host.id, host.hostname, host.os, host.os_version, host.architecture
    );
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
    let mut client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = &options.ca_cert {
        let pem = fs::read(path).with_context(|| format!("read CA file {}", path.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parse CA file {}", path.display()))?;
        if certs.is_empty() {
            bail!("CA file {} contains no certificates", path.display());
        }
        for cert in certs {
            client = client.add_root_certificate(cert);
        }
    }
    let client = client.build()?;
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
        // A failed delivery retries sooner than the scan interval, so a short server
        // outage does not delay inventory by a whole (e.g. 12h) scan period.
        let delay = if state.pending.is_some() {
            config.interval_seconds.min(RETRY_SECONDS)
        } else {
            config.interval_seconds
        };
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_os_release() {
        let arch = super::parse_os_release(
            "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n# c=d\n",
        );
        assert_eq!(arch["ID"], "arch");
        assert_eq!(arch["NAME"], "Arch Linux");
        assert!(!arch.contains_key("VERSION_ID"));
        let derivative = super::parse_os_release("ID=endeavouros\nID_LIKE=arch\nVERSION_ID='1'\n");
        assert_eq!(derivative["ID"], "endeavouros");
        assert_eq!(derivative["VERSION_ID"], "1");
    }
}
