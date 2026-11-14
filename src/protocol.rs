//! Versioned agent/server contract. Sequence numbers belong to a stable host identity.
use crate::model::Inventory;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub protocol_version: u32,
    pub host: Host,
    pub sequence: i64,
    pub inventory: Inventory,
}

impl Submission {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != 1 || self.inventory.schema_version != 1 {
            bail!("unsupported protocol or inventory schema");
        }
        if self.sequence <= 0 || !self.inventory.initial_scan_complete {
            bail!("positive sequence and completed scan required");
        }
        if !valid_id(&self.host.id) {
            bail!("invalid host ID");
        }
        for value in [
            &self.host.hostname,
            &self.host.os,
            &self.host.os_version,
            &self.host.architecture,
        ] {
            if value.trim().is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
                bail!("host metadata must contain 1..255 bytes without control characters");
            }
        }
        if self.inventory.collectors.len() > 128 {
            bail!("too many collectors");
        }
        let mut count: usize = 0;
        for (id, state) in &self.inventory.collectors {
            if !valid_id(id)
                || !state.path.is_absolute()
                || !state.duration_seconds.is_finite()
                || state.duration_seconds < 0.0
                || state.last_attempt_timestamp_seconds == 0
                || state.last_attempt_timestamp_seconds > i64::MAX as u64
                || state
                    .last_success_timestamp_seconds
                    .is_some_and(|t: u64| t > state.last_attempt_timestamp_seconds)
            {
                bail!("invalid collector metadata: {id}");
            }
            let source: crate::config::Kind =
                serde_json::from_value::<crate::config::Kind>(serde_json::json!(state.source))?;
            if state.success
                && (state.error.is_some()
                    || state.last_success_timestamp_seconds
                        != Some(state.last_attempt_timestamp_seconds))
            {
                bail!("inconsistent successful collector: {id}");
            }
            if !state.success && state.error.is_none() {
                bail!("failed collector must include an error: {id}");
            }
            let mut identities: HashSet<(&String, &Option<String>)> = HashSet::new();
            for item in &state.software {
                count += 1;
                if count > 100_000
                    || item.scope != *id
                    || item.source != source
                    || item.name.trim().is_empty()
                    || item.name.len() > 4096
                    || [&item.source_package, &item.source_version].iter().any(
                        |v: &&Option<String>| {
                            v.as_ref()
                                .is_some_and(|v: &String| v.is_empty() || v.len() > 4096)
                        },
                    )
                    || item.installation_id.len() != 24
                    || !item
                        .installation_id
                        .bytes()
                        .all(|b: u8| b.is_ascii_hexdigit())
                    || !identities.insert((&item.installation_id, &item.version))
                {
                    bail!("invalid or duplicate installation in {id}");
                }
            }
        }
        Ok(())
    }
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
