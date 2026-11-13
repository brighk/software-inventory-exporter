use crate::config::{Collector, Kind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Software {
    pub name: String,
    pub version: Option<String>,
    pub source: Kind,
    pub scope: String,
    pub architecture: String,
    pub installation_id: String,
    pub path: Option<PathBuf>,
    pub evidence: String,
}
impl Software {
    #[allow(clippy::too_many_arguments)] // One normalized record assembled by each format parser.
    pub fn new(
        c: &Collector,
        name: &str,
        version: &str,
        arch: &str,
        path: Option<PathBuf>,
        evidence: &str,
        identity: &str,
    ) -> Self {
        let key = format!(
            "{}\0{}\0{}\0{}\0{}",
            c.kind.name(),
            c.id,
            name,
            arch,
            identity
        );
        let hash = Sha256::digest(key.as_bytes());
        Self {
            name: name.into(),
            version: if version.is_empty() {
                None
            } else {
                Some(version.into())
            },
            source: c.kind,
            scope: c.id.clone(),
            architecture: arch.into(),
            installation_id: format!("{hash:x}")[..24].into(),
            path,
            evidence: evidence.into(),
        }
    }
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CollectorState {
    pub max_depth: usize,
    pub source: String,
    pub path: PathBuf,
    pub success: bool,
    pub last_attempt_timestamp_seconds: u64,
    pub last_success_timestamp_seconds: Option<u64>,
    pub duration_seconds: f64,
    pub error: Option<String>,
    pub software: Vec<Software>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Inventory {
    pub schema_version: u32,
    pub initial_scan_complete: bool,
    pub collectors: BTreeMap<String, CollectorState>,
}
impl Inventory {
    pub fn apply(
        &mut self,
        c: &Collector,
        result: anyhow::Result<Vec<Software>>,
        timestamp: u64,
        duration: f64,
    ) {
        let state = self.collectors.entry(c.id.clone()).or_default();
        state.source = c.kind.name().into();
        state.max_depth = c.max_depth;
        state.path = c.path.clone();
        state.last_attempt_timestamp_seconds = timestamp;
        state.duration_seconds = duration;
        match result {
            Ok(mut items) => {
                items.sort_by(|a, b| {
                    (&a.name, &a.installation_id, &a.version).cmp(&(
                        &b.name,
                        &b.installation_id,
                        &b.version,
                    ))
                });
                items.dedup();
                state.software = items;
                state.success = true;
                state.last_success_timestamp_seconds = Some(timestamp);
                state.error = None;
            }
            Err(error) => {
                state.success = false;
                state.error = Some(format!("{error:#}"));
            }
        }
    }
}
