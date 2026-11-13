//! Conservative Arch advisory matching. Uncertain version ranges remain review findings.
use crate::{database::Database, model};
use alpm_types::Version;
use anyhow::{Context, Result, bail};
use clap::Args;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::PathBuf,
    time::Duration,
};

const FEED_URL: &str = "https://security.archlinux.org/issues/all.json";
const MAX_FEED: usize = 32 * 1024 * 1024;
#[derive(Args)]
pub struct Options {
    #[arg(long, default_value = "inventory.db")]
    database: PathBuf,
    /// Use a local Arch tracker JSON fixture instead of downloading the feed.
    #[arg(long)]
    feed_file: Option<PathBuf>,
    #[arg(long, default_value_t = 3600)]
    interval_seconds: u64,
    #[arg(long)]
    once: bool,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct Advisory {
    name: String,
    packages: Vec<String>,
    status: String,
    severity: String,
    affected: Option<String>,
    fixed: Option<String>,
    issues: Vec<String>,
}

fn classify(version: &str, advisory: &Advisory) -> Option<&'static str> {
    if advisory.status == "Not affected" {
        return None;
    }
    let Ok(installed) = version.parse::<Version>() else {
        return Some("needs_review");
    };
    if let Some(fixed) = advisory.fixed.as_deref().filter(|v| !v.is_empty()) {
        let Ok(fixed) = fixed.parse::<Version>() else {
            return Some("needs_review");
        };
        if Version::vercmp(&installed, &fixed) >= 0 {
            return None;
        }
    }
    let exact_affected = advisory
        .affected
        .as_deref()
        .and_then(|v| v.parse::<Version>().ok())
        .is_some_and(|affected| Version::vercmp(&installed, &affected) == 0);
    if exact_affected && matches!(advisory.status.as_str(), "Vulnerable" | "Fixed") {
        Some("affected")
    } else {
        // The tracker's affected value is not a proven introduced-version bound.
        Some("needs_review")
    }
}

fn parse_feed(bytes: &[u8]) -> Result<Vec<Advisory>> {
    let feed: Vec<Advisory> =
        serde_json::from_slice(bytes).context("invalid Arch advisory feed")?;
    if feed.is_empty() || feed.len() > 100_000 {
        bail!("empty or oversized advisory feed");
    }
    let mut ids = HashSet::new();
    for advisory in &feed {
        if !advisory.name.starts_with("AVG-")
            || !ids.insert(&advisory.name)
            || advisory.packages.is_empty()
            || advisory.packages.iter().any(|p| p.is_empty())
            || advisory.issues.is_empty()
        {
            bail!("invalid advisory identity, package list or issues");
        }
    }
    Ok(feed)
}

impl Database {
    pub fn assess(&mut self, bytes: &[u8], source: &str) -> Result<()> {
        let advisories = parse_feed(bytes)?;
        let mut by_package: HashMap<&str, Vec<&Advisory>> = HashMap::new();
        for advisory in &advisories {
            for package in &advisory.packages {
                by_package.entry(package).or_default().push(advisory);
            }
        }
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = model::now() as i64;
        tx.execute("DELETE FROM advisories", [])?;
        for advisory in &advisories {
            tx.execute(
                "INSERT INTO advisories(id,source,data) VALUES (?1,'arch',?2)",
                params![advisory.name, serde_json::to_string(advisory)?],
            )?;
        }
        tx.execute("DELETE FROM assessments", [])?;
        {
            let mut stmt = tx.prepare("SELECT i.host_id,i.collector_id,i.installation_id,i.version,i.name,i.source,h.os,h.last_sequence,c.success,c.active
                FROM installations i JOIN hosts h ON h.id=i.host_id JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let host: String = row.get(0)?;
                let collector: String = row.get(1)?;
                let identity: String = row.get(2)?;
                let version: Option<String> = row.get(3)?;
                let name: String = row.get(4)?;
                let ecosystem: String = row.get(5)?;
                let os: String = row.get(6)?;
                let sequence: i64 = row.get(7)?;
                let successful: bool = row.get(8)?;
                let active: bool = row.get(9)?;
                let mut findings = Vec::new();
                let status = if !successful || !active {
                    "stale_inventory"
                } else if os != "arch" || ecosystem != "pacman" {
                    "unsupported"
                } else if let Some(version) = &version {
                    if let Some(records) = by_package.get(name.as_str()) {
                        for advisory in records {
                            if let Some(status) = classify(version, advisory) {
                                findings.push(json!({"advisory_id":advisory.name,"cves":advisory.issues,
                                        "severity":advisory.severity,"status":status,"fixed_version":advisory.fixed,
                                        "tracker_status":advisory.status}));
                            }
                        }
                    }
                    if findings.iter().any(|f| f["status"] == "affected") {
                        "affected"
                    } else if !findings.is_empty() {
                        "needs_review"
                    } else {
                        "no_known_match"
                    }
                } else {
                    "not_assessed"
                };
                tx.execute("INSERT INTO assessments(host_id,collector_id,installation_id,version,name,sequence,assessed_at,status,findings)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![host,collector,identity,version.unwrap_or_default(),name,sequence,now,status,serde_json::to_string(&findings)?])?;
            }
        }
        tx.execute("INSERT INTO assessment_state(id,last_attempt,last_success,success,feed_sha256,feed_source) VALUES (1,?1,?1,1,?2,?3)
            ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,last_success=excluded.last_success,success=1,error=NULL,
            feed_sha256=excluded.feed_sha256,feed_source=excluded.feed_source",
            params![now,format!("{:x}",Sha256::digest(bytes)),source])?;
        tx.commit()?;
        Ok(())
    }
    pub fn assessment_failed(&self, error: &str) -> Result<()> {
        self.0.execute("INSERT INTO assessment_state(id,last_attempt,success,error) VALUES(1,?1,0,?2)
            ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,success=0,error=excluded.error",
            params![model::now() as i64,error])?;
        Ok(())
    }
    pub fn assessment_status(&self) -> Result<Value> {
        Ok(self.0.query_row("SELECT last_attempt,last_success,success,error,feed_sha256,feed_source FROM assessment_state WHERE id=1",[],|r| Ok(json!({
            "last_attempt":r.get::<_,i64>(0)?,"last_success":r.get::<_,Option<i64>>(1)?,"success":r.get::<_,bool>(2)?,
            "error":r.get::<_,Option<String>>(3)?,"feed_sha256":r.get::<_,Option<String>>(4)?,"feed_source":r.get::<_,Option<String>>(5)?
        }))).optional()?.unwrap_or(json!({"success":false,"last_success":null,"error":"not assessed"})))
    }
    pub fn findings(&self, host: Option<&str>, limit: i64, offset: i64) -> Result<Vec<Value>> {
        let mut stmt = self.0.prepare("SELECT i.host_id,i.collector_id,i.installation_id,i.name,i.version,a.status,a.findings,a.assessed_at,
            a.sequence,h.last_sequence,c.success,c.active,h.last_seen
            FROM installations i JOIN hosts h ON h.id=i.host_id JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id
            LEFT JOIN assessments a ON a.host_id=i.host_id AND a.collector_id=i.collector_id AND a.installation_id=i.installation_id AND a.version=COALESCE(i.version,'')
            WHERE (?1 IS NULL OR i.host_id=?1) ORDER BY i.host_id,i.collector_id,i.installation_id,i.version LIMIT ?2 OFFSET ?3")?;
        let rows = stmt.query_map(params![host,limit,offset], |r| {
            let assessed_sequence: Option<i64> = r.get(8)?;
            let current_sequence: i64 = r.get(9)?;
            let success: bool = r.get(10)?; let active: bool = r.get(11)?;
            let stored_status: Option<String> = r.get(5)?;
            let status = if !success || !active { "stale_inventory" }
                else if assessed_sequence.is_some_and(|s| s != current_sequence) { "pending" }
                else { stored_status.as_deref().unwrap_or("not_assessed") };
            let findings: Option<String> = r.get(6)?;
            Ok(json!({"host_id":r.get::<_,String>(0)?,"collector_id":r.get::<_,String>(1)?,
                "installation_id":r.get::<_,String>(2)?,"name":r.get::<_,String>(3)?,"version":r.get::<_,Option<String>>(4)?,
                "status":status,"findings":findings.and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!([])),
                "assessed_at":r.get::<_,Option<i64>>(7)?,"host_last_seen":r.get::<_,i64>(12)?}))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

async fn feed(file: &Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(path) = file {
        let path = path.clone();
        return tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(MAX_FEED as u64 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_FEED {
                bail!("feed exceeds 32 MiB");
            }
            Ok(bytes)
        })
        .await?;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client.get(FEED_URL).send().await?.error_for_status()?;
    if !response.status().is_success() {
        bail!("unexpected feed response");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_FEED {
            bail!("feed exceeds 32 MiB");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub async fn run(options: Options) -> Result<()> {
    if options.interval_seconds == 0 {
        bail!("interval must be positive");
    }
    loop {
        let downloaded = feed(&options.feed_file).await;
        let path = options.database.clone();
        let source = options
            .feed_file
            .as_ref()
            .map(|p| format!("file:{}", p.display()))
            .unwrap_or(FEED_URL.into());
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut db = Database::open(&path)?;
            let result = downloaded.and_then(|bytes| db.assess(&bytes, &source));
            if let Err(error) = &result {
                db.assessment_failed(&format!("{error:#}"))?;
            }
            result
        })
        .await?;
        if options.once {
            return result;
        }
        match result {
            Ok(()) => eprintln!("Arch assessment completed"),
            Err(e) => eprintln!("Arch assessment failed: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(options.interval_seconds)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arch_versions_and_uncertainty() {
        let mut a = Advisory {
            name: "AVG-1".into(),
            packages: vec!["demo".into()],
            status: "Fixed".into(),
            severity: "High".into(),
            affected: Some("1:2.9-1".into()),
            fixed: Some("1:2.10-2".into()),
            issues: vec!["CVE-TEST".into()],
        };
        assert_eq!(classify("1:2.9-1", &a), Some("affected"));
        assert_eq!(classify("1:2.10-1", &a), Some("needs_review"));
        assert_eq!(classify("1:2.10-2", &a), None);
        assert_eq!(classify("2:1.0-1", &a), None);
        assert_eq!(classify("0.1-1", &a), Some("needs_review"));
        a.status = "Unknown".into();
        assert_eq!(classify("1:2.9-1", &a), Some("needs_review"));
        a.fixed = None;
        assert_eq!(classify("3:1-1", &a), Some("needs_review"));
        assert!(parse_feed(b"[]").is_err());
    }
}
