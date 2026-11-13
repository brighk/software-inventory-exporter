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

/// Effective assessment status of an installation row `i` joined with host `h`,
/// collector `c` and (left-joined) assessment `a`. Shared by the API and metrics.
pub const EFFECTIVE_STATUS: &str = "CASE WHEN c.success=0 OR c.active=0 THEN 'stale_inventory'
    WHEN a.sequence IS NOT NULL AND a.sequence<>h.last_sequence THEN 'pending'
    ELSE COALESCE(a.status,'not_assessed') END";
const FEED_URL: &str = "https://security.archlinux.org/issues/all.json";
const MAX_FEED: usize = 32 * 1024 * 1024;
#[derive(Args)]
pub struct Options {
    #[arg(long, default_value = "inventory.db")]
    database: PathBuf,
    /// Use a local Arch tracker JSON fixture instead of downloading the feed.
    #[arg(long)]
    feed_file: Option<PathBuf>,
    /// How often the Arch security tracker feed is downloaded.
    #[arg(long, default_value_t = 3600)]
    interval_seconds: u64,
    /// Disable the Arch security tracker (pacman packages become unsupported).
    #[arg(long)]
    no_arch: bool,
    /// Disable OSV.dev matching for Debian, Ubuntu, RPM distributions, PyPI, npm and crates.io.
    #[arg(long)]
    no_osv: bool,
    /// OSV API base URL.
    #[arg(long, default_value = crate::osv::DEFAULT_URL)]
    osv_url: String,
    /// Re-query cached OSV results older than this.
    #[arg(long, default_value_t = 6 * 3600)]
    osv_refresh_seconds: u64,
    #[arg(long)]
    once: bool,
    /// Disable CVSS enrichment from the NIST NVD API.
    #[arg(long)]
    no_nvd: bool,
    /// NVD CVE API 2.0 endpoint. An optional API key is read from NVD_API_KEY.
    #[arg(long, default_value = crate::nvd::DEFAULT_URL)]
    nvd_url: String,
    /// Re-fetch cached NVD records older than this.
    #[arg(long, default_value_t = 7 * 86400)]
    nvd_refresh_seconds: u64,
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

/// Advisory sources enabled for an assessment.
#[derive(Clone, Copy)]
pub struct Sources {
    pub arch: bool,
    pub osv: bool,
}

fn summarize(findings: &[Value]) -> &'static str {
    if findings.iter().any(|f| f["status"] == "affected") {
        "affected"
    } else if !findings.is_empty() {
        "needs_review"
    } else {
        "no_known_match"
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
    /// Replaces the stored Arch advisories with a downloaded feed.
    pub fn import_arch(&mut self, bytes: &[u8], source: &str) -> Result<usize> {
        let advisories = parse_feed(bytes)?;
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM advisories WHERE source='arch'", [])?;
        for advisory in &advisories {
            tx.execute(
                "INSERT INTO advisories(id,source,data) VALUES (?1,'arch',?2)",
                params![advisory.name, serde_json::to_string(advisory)?],
            )?;
        }
        let now = model::now() as i64;
        tx.execute("INSERT INTO assessment_state(id,last_attempt,last_success,success,feed_sha256,feed_source) VALUES (1,?1,?1,1,?2,?3)
            ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,last_success=excluded.last_success,success=1,error=NULL,
            feed_sha256=excluded.feed_sha256,feed_source=excluded.feed_source",
            params![now,format!("{:x}",Sha256::digest(bytes)),source])?;
        tx.commit()?;
        Ok(advisories.len())
    }

    /// Stored Arch advisories, or `None` when no feed was ever imported.
    fn arch_advisories(&self) -> Result<Option<Vec<Advisory>>> {
        let imported: bool = self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM assessment_state WHERE feed_sha256 IS NOT NULL)",
            [],
            |r| r.get(0),
        )?;
        if !imported {
            return Ok(None);
        }
        let mut stmt = self
            .0
            .prepare("SELECT data FROM advisories WHERE source='arch'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut advisories = Vec::new();
        for row in rows {
            advisories.push(serde_json::from_str(&row?)?);
        }
        Ok(Some(advisories))
    }

    /// Records that the Arch tracker is disabled, so its state does not read as a failure.
    fn arch_disabled(&self) -> Result<()> {
        self.0.execute("INSERT INTO assessment_state(id,last_attempt,last_success,success,feed_source) VALUES (1,?1,?1,1,'disabled')
            ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,last_success=excluded.last_success,success=1,error=NULL,
            feed_source='disabled'", [model::now() as i64])?;
        Ok(())
    }

    /// Re-assesses every installation from the stored Arch advisories and the OSV cache.
    pub fn assess(&mut self, sources: Sources) -> Result<()> {
        let arch = if sources.arch {
            self.arch_advisories()?
        } else {
            self.arch_disabled()?;
            None
        };
        let mut by_package: HashMap<&str, Vec<&Advisory>> = HashMap::new();
        for advisory in arch.iter().flatten() {
            for package in &advisory.packages {
                by_package.entry(package).or_default().push(advisory);
            }
        }
        let osv = if sources.osv {
            Some(self.osv_cache()?)
        } else {
            // Like a disabled Arch tracker, a disabled OSV source is not a failure.
            self.osv_result(None)?;
            None
        };
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = model::now() as i64;
        tx.execute("DELETE FROM assessments", [])?;
        {
            let mut stmt = tx.prepare("SELECT i.host_id,i.collector_id,i.installation_id,i.version,i.name,i.source,h.os,h.last_sequence,c.success,c.active,
                h.os_version,i.source_package,i.source_version,i.evidence
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
                let os_version: String = row.get(10)?;
                let source_package: Option<String> = row.get(11)?;
                let source_version: Option<String> = row.get(12)?;
                let evidence: String = row.get(13)?;
                let mut findings = Vec::new();
                let package = crate::osv::Package {
                    os: &os,
                    os_version: &os_version,
                    kind: &ecosystem,
                    name: &name,
                    version: version.as_deref().unwrap_or(""),
                    source_package: source_package.as_deref(),
                    source_version: source_version.as_deref(),
                    evidence: &evidence,
                };
                let is_arch = os == "arch" && ecosystem == "pacman";
                let osv_queries = crate::osv::queries(&package);
                let status = if !successful || !active {
                    "stale_inventory"
                } else if version.is_none() {
                    if is_arch || osv_queries.is_some() {
                        "not_assessed"
                    } else {
                        "unsupported"
                    }
                } else if is_arch && sources.arch {
                    if arch.is_none() {
                        "not_assessed"
                    } else {
                        let version = version.as_deref().unwrap_or("");
                        for advisory in by_package.get(name.as_str()).into_iter().flatten() {
                            if let Some(status) = classify(version, advisory) {
                                findings.push(json!({"source":"arch","advisory_id":advisory.name,
                                    "advisory_url":format!("https://security.archlinux.org/{}",advisory.name),
                                    "cves":advisory.issues,"severity":advisory.severity,"status":status,
                                    "fixed_version":advisory.fixed,"tracker_status":advisory.status}));
                            }
                        }
                        summarize(&findings)
                    }
                } else if let (Some(queries), Some(cache)) = (&osv_queries, &osv) {
                    let mut complete = true;
                    for query in queries {
                        match cache.queries.get(query) {
                            Some(ids) => findings.extend(ids.iter().filter_map(|id| {
                                crate::osv::finding(query, id, cache.vulns.get(id))
                            })),
                            None => complete = false,
                        }
                    }
                    if complete {
                        findings = crate::osv::dedupe(findings);
                        summarize(&findings)
                    } else {
                        // Never report "no_known_match" for a package OSV was not asked about.
                        findings.clear();
                        "not_assessed"
                    }
                } else {
                    "unsupported"
                };
                tx.execute("INSERT INTO assessments(host_id,collector_id,installation_id,version,name,sequence,assessed_at,status,findings)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![host,collector,identity,version.unwrap_or_default(),name,sequence,now,status,serde_json::to_string(&findings)?])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn assessment_failed(&self, error: &str) -> Result<()> {
        self.0.execute("INSERT INTO assessment_state(id,last_attempt,success,error) VALUES(1,?1,0,?2)
            ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,success=0,error=excluded.error",
            params![model::now() as i64,error])?;
        Ok(())
    }
    /// Arch tracker import state, with the OSV query state under `osv`.
    pub fn assessment_status(&self) -> Result<Value> {
        let mut status = self.0.query_row("SELECT last_attempt,last_success,success,error,feed_sha256,feed_source FROM assessment_state WHERE id=1",[],|r| Ok(json!({
            "last_attempt":r.get::<_,i64>(0)?,"last_success":r.get::<_,Option<i64>>(1)?,"success":r.get::<_,bool>(2)?,
            "error":r.get::<_,Option<String>>(3)?,"feed_sha256":r.get::<_,Option<String>>(4)?,"feed_source":r.get::<_,Option<String>>(5)?
        }))).optional()?.unwrap_or(json!({"success":false,"last_success":null,"error":"not assessed"}));
        status["osv"] = self.0.query_row("SELECT last_attempt,last_success,success,error FROM osv_state WHERE id=1",[],|r| Ok(json!({
            "last_attempt":r.get::<_,i64>(0)?,"last_success":r.get::<_,Option<i64>>(1)?,"success":r.get::<_,bool>(2)?,
            "error":r.get::<_,Option<String>>(3)?
        }))).optional()?.unwrap_or(Value::Null);
        Ok(status)
    }
    pub fn findings(
        &self,
        host: Option<&str>,
        statuses: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Value>> {
        let mut stmt = self.0.prepare(&format!("SELECT i.host_id,i.collector_id,i.installation_id,i.name,i.version,a.status,a.findings,a.assessed_at,
            a.sequence,h.last_sequence,c.success,c.active,h.last_seen,
            {EFFECTIVE_STATUS} AS effective
            FROM installations i JOIN hosts h ON h.id=i.host_id JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id
            LEFT JOIN assessments a ON a.host_id=i.host_id AND a.collector_id=i.collector_id AND a.installation_id=i.installation_id AND a.version=COALESCE(i.version,'')
            WHERE (?1 IS NULL OR i.host_id=?1) AND (?4 IS NULL OR instr(','||?4||',', ','||effective||',')>0)
            ORDER BY i.host_id,i.collector_id,i.installation_id,i.version LIMIT ?2 OFFSET ?3"))?;
        let scores = self.cvss_scores()?;
        let rows = stmt.query_map(params![host,limit,offset,statuses], |r| {
            // Effective status is computed in SQL so filtering and pagination agree.
            let status: String = r.get(13)?;
            let findings: Option<String> = r.get(6)?;
            Ok(json!({"host_id":r.get::<_,String>(0)?,"collector_id":r.get::<_,String>(1)?,
                "installation_id":r.get::<_,String>(2)?,"name":r.get::<_,String>(3)?,"version":r.get::<_,Option<String>>(4)?,
                "status":status,"findings":with_cvss(findings.and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or(json!([])), &scores),
                "assessed_at":r.get::<_,Option<i64>>(7)?,"host_last_seen":r.get::<_,i64>(12)?}))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

/// Adds the highest cached NVD CVSS score of each finding's CVEs as `cvss` (or null).
fn with_cvss(mut findings: Value, scores: &HashMap<String, crate::nvd::Cvss>) -> Value {
    if let Some(items) = findings.as_array_mut() {
        for finding in items {
            let cvss = crate::nvd::to_json(crate::nvd::best(&finding["cves"], scores));
            finding["cvss"] = cvss;
        }
    }
    findings
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
/// How often the worker checks for inventory that arrived since the last assessment.
const NEW_INVENTORY_CHECK: Duration = Duration::from_secs(60);

impl Database {
    /// True when some current installation has no assessment for its host's latest sequence.
    fn has_unassessed_inventory(&self) -> Result<bool> {
        Ok(self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM installations i JOIN hosts h ON h.id=i.host_id
             LEFT JOIN assessments a ON a.host_id=i.host_id AND a.collector_id=i.collector_id
                AND a.installation_id=i.installation_id AND a.version=COALESCE(i.version,'')
             WHERE a.sequence IS NULL OR a.sequence<>h.last_sequence)",
            [],
            |r| r.get(0),
        )?)
    }
}

/// Wait before retrying OSV after a failed pass.
const OSV_RETRY: Duration = Duration::from_secs(600);

pub async fn run(options: Options) -> Result<()> {
    if options.interval_seconds == 0 || options.osv_refresh_seconds == 0 {
        bail!("intervals must be positive");
    }
    if options.no_arch && options.no_osv {
        bail!("--no-arch and --no-osv together leave nothing to assess");
    }
    let sources = Sources {
        arch: !options.no_arch,
        osv: !options.no_osv,
    };
    let nvd = (!options.no_nvd).then(|| crate::nvd::Options {
        url: options.nvd_url.clone(),
        api_key: std::env::var("NVD_API_KEY")
            .ok()
            .filter(|k| !k.trim().is_empty()),
        refresh_seconds: options.nvd_refresh_seconds,
    });
    let mut nvd_once = None;
    if let Some(nvd) = nvd {
        if options.once {
            nvd_once = Some(nvd);
        } else {
            // Independent, rate-limited loop; reads findings the assessment writes.
            tokio::spawn(crate::nvd::run(options.database.clone(), nvd));
        }
    }
    let osv = crate::osv::Options {
        url: options.osv_url.clone(),
        refresh_seconds: options.osv_refresh_seconds,
    };
    let source = options
        .feed_file
        .as_ref()
        .map(|p| format!("file:{}", p.display()))
        .unwrap_or(FEED_URL.into());
    let mut next_download = tokio::time::Instant::now();
    let mut next_osv = tokio::time::Instant::now();
    loop {
        let mut changed = false;
        let mut errors = Vec::new();
        if sources.arch && tokio::time::Instant::now() >= next_download {
            next_download =
                tokio::time::Instant::now() + Duration::from_secs(options.interval_seconds);
            let downloaded = feed(&options.feed_file).await;
            let path = options.database.clone();
            let source = source.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<usize> {
                let mut db = Database::open(&path)?;
                let result = downloaded.and_then(|bytes| db.import_arch(&bytes, &source));
                if let Err(error) = &result {
                    db.assessment_failed(&format!("{error:#}"))?;
                }
                result
            })
            .await?;
            match result {
                Ok(n) => {
                    changed = true;
                    eprintln!("Arch tracker feed imported ({n} advisories)");
                }
                // Previously imported advisories stay in use; the failure stays visible
                // in the assessment status until the next successful download.
                Err(e) => errors.push(format!("Arch tracker: {e:#}")),
            }
        }
        if sources.osv && tokio::time::Instant::now() >= next_osv {
            match crate::osv::pass(&options.database, &osv).await {
                Ok(0) => {}
                Ok(n) => {
                    changed = true;
                    eprintln!("OSV refreshed {n} package queries");
                }
                Err(e) => {
                    next_osv = tokio::time::Instant::now() + OSV_RETRY;
                    errors.push(format!("OSV: {e:#}"));
                }
            }
        }
        let path = options.database.clone();
        let force = changed || options.once;
        let assessed = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut db = Database::open(&path)?;
            if !force && !db.has_unassessed_inventory()? {
                return Ok(false);
            }
            db.assess(sources)?;
            Ok(true)
        })
        .await?;
        match assessed {
            Ok(true) => eprintln!("Assessment completed"),
            Ok(false) => {}
            Err(e) => errors.push(format!("assessment: {e:#}")),
        }
        for error in &errors {
            eprintln!("Assessment source failed: {error}");
        }
        if options.once {
            if let Some(nvd) = &nvd_once {
                let n = crate::nvd::pass(&options.database, nvd).await?;
                eprintln!("NVD enrichment updated {n} CVEs");
            }
            if !errors.is_empty() {
                bail!("{}", errors.join("; "));
            }
            return Ok(());
        }
        let mut wake = NEW_INVENTORY_CHECK;
        if sources.arch {
            wake = wake.min(next_download.saturating_duration_since(tokio::time::Instant::now()));
        }
        tokio::time::sleep(wake).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Collector, Kind},
        model::{Inventory, Software},
        protocol::{Host, Submission},
    };

    fn host(db: &mut Database, id: &str, os: &str, kind: Kind, items: Vec<(&str, Option<&str>)>) {
        let c = Collector {
            id: "os".into(),
            kind,
            path: "/usr/bin/true".into(),
            max_depth: 1,
        };
        let mut inventory = Inventory {
            schema_version: 1,
            initial_scan_complete: true,
            ..Inventory::default()
        };
        let software = items
            .into_iter()
            .map(|(name, source)| {
                let item = Software::new(&c, name, "1.0-1", "", None, "package database", "");
                match source {
                    Some(source) => item.with_source(source, ""),
                    None => item,
                }
            })
            .collect();
        inventory.apply(&c, Ok(software), 100, 0.1);
        db.ingest(&Submission {
            protocol_version: 1,
            host: Host {
                id: id.into(),
                hostname: id.into(),
                os: os.into(),
                os_version: "12".into(),
                architecture: "x86_64".into(),
            },
            sequence: 1,
            inventory,
        })
        .unwrap();
    }

    #[test]
    fn statuses_without_advisory_data() {
        let mut db = Database::open(std::path::Path::new(":memory:")).unwrap();
        host(
            &mut db,
            "deb",
            "debian",
            Kind::Dpkg,
            vec![("libfoo1", Some("foo")), ("old", None)],
        );
        host(&mut db, "arch", "arch", Kind::Pacman, vec![("demo", None)]);
        host(&mut db, "fedora", "fedora", Kind::Rpm, vec![("demo", None)]);
        let status = |db: &Database| -> Vec<(String, String)> {
            db.findings(None, None, 100, 0)
                .unwrap()
                .iter()
                .map(|f| {
                    (
                        f["name"].as_str().unwrap().into(),
                        f["status"].as_str().unwrap().into(),
                    )
                })
                .collect()
        };
        db.assess(Sources {
            arch: true,
            osv: true,
        })
        .unwrap();
        // No feed imported and no OSV result cached: nothing is reported as clean.
        let s = status(&db);
        assert!(s.contains(&("demo".into(), "not_assessed".into())), "{s:?}");
        assert!(
            s.contains(&("libfoo1".into(), "not_assessed".into())),
            "{s:?}"
        );
        // A dpkg record without a source package (old agent) and Fedora are not covered.
        assert!(s.contains(&("old".into(), "unsupported".into())), "{s:?}");
        assert_eq!(
            s.iter().filter(|x| x.1 == "unsupported").count(),
            2,
            "{s:?}"
        );
        db.0.execute(
            "INSERT INTO osv_queries VALUES ('Debian:12','foo','1.0-1',1,'[]')",
            [],
        )
        .unwrap();
        db.assess(Sources {
            arch: false,
            osv: true,
        })
        .unwrap();
        let s = status(&db);
        assert!(
            s.contains(&("libfoo1".into(), "no_known_match".into())),
            "{s:?}"
        );
        assert_eq!(
            s.iter().filter(|x| x.1 == "unsupported").count(),
            3,
            "{s:?}"
        );
        assert!(
            db.assessment_status().unwrap()["success"]
                .as_bool()
                .unwrap()
        );
    }
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
