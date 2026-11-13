//! CVSS enrichment from the NIST NVD CVE API 2.0. Only CVEs referenced by current
//! findings are looked up; results are cached in the database and refreshed periodically.
use crate::{database::Database, model};
use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

pub const DEFAULT_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
/// NVD asks clients without an API key to wait about 6 seconds between requests
/// (5 requests per rolling 30 seconds); with a key the limit is 50 per 30 seconds.
const DELAY_WITHOUT_KEY: Duration = Duration::from_secs(6);
const DELAY_WITH_KEY: Duration = Duration::from_millis(700);
const PASS_INTERVAL: Duration = Duration::from_secs(600);
const MAX_PER_PASS: i64 = 500;
/// CVSS versions in order of preference: v3.x is the most widely populated and comparable.
const METRICS: [&str; 4] = [
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV40",
    "cvssMetricV2",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Cvss {
    pub score: f64,
    pub severity: String,
    pub version: String,
    pub vector: String,
    pub source: String,
    /// NVD's own (Primary) score rather than a CNA-supplied (Secondary) one.
    pub primary: bool,
}

#[derive(Debug, PartialEq)]
pub struct Details {
    pub vuln_status: String,
    pub published: String,
    pub last_modified: String,
    pub description: String,
    pub cvss: Option<Cvss>,
}

pub struct Options {
    pub url: String,
    pub api_key: Option<String>,
    pub refresh_seconds: u64,
}

pub fn valid_cve(id: &str) -> bool {
    let mut parts = id.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| (4..=19).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

/// Selects the preferred CVSS metric from an NVD `cve` object.
fn select_cvss(cve: &Value) -> Option<Cvss> {
    for key in METRICS {
        let Some(entries) = cve["metrics"][key].as_array() else {
            continue;
        };
        let mut best: Option<Cvss> = None;
        for entry in entries {
            let data = &entry["cvssData"];
            let Some(score) = data["baseScore"]
                .as_f64()
                .filter(|s| (0.0..=10.0).contains(s))
            else {
                continue;
            };
            let candidate = Cvss {
                score,
                // v2 keeps the severity beside cvssData rather than inside it.
                severity: data["baseSeverity"]
                    .as_str()
                    .or(entry["baseSeverity"].as_str())
                    .unwrap_or("")
                    .to_string(),
                version: data["version"].as_str().unwrap_or("").to_string(),
                vector: data["vectorString"].as_str().unwrap_or("").to_string(),
                source: entry["source"].as_str().unwrap_or("").to_string(),
                primary: entry["type"].as_str() == Some("Primary"),
            };
            // Within a version prefer NVD's Primary score, then the highest score.
            let better = best
                .as_ref()
                .is_none_or(|b| (candidate.primary, candidate.score) > (b.primary, b.score));
            if better {
                best = Some(candidate);
            }
        }
        if best.is_some() {
            return best;
        }
    }
    None
}

/// Parses an NVD 2.0 response for one CVE ID. `Ok(None)` means NVD has no such record.
pub fn parse_response(bytes: &[u8], id: &str) -> Result<Option<Details>> {
    let body: Value = serde_json::from_slice(bytes).context("invalid NVD response")?;
    let Some(items) = body["vulnerabilities"].as_array() else {
        bail!("NVD response has no vulnerabilities array");
    };
    let Some(cve) = items.iter().map(|v| &v["cve"]).find(|c| c["id"] == id) else {
        if body["totalResults"].as_u64() == Some(0) {
            return Ok(None);
        }
        bail!("NVD response does not contain {id}");
    };
    let text = |key: &str| cve[key].as_str().unwrap_or("").to_string();
    let description = cve["descriptions"]
        .as_array()
        .and_then(|d| d.iter().find(|x| x["lang"] == "en"))
        .and_then(|x| x["value"].as_str())
        .unwrap_or("")
        .chars()
        .take(2000)
        .collect();
    Ok(Some(Details {
        vuln_status: text("vulnStatus"),
        published: text("published"),
        last_modified: text("lastModified"),
        description,
        cvss: select_cvss(cve),
    }))
}

impl Database {
    /// CVEs referenced by current affected/needs_review findings that are missing from the
    /// cache or older than `stale_before`; never-fetched IDs first.
    pub fn cves_to_fetch(&self, stale_before: i64, limit: i64) -> Result<Vec<String>> {
        let mut stmt = self.0.prepare(
            "SELECT r.id FROM (SELECT DISTINCT c.value AS id FROM assessments a,
                json_each(a.findings) f, json_each(json_extract(f.value,'$.cves')) c
                WHERE a.status IN ('affected','needs_review')) r
             LEFT JOIN nvd_cves n ON n.id=r.id
             WHERE n.id IS NULL OR n.fetched_at < ?1
             ORDER BY n.fetched_at IS NOT NULL, n.fetched_at, r.id LIMIT ?2",
        )?;
        let ids = stmt
            .query_map(params![stale_before, limit], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids.into_iter().filter(|id| valid_cve(id)).collect())
    }

    pub fn store_cve(&self, id: &str, details: Option<&Details>) -> Result<()> {
        let c = details.and_then(|d| d.cvss.as_ref());
        self.0.execute(
            "INSERT INTO nvd_cves(id,fetched_at,found,vuln_status,published,last_modified,description,
                cvss_score,cvss_severity,cvss_version,cvss_vector,cvss_source,cvss_primary)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(id) DO UPDATE SET fetched_at=excluded.fetched_at,found=excluded.found,
                vuln_status=excluded.vuln_status,published=excluded.published,
                last_modified=excluded.last_modified,description=excluded.description,
                cvss_score=excluded.cvss_score,cvss_severity=excluded.cvss_severity,
                cvss_version=excluded.cvss_version,cvss_vector=excluded.cvss_vector,
                cvss_source=excluded.cvss_source,cvss_primary=excluded.cvss_primary",
            params![
                id,
                model::now() as i64,
                details.is_some(),
                details.map(|d| &d.vuln_status),
                details.map(|d| &d.published),
                details.map(|d| &d.last_modified),
                details.map(|d| &d.description),
                c.map(|c| c.score),
                c.map(|c| &c.severity),
                c.map(|c| &c.version),
                c.map(|c| &c.vector),
                c.map(|c| &c.source),
                c.map(|c| c.primary),
            ],
        )?;
        Ok(())
    }

    pub fn nvd_result(&self, error: Option<&str>) -> Result<()> {
        let now = model::now() as i64;
        self.0.execute(
            "INSERT INTO nvd_state(id,last_attempt,last_success,success,error)
             VALUES (1,?1,CASE WHEN ?2 IS NULL THEN ?1 END,?2 IS NULL,?2)
             ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,
                last_success=COALESCE(excluded.last_success,nvd_state.last_success),
                success=excluded.success,error=excluded.error",
            params![now, error],
        )?;
        Ok(())
    }

    /// (success, last_success) of the latest enrichment pass, if any.
    pub fn nvd_state(&self) -> Result<Option<(bool, Option<i64>)>> {
        Ok(self
            .0
            .query_row(
                "SELECT success,last_success FROM nvd_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// All cached CVSS scores, keyed by CVE ID.
    pub fn cvss_scores(&self) -> Result<HashMap<String, Cvss>> {
        let mut stmt = self.0.prepare(
            "SELECT id,cvss_score,cvss_severity,cvss_version,cvss_vector,cvss_source,cvss_primary
             FROM nvd_cves WHERE cvss_score IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                Cvss {
                    score: r.get(1)?,
                    severity: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    version: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    vector: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    source: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    primary: r.get::<_, Option<bool>>(6)?.unwrap_or(false),
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

/// Highest cached CVSS score among a finding's CVEs, with the CVE it came from.
pub fn best<'a>(cves: &'a Value, scores: &'a HashMap<String, Cvss>) -> Option<(&'a str, &'a Cvss)> {
    cves.as_array()?
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|id| scores.get(id).map(|c| (id, c)))
        .max_by(|a, b| a.1.score.total_cmp(&b.1.score))
}

pub fn to_json(best: Option<(&str, &Cvss)>) -> Value {
    best.map_or(Value::Null, |(id, c)| {
        json!({"cve":id,"score":c.score,"severity":c.severity,"version":c.version,
               "vector":c.vector,"source":c.source,"primary":c.primary})
    })
}

enum Fetch {
    Done(Option<Details>),
    /// Network error or 5xx: worth retrying the same CVE after a short wait.
    Transient(String),
    /// Rate limited (403/429) or unexpected response: stop this pass and retry later.
    Stop(String),
}

/// Waits before retrying a transient failure for the same CVE.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(6), Duration::from_secs(12)];

async fn fetch(client: &reqwest::Client, options: &Options, id: &str) -> Result<Fetch> {
    let mut request = client.get(&options.url).query(&[("cveId", id)]);
    if let Some(key) = &options.api_key {
        request = request.header("apiKey", key);
    }
    // reqwest's Display omits the cause (DNS, TLS, reset, timeout); include the chain.
    let detail = |e: reqwest::Error| format!("{:#}", anyhow::Error::from(e));
    let mut response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(Fetch::Transient(format!(
                "request for {id} failed: {}",
                detail(e)
            )));
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Fetch::Done(None));
    }
    if status.is_server_error() {
        return Ok(Fetch::Transient(format!("NVD returned {status} for {id}")));
    }
    if !status.is_success() {
        return Ok(Fetch::Stop(format!("NVD returned {status} for {id}")));
    }
    let mut bytes = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => {
                return Ok(Fetch::Transient(format!(
                    "reading {id} failed: {}",
                    detail(e)
                )));
            }
        };
        if bytes.len() + chunk.len() > MAX_RESPONSE {
            bail!("NVD response for {id} exceeds 4 MiB");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Fetch::Done(parse_response(&bytes, id)?))
}

/// One enrichment pass. Returns the number of CVEs looked up.
pub async fn pass(database: &Path, options: &Options) -> Result<usize> {
    let path = database.to_path_buf();
    let stale_before = (model::now() as i64).saturating_sub(options.refresh_seconds as i64);
    let ids = tokio::task::spawn_blocking(move || {
        Database::open(&path)?.cves_to_fetch(stale_before, MAX_PER_PASS)
    })
    .await??;
    let client = reqwest::Client::builder()
        // NVD responses occasionally take tens of seconds.
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            "software-inventory-exporter/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let delay = if options.api_key.is_some() {
        DELAY_WITH_KEY
    } else {
        DELAY_WITHOUT_KEY
    };
    let mut error = None;
    let mut done = 0;
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(delay).await;
        }
        let mut outcome = Fetch::Stop("not attempted".into());
        for attempt in 0..=RETRY_DELAYS.len() {
            if attempt > 0 {
                tokio::time::sleep(RETRY_DELAYS[attempt - 1]).await;
            }
            outcome = match fetch(&client, options, id).await {
                Ok(outcome) => outcome,
                Err(e) => Fetch::Stop(format!("{e:#}")),
            };
            match &outcome {
                Fetch::Transient(message) => eprintln!("NVD attempt {}: {message}", attempt + 1),
                _ => break,
            }
        }
        let path = database.to_path_buf();
        let id = id.clone();
        match outcome {
            Fetch::Done(details) => {
                tokio::task::spawn_blocking(move || {
                    Database::open(&path)?.store_cve(&id, details.as_ref())
                })
                .await??;
                done += 1;
            }
            Fetch::Stop(message) | Fetch::Transient(message) => {
                error = Some(message);
                break;
            }
        }
    }
    let path = database.to_path_buf();
    let recorded = error.clone();
    tokio::task::spawn_blocking(move || Database::open(&path)?.nvd_result(recorded.as_deref()))
        .await??;
    match error {
        Some(e) => bail!("NVD enrichment stopped after {done} lookups: {e}"),
        None => Ok(done),
    }
}

pub async fn run(database: PathBuf, options: Options) {
    loop {
        match pass(&database, &options).await {
            Ok(0) => {}
            Ok(n) => eprintln!("NVD enrichment updated {n} CVEs"),
            Err(e) => eprintln!("{e:#}"),
        }
        tokio::time::sleep(PASS_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_cve_ids() {
        assert!(valid_cve("CVE-2025-6020"));
        assert!(valid_cve("CVE-2021-1234567"));
        for bad in [
            "CVE-25-6020",
            "CVE-2025-60",
            "cve-2025-6020",
            "CVE-2025-6020-1",
            "AVG-1",
        ] {
            assert!(!valid_cve(bad), "{bad}");
        }
    }

    #[test]
    fn selects_preferred_cvss_and_handles_missing_records() {
        // Shape taken from a live NVD 2.0 response (CVE-2025-6020), plus synthetic metrics.
        let body = json!({"totalResults":1,"vulnerabilities":[{"cve":{
            "id":"CVE-2025-6020","vulnStatus":"Deferred","published":"2025-06-17T13:15:21.660",
            "lastModified":"2026-11-06T01:17:47.313",
            "descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"A flaw in linux-pam."}],
            "metrics":{
                "cvssMetricV40":[{"source":"cna","type":"Secondary","cvssData":{"version":"4.0","baseScore":9.3,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/x"}}],
                "cvssMetricV31":[
                    {"source":"secalert@redhat.com","type":"Secondary","cvssData":{"version":"3.1","baseScore":7.8,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:L"}},
                    {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":5.5,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N"}}],
                "ssvcV203":[{"source":"cisa","ssvcData":{}}]}}}]});
        let details = parse_response(body.to_string().as_bytes(), "CVE-2025-6020")
            .unwrap()
            .unwrap();
        assert_eq!(details.description, "A flaw in linux-pam.");
        assert_eq!(details.vuln_status, "Deferred");
        let cvss = details.cvss.unwrap();
        // v3.1 preferred over v4.0; NVD Primary preferred over a higher CNA score.
        assert_eq!(
            (cvss.score, cvss.version.as_str(), cvss.primary),
            (5.5, "3.1", true)
        );

        let v2 = json!({"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2010-0001",
            "metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","baseSeverity":"HIGH",
                "cvssData":{"version":"2.0","baseScore":7.5,"vectorString":"AV:N"}}]}}}]});
        let cvss = parse_response(v2.to_string().as_bytes(), "CVE-2010-0001")
            .unwrap()
            .unwrap()
            .cvss
            .unwrap();
        assert_eq!((cvss.score, cvss.severity.as_str()), (7.5, "HIGH"));

        let none = json!({"totalResults":0,"vulnerabilities":[]});
        assert!(
            parse_response(none.to_string().as_bytes(), "CVE-2099-0001")
                .unwrap()
                .is_none()
        );
        let unscored = json!({"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","vulnStatus":"Received"}}]});
        let details = parse_response(unscored.to_string().as_bytes(), "CVE-2026-0001")
            .unwrap()
            .unwrap();
        assert!(details.cvss.is_none());
        assert!(parse_response(b"{}", "CVE-2026-0001").is_err());
    }
}
