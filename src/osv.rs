//! Vulnerability matching through the OSV.dev API for Debian, Ubuntu, RPM distributions
//! (AlmaLinux, Rocky Linux, RHEL, openSUSE), PyPI, npm and crates.io.
//!
//! OSV evaluates the version ranges itself (dpkg, RPM, PEP 440 and SemVer ordering), so a
//! returned advisory means the installed version is inside an affected range. Only
//! (ecosystem, package name, version) triples are sent; host IDs and hostnames never are.
//! Query results and advisory details are cached in the database.
use crate::{database::Database, model};
use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

pub const DEFAULT_URL: &str = "https://api.osv.dev";
/// The querybatch endpoint accepts at most 1000 queries per request.
const BATCH: usize = 1000;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const MAX_VULN: usize = 4 * 1024 * 1024;
const CONCURRENCY: usize = 16;
const MAX_PAGES: usize = 50;

pub struct Options {
    pub url: String,
    /// Re-query cached (ecosystem, name, version) results older than this.
    pub refresh_seconds: u64,
}

/// One OSV package query.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Query {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// The inventory facts that decide whether and how a package is looked up in OSV.
pub struct Package<'a> {
    pub os: &'a str,
    pub os_version: &'a str,
    /// Collector kind, e.g. `dpkg` or `python`.
    pub kind: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub source_package: Option<&'a str>,
    pub source_version: Option<&'a str>,
    pub evidence: &'a str,
}

fn numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Major release from an os-release VERSION_ID such as `12` or `9.4`.
fn major(version: &str) -> Option<&str> {
    version.split('.').next().filter(|m| numeric(m))
}

/// OSV ecosystem of an Ubuntu release: `22.04` is `Ubuntu:22.04:LTS`, `24.10` is `Ubuntu:24.10`.
fn ubuntu(version: &str) -> Option<String> {
    let (year, month) = version.split_once('.')?;
    if !numeric(year) || !numeric(month) || year.len() != 2 || month.len() != 2 {
        return None;
    }
    let lts = month == "04" && year.parse::<u8>().is_ok_and(|y| y % 2 == 0);
    Some(format!("Ubuntu:{version}{}", if lts { ":LTS" } else { "" }))
}

/// Cargo installs from git, a path or another registry are not crates.io packages.
/// Agents before 0.2 did not record the origin; those installs are assumed to be crates.io.
fn crates_io(evidence: &str) -> bool {
    !evidence.contains('+')
        || evidence.contains("github.com/rust-lang/crates.io-index")
        || evidence.contains("index.crates.io")
}

/// OSV queries for a package, or `None` when OSV has no matching ecosystem.
pub fn queries(p: &Package) -> Option<Vec<Query>> {
    let query = |ecosystem: String, name: &str, version: &str| Query {
        ecosystem,
        name: name.into(),
        version: version.into(),
    };
    let one = |ecosystem: &str| Some(vec![query(ecosystem.into(), p.name, p.version)]);
    match p.kind {
        "python" => one("PyPI"),
        "npm" => one("npm"),
        "cargo" if crates_io(p.evidence) => one("crates.io"),
        "dpkg" => {
            let ecosystem = match p.os {
                "debian" => format!("Debian:{}", major(p.os_version)?),
                "ubuntu" => ubuntu(p.os_version)?,
                _ => return None,
            };
            // Debian and Ubuntu advisories name source packages (openssl, not libssl3).
            let name = p.source_package?;
            Some(vec![query(
                ecosystem,
                name,
                p.source_version.unwrap_or(p.version),
            )])
        }
        "rpm" => {
            let m = major(p.os_version);
            let (ecosystems, by_source) = match p.os {
                "almalinux" => (vec![format!("AlmaLinux:{}", m?)], false),
                "rocky" => (vec![format!("Rocky Linux:{}", m?)], false),
                // Red Hat splits advisories by repository; BaseOS and AppStream cover the
                // packages of a standard installation.
                "rhel" => {
                    let m = m?;
                    (
                        ["baseos", "appstream"]
                            .map(|repo| format!("Red Hat:enterprise_linux:{m}::{repo}"))
                            .to_vec(),
                        false,
                    )
                }
                "opensuse-leap" if m.is_some() => {
                    (vec![format!("openSUSE:Leap {}", p.os_version)], true)
                }
                "opensuse-tumbleweed" => (vec!["openSUSE:Tumbleweed".into()], true),
                _ => return None,
            };
            // SUSE advisories name source packages; Red Hat family advisories name binaries.
            let name = if by_source { p.source_package? } else { p.name };
            // RPM treats a missing epoch as 0; OSV records omit a zero epoch.
            let version = p.version.strip_prefix("0:").unwrap_or(p.version);
            Some(
                ecosystems
                    .into_iter()
                    .map(|e| query(e, name, version))
                    .collect(),
            )
        }
        _ => None,
    }
}

/// The parts of an OSV record that findings need.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Vuln {
    pub id: String,
    pub summary: String,
    /// CVE IDs: the record's own ID, its aliases and its upstream records.
    pub cves: Vec<String>,
    /// Other IDs of the same vulnerability (e.g. PYSEC for a GHSA record).
    #[serde(default)]
    pub aliases: Vec<String>,
    pub severity: String,
    pub withdrawn: bool,
    pub affected: Vec<Affected>,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Affected {
    pub ecosystem: String,
    pub name: String,
    pub fixed: Vec<String>,
    pub severity: String,
}

fn severity_word(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("not yet assigned") {
        return String::new();
    }
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| {
            c.to_uppercase()
                .chain(chars.flat_map(char::to_lowercase))
                .collect()
        })
        .unwrap_or_default()
}

/// Parses a full OSV record into the cached summary.
pub fn parse_vuln(bytes: &[u8]) -> Result<Vuln> {
    let v: Value = serde_json::from_slice(bytes).context("invalid OSV record")?;
    let id = v["id"]
        .as_str()
        .context("OSV record has no id")?
        .to_string();
    let mut cves = Vec::new();
    let mut add = |s: &str| {
        if crate::nvd::valid_cve(s) && !cves.iter().any(|c| c == s) {
            cves.push(s.to_string());
        }
    };
    add(&id);
    let aliases: Vec<String> = v["aliases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str().filter(|a| !a.is_empty() && a.len() <= 128))
        .map(String::from)
        .collect();
    for key in ["aliases", "upstream"] {
        for s in v[key].as_array().into_iter().flatten() {
            add(s.as_str().unwrap_or(""));
        }
    }
    // GitHub advisories carry a qualitative severity; Ubuntu a priority.
    let severity = v["database_specific"]["severity"]
        .as_str()
        .or_else(|| {
            v["severity"]
                .as_array()?
                .iter()
                .find(|s| s["type"] == "Ubuntu")?["score"]
                .as_str()
        })
        .map(severity_word)
        .unwrap_or_default();
    let affected = v["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| Affected {
            ecosystem: a["package"]["ecosystem"].as_str().unwrap_or("").into(),
            name: a["package"]["name"].as_str().unwrap_or("").into(),
            fixed: a["ranges"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|r| r["events"].as_array().into_iter().flatten())
                .filter_map(|e| e["fixed"].as_str().map(String::from))
                .collect(),
            // Debian records an urgency per release.
            severity: severity_word(a["ecosystem_specific"]["urgency"].as_str().unwrap_or("")),
        })
        .collect();
    Ok(Vuln {
        id,
        summary: v["summary"]
            .as_str()
            .or(v["details"].as_str())
            .unwrap_or("")
            .chars()
            .take(300)
            .collect(),
        cves,
        aliases,
        severity,
        withdrawn: v["withdrawn"].as_str().is_some_and(|s| !s.is_empty()),
        affected,
    })
}

/// PyPI names compare case-insensitively with runs of `-`, `_` and `.` equivalent (PEP 503).
fn same_name(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem != "PyPI" {
        return a == b;
    }
    let norm = |s: &str| {
        s.to_ascii_lowercase()
            .split(['-', '_', '.'])
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    };
    norm(a) == norm(b)
}

/// Approximate version ordering used only to pick which fixed version to display;
/// OSV itself decides whether a version is affected.
fn natural_cmp(a: &str, b: &str) -> Ordering {
    fn tokens(s: &str) -> Vec<(bool, &str)> {
        let mut out = Vec::new();
        let mut start = 0;
        let bytes = s.as_bytes();
        for i in 1..=bytes.len() {
            if i == bytes.len() || bytes[i].is_ascii_digit() != bytes[start].is_ascii_digit() {
                out.push((bytes[start].is_ascii_digit(), &s[start..i]));
                start = i;
            }
        }
        out
    }
    let (ta, tb) = (tokens(a), tokens(b));
    for (x, y) in ta.iter().zip(&tb) {
        let order = match (x.0, y.0) {
            (true, true) => {
                let (x, y) = (x.1.trim_start_matches('0'), y.1.trim_start_matches('0'));
                x.len().cmp(&y.len()).then_with(|| x.cmp(y))
            }
            _ => x.1.cmp(y.1),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    // A trailing `~` part (Debian pre-release) sorts before the end of the version.
    let tilde = |rest: &[(bool, &str)]| rest.first().is_some_and(|t| t.1.starts_with('~'));
    match ta.len().cmp(&tb.len()) {
        Ordering::Greater if tilde(&ta[tb.len()..]) => Ordering::Less,
        Ordering::Less if tilde(&tb[ta.len()..]) => Ordering::Greater,
        order => order,
    }
}

/// The lowest fixed version above the installed one; with several release branches the
/// record lists a fix per branch.
fn choose_fixed(installed: &str, mut fixed: Vec<&str>) -> Option<String> {
    fixed.sort_by(|a, b| natural_cmp(a, b));
    fixed.dedup();
    match fixed.as_slice() {
        [] => None,
        [one] => Some(one.to_string()),
        many => Some(
            many.iter()
                .find(|f| natural_cmp(f, installed) == Ordering::Greater)
                .map(|f| f.to_string())
                .unwrap_or_else(|| many.join(", ")),
        ),
    }
}

/// A finding for `query` from an OSV record (or just its ID when details are missing).
pub fn finding(query: &Query, id: &str, vuln: Option<&Vuln>) -> Option<Value> {
    if vuln.is_some_and(|v| v.withdrawn) {
        return None;
    }
    let relevant: Vec<&Affected> = vuln
        .map(|v| {
            v.affected
                .iter()
                .filter(|a| {
                    a.ecosystem == query.ecosystem && same_name(&a.ecosystem, &a.name, &query.name)
                })
                .collect()
        })
        .unwrap_or_default();
    let fixed = choose_fixed(
        &query.version,
        relevant
            .iter()
            .flat_map(|a| a.fixed.iter().map(String::as_str))
            .collect(),
    );
    let severity = relevant
        .iter()
        .map(|a| a.severity.as_str())
        .find(|s| !s.is_empty())
        .or(vuln.map(|v| v.severity.as_str()))
        .unwrap_or("");
    Some(json!({
        "source": "osv",
        "advisory_id": id,
        "advisory_url": format!("https://osv.dev/vulnerability/{id}"),
        "ecosystem": query.ecosystem,
        "cves": vuln.map(|v| v.cves.clone()).unwrap_or_default(),
        "aliases": vuln.map(|v| v.aliases.clone()).unwrap_or_default(),
        "summary": vuln.map(|v| v.summary.as_str()).unwrap_or(""),
        "severity": severity,
        "status": "affected",
        "fixed_version": fixed,
        "tracker_status": "",
    }))
}

/// OSV often returns one vulnerability under several IDs (a GHSA and a PYSEC record for
/// the same CVE). Findings are duplicates when one names the other as an alias or both
/// cover exactly the same CVEs; distro notices bundling several CVEs (DSA, USN) stay
/// separate. Keeps a record with a severity first, then the lowest ID.
pub fn dedupe(mut findings: Vec<Value>) -> Vec<Value> {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    findings.sort_by_key(|f| {
        (
            f["severity"].as_str().is_none_or(str::is_empty),
            text(&f["advisory_id"]),
        )
    });
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for f in findings {
        let mut keys: Vec<String> = f["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .map(text)
            .collect();
        keys.push(text(&f["advisory_id"]));
        let mut cves: Vec<String> = f["cves"]
            .as_array()
            .into_iter()
            .flatten()
            .map(text)
            .collect();
        if !cves.is_empty() {
            cves.sort();
            keys.push(format!("cves:{}", cves.join(",")));
        }
        if keys.iter().any(|k| seen.contains(k)) {
            continue;
        }
        seen.extend(keys);
        kept.push(f);
    }
    kept
}

/// Cached OSV data used by an assessment pass.
pub struct Cache {
    pub queries: HashMap<Query, Vec<String>>,
    pub vulns: HashMap<String, Vuln>,
}

impl Database {
    /// OSV queries for every current installation of a successful, active collector.
    pub fn osv_targets(&self) -> Result<HashSet<Query>> {
        let mut stmt = self.0.prepare(
            "SELECT h.os,h.os_version,i.source,i.name,i.version,i.source_package,i.source_version,i.evidence
             FROM installations i JOIN hosts h ON h.id=i.host_id
             JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id
             WHERE c.success=1 AND c.active=1 AND i.version IS NOT NULL",
        )?;
        let mut rows = stmt.query([])?;
        let mut targets = HashSet::new();
        while let Some(r) = rows.next()? {
            let text = |i| r.get::<_, Option<String>>(i);
            let (os, os_version, kind, name) = (text(0)?, text(1)?, text(2)?, text(3)?);
            let (version, source_package, source_version, evidence) =
                (text(4)?, text(5)?, text(6)?, text(7)?);
            let package = Package {
                os: os.as_deref().unwrap_or(""),
                os_version: os_version.as_deref().unwrap_or(""),
                kind: kind.as_deref().unwrap_or(""),
                name: name.as_deref().unwrap_or(""),
                version: version.as_deref().unwrap_or(""),
                source_package: source_package.as_deref(),
                source_version: source_version.as_deref(),
                evidence: evidence.as_deref().unwrap_or(""),
            };
            targets.extend(queries(&package).into_iter().flatten());
        }
        Ok(targets)
    }

    /// Queries never fetched or fetched before `stale_before`. Cached results for
    /// packages no longer installed anywhere are deleted.
    fn osv_due(&self, stale_before: i64) -> Result<Vec<Query>> {
        let targets = self.osv_targets()?;
        let mut fetched: HashMap<Query, i64> = HashMap::new();
        {
            let mut stmt = self
                .0
                .prepare("SELECT ecosystem,name,version,fetched_at FROM osv_queries")?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let q = Query {
                    ecosystem: r.get(0)?,
                    name: r.get(1)?,
                    version: r.get(2)?,
                };
                fetched.insert(q, r.get(3)?);
            }
        }
        let stale: Vec<&Query> = fetched.keys().filter(|q| !targets.contains(*q)).collect();
        if !stale.is_empty() {
            let tx = self.0.unchecked_transaction()?;
            for q in stale {
                tx.execute(
                    "DELETE FROM osv_queries WHERE ecosystem=?1 AND name=?2 AND version=?3",
                    params![q.ecosystem, q.name, q.version],
                )?;
            }
            tx.execute(
                "DELETE FROM osv_vulns WHERE id NOT IN (SELECT DISTINCT v.value
                    FROM osv_queries q, json_each(q.vulns) v)",
                [],
            )?;
            tx.commit()?;
        }
        let mut due: Vec<Query> = targets
            .into_iter()
            .filter(|q| fetched.get(q).is_none_or(|t| *t < stale_before))
            .collect();
        due.sort();
        Ok(due)
    }

    /// IDs whose cached details are missing or older than OSV's `modified` timestamp.
    fn osv_vulns_due(&self, seen: &HashMap<String, String>) -> Result<Vec<String>> {
        let mut stmt = self
            .0
            .prepare("SELECT modified FROM osv_vulns WHERE id=?1")?;
        let mut due = Vec::new();
        for (id, modified) in seen {
            let cached: Option<String> = stmt.query_row([id], |r| r.get(0)).optional()?;
            if cached.as_ref() != Some(modified) {
                due.push(id.clone());
            }
        }
        due.sort();
        Ok(due)
    }

    fn store_osv_vulns(&self, vulns: &[(String, Vuln)]) -> Result<()> {
        let tx = self.0.unchecked_transaction()?;
        let now = model::now() as i64;
        for (modified, vuln) in vulns {
            tx.execute(
                "INSERT INTO osv_vulns(id,modified,fetched_at,data) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(id) DO UPDATE SET modified=excluded.modified,
                    fetched_at=excluded.fetched_at,data=excluded.data",
                params![vuln.id, modified, now, serde_json::to_string(vuln)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn store_osv_queries(&self, results: &[(Query, Vec<String>)]) -> Result<()> {
        let tx = self.0.unchecked_transaction()?;
        let now = model::now() as i64;
        for (q, ids) in results {
            tx.execute(
                "INSERT INTO osv_queries(ecosystem,name,version,fetched_at,vulns) VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(ecosystem,name,version) DO UPDATE SET fetched_at=excluded.fetched_at,vulns=excluded.vulns",
                params![q.ecosystem, q.name, q.version, now, serde_json::to_string(ids)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn osv_cache(&self) -> Result<Cache> {
        let mut queries = HashMap::new();
        let mut stmt = self
            .0
            .prepare("SELECT ecosystem,name,version,vulns FROM osv_queries")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let ids: Vec<String> = serde_json::from_str(&r.get::<_, String>(3)?)?;
            queries.insert(
                Query {
                    ecosystem: r.get(0)?,
                    name: r.get(1)?,
                    version: r.get(2)?,
                },
                ids,
            );
        }
        let mut vulns = HashMap::new();
        let mut stmt = self.0.prepare("SELECT id,data FROM osv_vulns")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            vulns.insert(r.get(0)?, serde_json::from_str(&r.get::<_, String>(1)?)?);
        }
        Ok(Cache { queries, vulns })
    }

    pub fn osv_result(&self, error: Option<&str>) -> Result<()> {
        self.0.execute(
            "INSERT INTO osv_state(id,last_attempt,last_success,success,error)
             VALUES (1,?1,CASE WHEN ?2 IS NULL THEN ?1 END,?2 IS NULL,?2)
             ON CONFLICT(id) DO UPDATE SET last_attempt=excluded.last_attempt,
                last_success=COALESCE(excluded.last_success,osv_state.last_success),
                success=excluded.success,error=excluded.error",
            params![model::now() as i64, error],
        )?;
        Ok(())
    }

    /// (success, last_success) of the latest OSV pass, if any.
    pub fn osv_state(&self) -> Result<Option<(bool, Option<i64>)>> {
        Ok(self
            .0
            .query_row(
                "SELECT success,last_success FROM osv_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            bail!("OSV response exceeds {} MiB", limit / (1024 * 1024));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Vulnerability (id, modified) lists for each query, following pagination.
async fn query_batch(
    client: &reqwest::Client,
    url: &str,
    queries: &[Query],
) -> Result<Vec<Vec<(String, String)>>> {
    let mut results = vec![Vec::new(); queries.len()];
    // (index into `queries`, page token) still to fetch.
    let mut pending: Vec<(usize, Option<String>)> = (0..queries.len()).map(|i| (i, None)).collect();
    for _ in 0..MAX_PAGES {
        if pending.is_empty() {
            return Ok(results);
        }
        let body: Vec<Value> = pending
            .iter()
            .map(|(i, token)| {
                let q = &queries[*i];
                let mut v =
                    json!({"package":{"ecosystem":q.ecosystem,"name":q.name},"version":q.version});
                if let Some(token) = token {
                    v["page_token"] = json!(token);
                }
                v
            })
            .collect();
        let response = client
            .post(format!("{url}/v1/querybatch"))
            .json(&json!({ "queries": body }))
            .send()
            .await
            .context("OSV querybatch request failed")?
            .error_for_status()
            .context("OSV querybatch failed")?;
        let value: Value = serde_json::from_slice(&read_limited(response, MAX_RESPONSE).await?)
            .context("invalid OSV querybatch response")?;
        let answers = value["results"]
            .as_array()
            .filter(|a| a.len() == pending.len())
            .context("OSV querybatch returned the wrong number of results")?;
        let mut next = Vec::new();
        for ((index, _), answer) in pending.iter().zip(answers) {
            for v in answer["vulns"].as_array().into_iter().flatten() {
                let id = v["id"].as_str().filter(|s| !s.is_empty() && s.len() <= 128);
                let id = id.context("OSV result without a valid id")?;
                results[*index].push((id.into(), v["modified"].as_str().unwrap_or("").into()));
            }
            if let Some(token) = answer["next_page_token"].as_str().filter(|t| !t.is_empty()) {
                next.push((*index, Some(token.to_string())));
            }
        }
        pending = next;
    }
    bail!("OSV pagination did not finish")
}

async fn fetch_vuln(client: reqwest::Client, url: String, id: String) -> Result<Option<Vuln>> {
    let mut endpoint = reqwest::Url::parse(&url)?;
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow::anyhow!("invalid OSV URL"))?
        .pop_if_empty()
        .extend(["v1", "vulns", &id]);
    let response = client
        .get(endpoint)
        .send()
        .await
        .with_context(|| format!("OSV request for {id} failed"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response
        .error_for_status()
        .with_context(|| format!("OSV lookup of {id} failed"))?;
    let vuln = parse_vuln(&read_limited(response, MAX_VULN).await?)?;
    if vuln.id != id {
        bail!("OSV returned {} for {id}", vuln.id);
    }
    Ok(Some(vuln))
}

/// Queries OSV for new and stale packages, fetches changed advisories and caches both.
/// Returns the number of package queries refreshed.
pub async fn pass(database: &Path, options: &Options) -> Result<usize> {
    let path = database.to_path_buf();
    let stale_before = (model::now() as i64).saturating_sub(options.refresh_seconds as i64);
    let (due, first) = tokio::task::spawn_blocking(move || -> Result<_> {
        let db = Database::open(&path)?;
        Ok((db.osv_due(stale_before)?, db.osv_state()?.is_none()))
    })
    .await??;
    // Passes without work are not recorded, except the first one, so that a fleet
    // without OSV-covered packages still reports a healthy state.
    if due.is_empty() && !first {
        return Ok(0);
    }
    let result = refresh(database, options, &due).await;
    let path = database.to_path_buf();
    let error = result.as_ref().err().map(|e| format!("{e:#}"));
    tokio::task::spawn_blocking(move || Database::open(&path)?.osv_result(error.as_deref()))
        .await??;
    result.map(|()| due.len())
}

async fn refresh(database: &Path, options: &Options, due: &[Query]) -> Result<()> {
    if due.is_empty() {
        return Ok(());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            "software-inventory-exporter/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let url = options.url.trim_end_matches('/').to_string();
    for chunk in due.chunks(BATCH) {
        let answers = query_batch(&client, &url, chunk).await?;
        let mut seen = HashMap::new();
        for (id, modified) in answers.iter().flatten() {
            seen.insert(id.clone(), modified.clone());
        }
        let path = database.to_path_buf();
        let wanted = tokio::task::spawn_blocking(move || -> Result<_> {
            let db = Database::open(&path)?;
            Ok((db.osv_vulns_due(&seen)?, seen))
        })
        .await??;
        let (wanted, seen) = wanted;
        for ids in wanted.chunks(CONCURRENCY * 8) {
            let mut tasks = tokio::task::JoinSet::new();
            let mut fetched = Vec::new();
            for id in ids {
                if tasks.len() >= CONCURRENCY {
                    fetched.push(tasks.join_next().await.context("task set empty")???);
                }
                let (client, url, id) = (client.clone(), url.clone(), id.clone());
                tasks.spawn(async move {
                    let vuln = fetch_vuln(client, url, id.clone()).await?;
                    Ok::<_, anyhow::Error>((id, vuln))
                });
            }
            while let Some(done) = tasks.join_next().await {
                fetched.push(done??);
            }
            let records: Vec<(String, Vuln)> = fetched
                .into_iter()
                .map(|(id, vuln)| {
                    // A record OSV no longer serves is cached as withdrawn.
                    let vuln = vuln.unwrap_or_else(|| Vuln {
                        id: id.clone(),
                        withdrawn: true,
                        ..Vuln::default()
                    });
                    (seen[&id].clone(), vuln)
                })
                .collect();
            let path = database.to_path_buf();
            tokio::task::spawn_blocking(move || Database::open(&path)?.store_osv_vulns(&records))
                .await??;
        }
        let results: Vec<(Query, Vec<String>)> = chunk
            .iter()
            .cloned()
            .zip(answers.into_iter().map(|a| {
                let mut ids: Vec<String> = a.into_iter().map(|(id, _)| id).collect();
                ids.sort();
                ids.dedup();
                ids
            }))
            .collect();
        let path = database.to_path_buf();
        tokio::task::spawn_blocking(move || Database::open(&path)?.store_osv_queries(&results))
            .await??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package<'a>(os: &'a str, os_version: &'a str, kind: &'a str) -> Package<'a> {
        Package {
            os,
            os_version,
            kind,
            name: "libssl3",
            version: "0:3.0.7-24.el9",
            source_package: Some("openssl"),
            source_version: None,
            evidence: "package database",
        }
    }

    #[test]
    fn maps_hosts_and_collectors_to_ecosystems() {
        let eco = |p: Package| {
            queries(&p).map(|q| {
                q.into_iter()
                    .map(|q| format!("{}|{}|{}", q.ecosystem, q.name, q.version))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            eco(package("debian", "12", "dpkg")).unwrap(),
            ["Debian:12|openssl|0:3.0.7-24.el9"]
        );
        let mut binnmu = package("debian", "12", "dpkg");
        binnmu.source_version = Some("3.0.11-1~deb12u2");
        assert_eq!(eco(binnmu).unwrap(), ["Debian:12|openssl|3.0.11-1~deb12u2"]);
        assert_eq!(
            eco(package("ubuntu", "22.04", "dpkg")).unwrap()[0],
            "Ubuntu:22.04:LTS|openssl|0:3.0.7-24.el9"
        );
        assert!(eco(package("ubuntu", "24.10", "dpkg")).unwrap()[0].starts_with("Ubuntu:24.10|"));
        assert_eq!(
            eco(package("almalinux", "9.4", "rpm")).unwrap(),
            ["AlmaLinux:9|libssl3|3.0.7-24.el9"]
        );
        assert_eq!(eco(package("rhel", "9.4", "rpm")).unwrap().len(), 2);
        assert_eq!(
            eco(package("opensuse-leap", "15.5", "rpm")).unwrap(),
            ["openSUSE:Leap 15.5|openssl|3.0.7-24.el9"]
        );
        assert_eq!(
            eco(package("arch", "rolling", "python")).unwrap()[0],
            "PyPI|libssl3|0:3.0.7-24.el9"
        );
        // Unknown distributions, Debian testing without VERSION_ID and dpkg records without
        // a source package (agents before 0.2) are not looked up.
        assert!(eco(package("fedora", "41", "rpm")).is_none());
        assert!(eco(package("debian", "rolling", "dpkg")).is_none());
        let mut old = package("debian", "12", "dpkg");
        old.source_package = None;
        assert!(eco(old).is_none());
        assert!(eco(package("arch", "rolling", "pacman")).is_none());
        let mut git = package("arch", "rolling", "cargo");
        git.evidence = "Cargo .crates.toml (git+https://example.com/x#abc); binary present";
        assert!(eco(git).is_none());
        let mut registry = package("arch", "rolling", "cargo");
        registry.evidence = "Cargo .crates.toml (registry+https://github.com/rust-lang/crates.io-index); binary present";
        assert!(eco(registry).is_some());
    }

    #[test]
    fn parses_records_and_builds_findings() {
        // Shapes taken from live OSV records (DEBIAN-CVE-2023-5363, GHSA-wcg3-cvx6-7396).
        let debian = json!({"id":"DEBIAN-CVE-2023-5363","upstream":["CVE-2023-5363"],
            "affected":[
                {"package":{"name":"openssl","ecosystem":"Debian:12"},"ecosystem_specific":{"urgency":"not yet assigned"},
                 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]},
                {"package":{"name":"openssl","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.12-1"}]}]}]});
        let vuln = parse_vuln(debian.to_string().as_bytes()).unwrap();
        assert_eq!(vuln.cves, ["CVE-2023-5363"]);
        let q = Query {
            ecosystem: "Debian:12".into(),
            name: "openssl".into(),
            version: "3.0.11-1~deb12u1".into(),
        };
        let f = finding(&q, &vuln.id, Some(&vuln)).unwrap();
        assert_eq!(f["fixed_version"], "3.0.11-1~deb12u2");
        assert_eq!(f["severity"], "");
        assert_eq!(f["status"], "affected");

        let ghsa = json!({"id":"GHSA-x","aliases":["CVE-2020-26235","RUSTSEC-2020-0071"],
            "database_specific":{"severity":"MODERATE"},"summary":"Segfault",
            "affected":[
                {"package":{"name":"Django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.2"},{"fixed":"3.2.25"}]}]},
                {"package":{"name":"django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.2"},{"fixed":"4.2.11"}]}]},
                {"package":{"name":"django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"5.0"},{"fixed":"5.0.3"}]}]}]});
        let vuln = parse_vuln(ghsa.to_string().as_bytes()).unwrap();
        assert_eq!(vuln.cves, ["CVE-2020-26235"]);
        let q = Query {
            ecosystem: "PyPI".into(),
            name: "django".into(),
            version: "4.2.0".into(),
        };
        let f = finding(&q, &vuln.id, Some(&vuln)).unwrap();
        assert_eq!(f["fixed_version"], "4.2.11");
        assert_eq!(f["severity"], "Moderate");
        assert_eq!(f["advisory_url"], "https://osv.dev/vulnerability/GHSA-x");

        let withdrawn = Vuln {
            withdrawn: true,
            ..vuln
        };
        assert!(finding(&q, "GHSA-x", Some(&withdrawn)).is_none());
        let pysec = json!({"advisory_id":"PYSEC-1","severity":"","aliases":["GHSA-x"]});
        let ghsa = json!({"advisory_id":"GHSA-x","severity":"High","aliases":["PYSEC-1"]});
        let other = json!({"advisory_id":"PYSEC-2","severity":"","aliases":[]});
        let kept = dedupe(vec![pysec, other, ghsa]);
        let ids: Vec<&str> = kept
            .iter()
            .map(|f| f["advisory_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["GHSA-x", "PYSEC-2"]);
        assert_eq!(
            finding(&q, "GHSA-y", None).unwrap()["fixed_version"],
            Value::Null
        );
    }

    #[test]
    fn orders_versions_for_display() {
        assert_eq!(natural_cmp("1.10", "1.9"), Ordering::Greater);
        assert_eq!(natural_cmp("3.0.11-1~deb12u2", "3.0.11-1"), Ordering::Less);
        assert_eq!(natural_cmp("2.0", "2.0.1"), Ordering::Less);
        assert_eq!(
            choose_fixed("9.0", vec!["5.0.3", "4.2.11"]).unwrap(),
            "4.2.11, 5.0.3"
        );
    }
}
