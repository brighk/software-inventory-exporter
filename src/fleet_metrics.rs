//! Prometheus exposition of the central inventory and its assessment results.
//! Rendered from the database on each scrape; one series per installed package
//! and one per advisory finding on packages that need attention.
use crate::{assessment::EFFECTIVE_STATUS, database::Database, metrics::escape};
use anyhow::Result;
use rusqlite::OptionalExtension;
use serde_json::Value;
use std::{collections::BTreeSet, fmt::Write};

fn header(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge").unwrap();
}

/// Renders `name{k="v",...} value` with escaped label values.
fn sample(name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) -> String {
    let labels: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
        .collect();
    format!("{name}{{{}}} {value}\n", labels.join(","))
}

impl Database {
    pub fn render_metrics(&self) -> Result<String> {
        let scores = self.cvss_scores()?;
        let mut cvss_scores = BTreeSet::new();
        let mut packages = BTreeSet::new();
        let mut vulnerabilities = BTreeSet::new();
        let mut stmt = self.0.prepare(&format!(
            "SELECT i.host_id,h.hostname,i.collector_id,i.name,i.version,a.findings,{EFFECTIVE_STATUS}
             FROM installations i JOIN hosts h ON h.id=i.host_id
             JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id
             LEFT JOIN assessments a ON a.host_id=i.host_id AND a.collector_id=i.collector_id
                AND a.installation_id=i.installation_id AND a.version=COALESCE(i.version,'')"
        ))?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let host: String = r.get(0)?;
            let hostname: String = r.get(1)?;
            let collector: String = r.get(2)?;
            let name: String = r.get(3)?;
            let version = r.get::<_, Option<String>>(4)?.unwrap_or("unknown".into());
            let findings: Option<String> = r.get(5)?;
            let status: String = r.get(6)?;
            packages.insert(sample(
                "software_inventory_package_info",
                &[
                    ("host_id", &host),
                    ("hostname", &hostname),
                    ("collector", &collector),
                    ("name", &name),
                    ("version", &version),
                    ("status", &status),
                ],
                1,
            ));
            if !matches!(status.as_str(), "affected" | "needs_review") {
                continue;
            }
            let findings: Vec<Value> = findings
                .and_then(|f| serde_json::from_str(&f).ok())
                .unwrap_or_default();
            for f in findings {
                let text = |key: &str| f[key].as_str().unwrap_or("").to_string();
                let fixed = text("fixed_version");
                let best = crate::nvd::best(&f["cves"], &scores);
                let score = best
                    .map(|(_, c)| format!("{:.1}", c.score))
                    .unwrap_or_default();
                let cves: Vec<&str> = f["cves"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                vulnerabilities.insert(sample(
                    "software_inventory_vulnerability_info",
                    &[
                        ("host_id", &host),
                        ("hostname", &hostname),
                        ("name", &name),
                        ("version", &version),
                        ("advisory", &text("advisory_id")),
                        ("severity", &text("severity")),
                        ("cves", &cves.join(",")),
                        ("fixed_version", &fixed),
                        (
                            "patch_available",
                            if fixed.is_empty() { "false" } else { "true" },
                        ),
                        ("finding_status", &text("status")),
                        ("tracker_status", &text("tracker_status")),
                        ("cvss_score", &score),
                        (
                            "cvss_severity",
                            best.map_or("", |(_, c)| c.severity.as_str()),
                        ),
                        ("cvss_version", best.map_or("", |(_, c)| c.version.as_str())),
                        ("cvss_cve", best.map_or("", |(id, _)| id)),
                    ],
                    1,
                ));
                if let Some((_, c)) = best {
                    cvss_scores.insert(sample(
                        "software_inventory_vulnerability_cvss_score",
                        &[
                            ("host_id", &host),
                            ("hostname", &hostname),
                            ("name", &name),
                            ("version", &version),
                            ("advisory", &text("advisory_id")),
                        ],
                        c.score,
                    ));
                }
            }
        }
        let mut out = String::new();
        header(
            &mut out,
            "software_inventory_package_info",
            "Installed package per host with its effective assessment status.",
        );
        packages.into_iter().for_each(|s| out.push_str(&s));
        header(
            &mut out,
            "software_inventory_vulnerability_info",
            "Advisory finding on a package whose status is affected or needs_review.",
        );
        vulnerabilities.into_iter().for_each(|s| out.push_str(&s));
        header(
            &mut out,
            "software_inventory_vulnerability_cvss_score",
            "Highest NVD CVSS base score among the finding's CVEs (absent when unscored).",
        );
        cvss_scores.into_iter().for_each(|s| out.push_str(&s));

        header(
            &mut out,
            "software_inventory_host_last_seen_timestamp_seconds",
            "Server receipt time of the host's latest accepted inventory.",
        );
        let mut stmt = self
            .0
            .prepare("SELECT id,hostname,last_seen FROM hosts ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let (id, hostname): (String, String) = (r.get(0)?, r.get(1)?);
            out.push_str(&sample(
                "software_inventory_host_last_seen_timestamp_seconds",
                &[("host_id", &id), ("hostname", &hostname)],
                r.get::<_, i64>(2)?,
            ));
        }
        header(
            &mut out,
            "software_inventory_collector_success",
            "Whether the host's latest attempt for this active collector succeeded.",
        );
        let mut stmt = self
            .0
            .prepare("SELECT host_id,id,success FROM collectors WHERE active=1 ORDER BY 1,2")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let (host, id): (String, String) = (r.get(0)?, r.get(1)?);
            out.push_str(&sample(
                "software_inventory_collector_success",
                &[("host_id", &host), ("collector", &id)],
                r.get::<_, i64>(2)?,
            ));
        }
        let state: Option<(bool, Option<i64>)> = self
            .0
            .query_row(
                "SELECT success,last_success FROM assessment_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        header(
            &mut out,
            "software_inventory_assessment_success",
            "Whether the latest advisory import and assessment succeeded.",
        );
        writeln!(
            out,
            "software_inventory_assessment_success {}",
            u8::from(state.is_some_and(|s| s.0))
        )?;
        header(
            &mut out,
            "software_inventory_assessment_last_success_timestamp_seconds",
            "Unix time of the latest successful assessment; zero if never.",
        );
        writeln!(
            out,
            "software_inventory_assessment_last_success_timestamp_seconds {}",
            state.and_then(|s| s.1).unwrap_or(0)
        )?;
        let nvd = self.nvd_state()?;
        header(
            &mut out,
            "software_inventory_nvd_success",
            "Whether the latest NVD enrichment pass completed without errors.",
        );
        writeln!(
            out,
            "software_inventory_nvd_success {}",
            u8::from(nvd.is_some_and(|s| s.0))
        )?;
        header(
            &mut out,
            "software_inventory_nvd_last_success_timestamp_seconds",
            "Unix time of the latest complete NVD enrichment pass; zero if never.",
        );
        writeln!(
            out,
            "software_inventory_nvd_last_success_timestamp_seconds {}",
            nvd.and_then(|s| s.1).unwrap_or(0)
        )?;
        header(
            &mut out,
            "software_inventory_nvd_pending_cves",
            "CVEs referenced by current findings that have not been looked up in NVD yet.",
        );
        writeln!(
            out,
            "software_inventory_nvd_pending_cves {}",
            self.cves_to_fetch(i64::MIN, i64::MAX)?.len()
        )?;
        Ok(out)
    }
}
