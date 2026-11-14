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
        .map(|(k, v): &(&str, &str)| format!("{k}=\"{}\"", escape(v)))
        .collect::<Vec<String>>();
    format!("{name}{{{}}} {value}\n", labels.join(","))
}

impl Database {
    pub fn render_metrics(&self) -> Result<String> {
        let scores: std::collections::HashMap<String, crate::nvd::Cvss> = self.cvss_scores()?;
        let mut cvss_scores: BTreeSet<String> = BTreeSet::new();
        let mut packages: BTreeSet<String> = BTreeSet::new();
        let mut vulnerabilities: BTreeSet<String> = BTreeSet::new();
        let mut stmt: rusqlite::Statement<'_> = self.0.prepare(&format!(
            "SELECT i.host_id,h.hostname,i.collector_id,i.name,i.version,a.findings,{EFFECTIVE_STATUS}
             FROM installations i JOIN hosts h ON h.id=i.host_id
             JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id
             LEFT JOIN assessments a ON a.host_id=i.host_id AND a.collector_id=i.collector_id
                AND a.installation_id=i.installation_id AND a.version=COALESCE(i.version,'')"
        ))?;
        let mut rows: rusqlite::Rows<'_> = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let host: String = r.get::<usize, String>(0)?;
            let hostname: String = r.get::<usize, String>(1)?;
            let collector: String = r.get::<usize, String>(2)?;
            let name: String = r.get::<usize, String>(3)?;
            let version: String = r
                .get::<usize, Option<String>>(4)?
                .unwrap_or("unknown".into());
            let findings: Option<String> = r.get::<usize, Option<String>>(5)?;
            let status: String = r.get::<usize, String>(6)?;
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
                .and_then(|f: String| serde_json::from_str::<Vec<Value>>(&f).ok())
                .unwrap_or_default();
            for f in findings {
                let text = |key: &str| -> String { f[key].as_str().unwrap_or("").to_string() };
                let fixed: String = text("fixed_version");
                let best: Option<(&str, &crate::nvd::Cvss)> = crate::nvd::best(&f["cves"], &scores);
                let score: String = best
                    .map(|(_, c): (&str, &crate::nvd::Cvss)| format!("{:.1}", c.score))
                    .unwrap_or_default();
                let cves: Vec<&str> = f["cves"]
                    .as_array()
                    .map(|a: &Vec<Value>| a.iter().filter_map(Value::as_str).collect::<Vec<&str>>())
                    .unwrap_or_default();
                vulnerabilities.insert(sample(
                    "software_inventory_vulnerability_info",
                    &[
                        ("host_id", &host),
                        ("hostname", &hostname),
                        ("name", &name),
                        ("version", &version),
                        ("advisory", &text("advisory_id")),
                        ("source", &text("source")),
                        ("advisory_url", &text("advisory_url")),
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
                            best.map_or("", |(_, c): (&str, &crate::nvd::Cvss)| {
                                c.severity.as_str()
                            }),
                        ),
                        (
                            "cvss_version",
                            best.map_or("", |(_, c): (&str, &crate::nvd::Cvss)| c.version.as_str()),
                        ),
                        (
                            "cvss_cve",
                            best.map_or("", |(id, _): (&str, &crate::nvd::Cvss)| id),
                        ),
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
        let mut out: String = String::new();
        header(
            &mut out,
            "software_inventory_package_info",
            "Installed package per host with its effective assessment status.",
        );
        packages.into_iter().for_each(|s: String| out.push_str(&s));
        header(
            &mut out,
            "software_inventory_vulnerability_info",
            "Advisory finding on a package whose status is affected or needs_review.",
        );
        vulnerabilities
            .into_iter()
            .for_each(|s: String| out.push_str(&s));
        header(
            &mut out,
            "software_inventory_vulnerability_cvss_score",
            "Highest NVD CVSS base score among the finding's CVEs (absent when unscored).",
        );
        cvss_scores
            .into_iter()
            .for_each(|s: String| out.push_str(&s));

        header(
            &mut out,
            "software_inventory_host_last_seen_timestamp_seconds",
            "Server receipt time of the host's latest accepted inventory.",
        );
        let mut stmt: rusqlite::Statement<'_> = self
            .0
            .prepare("SELECT id,hostname,last_seen FROM hosts ORDER BY id")?;
        let mut rows: rusqlite::Rows<'_> = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let (id, hostname): (String, String) =
                (r.get::<usize, String>(0)?, r.get::<usize, String>(1)?);
            out.push_str(&sample(
                "software_inventory_host_last_seen_timestamp_seconds",
                &[("host_id", &id), ("hostname", &hostname)],
                r.get::<usize, i64>(2)?,
            ));
        }
        header(
            &mut out,
            "software_inventory_collector_success",
            "Whether the host's latest attempt for this active collector succeeded.",
        );
        let mut stmt: rusqlite::Statement<'_> = self
            .0
            .prepare("SELECT host_id,id,success FROM collectors WHERE active=1 ORDER BY 1,2")?;
        let mut rows: rusqlite::Rows<'_> = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let (host, id): (String, String) =
                (r.get::<usize, String>(0)?, r.get::<usize, String>(1)?);
            out.push_str(&sample(
                "software_inventory_collector_success",
                &[("host_id", &host), ("collector", &id)],
                r.get::<usize, i64>(2)?,
            ));
        }
        let state: Option<(bool, Option<i64>)> = self
            .0
            .query_row(
                "SELECT success,last_success FROM assessment_state WHERE id=1",
                [],
                |r: &rusqlite::Row<'_>| {
                    Ok((r.get::<usize, bool>(0)?, r.get::<usize, Option<i64>>(1)?))
                },
            )
            .optional()?;
        header(
            &mut out,
            "software_inventory_assessment_success",
            "Whether the latest Arch security tracker import succeeded (1 when disabled).",
        );
        writeln!(
            out,
            "software_inventory_assessment_success {}",
            u8::from(state.is_some_and(|s: (bool, Option<i64>)| s.0))
        )?;
        header(
            &mut out,
            "software_inventory_assessment_last_success_timestamp_seconds",
            "Unix time of the latest successful Arch tracker import; zero if never.",
        );
        writeln!(
            out,
            "software_inventory_assessment_last_success_timestamp_seconds {}",
            state.and_then(|s: (bool, Option<i64>)| s.1).unwrap_or(0)
        )?;
        let osv: Option<(bool, Option<i64>)> = self.osv_state()?;
        header(
            &mut out,
            "software_inventory_osv_success",
            "Whether the latest OSV.dev query pass succeeded.",
        );
        writeln!(
            out,
            "software_inventory_osv_success {}",
            u8::from(osv.is_some_and(|s: (bool, Option<i64>)| s.0))
        )?;
        header(
            &mut out,
            "software_inventory_osv_last_success_timestamp_seconds",
            "Unix time of the latest successful OSV.dev query pass; zero if never.",
        );
        writeln!(
            out,
            "software_inventory_osv_last_success_timestamp_seconds {}",
            osv.and_then(|s: (bool, Option<i64>)| s.1).unwrap_or(0)
        )?;
        let nvd: Option<(bool, Option<i64>)> = self.nvd_state()?;
        header(
            &mut out,
            "software_inventory_nvd_success",
            "Whether the latest NVD enrichment pass completed without errors.",
        );
        writeln!(
            out,
            "software_inventory_nvd_success {}",
            u8::from(nvd.is_some_and(|s: (bool, Option<i64>)| s.0))
        )?;
        header(
            &mut out,
            "software_inventory_nvd_last_success_timestamp_seconds",
            "Unix time of the latest complete NVD enrichment pass; zero if never.",
        );
        writeln!(
            out,
            "software_inventory_nvd_last_success_timestamp_seconds {}",
            nvd.and_then(|s: (bool, Option<i64>)| s.1).unwrap_or(0)
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
