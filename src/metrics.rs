use crate::{
    config::{Config, Kind},
    model::Inventory,
};
use std::{collections::BTreeSet, fmt::Write};

pub fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}
fn header(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge").unwrap();
}
pub fn render(inventory: &Inventory, config: &Config) -> String {
    let mut out = String::new();
    header(
        &mut out,
        "host_software_info",
        "Observed software installation; may be cached after collector failure.",
    );
    let mut samples = BTreeSet::new();
    for state in inventory.collectors.values() {
        for item in &state.software {
            if item.source == Kind::Filesystem && !config.export_filesystem {
                continue;
            }
            if !config.include_names.is_empty() && !config.include_names.contains(&item.name) {
                continue;
            }
            samples.insert(format!("host_software_info{{name=\"{}\",version=\"{}\",source=\"{}\",scope=\"{}\",architecture=\"{}\",installation_id=\"{}\"}} 1\n",
                escape(&item.name), escape(item.version.as_deref().unwrap_or("unknown")), item.source.name(),
                escape(&item.scope), escape(&item.architecture), escape(&item.installation_id)));
        }
    }
    for sample in samples {
        out.push_str(&sample);
    }
    for (name, help) in [
        (
            "host_software_collector_success",
            "Whether the latest scan succeeded; zero also before the first scan.",
        ),
        (
            "host_software_collector_last_attempt_timestamp_seconds",
            "Unix time of latest collector attempt; zero if never attempted.",
        ),
        (
            "host_software_collector_last_success_timestamp_seconds",
            "Unix time of latest successful scan; zero if never successful.",
        ),
        (
            "host_software_collector_duration_seconds",
            "Duration of latest collector attempt.",
        ),
        (
            "host_software_collector_items",
            "Number of cached records, including records excluded from software metrics.",
        ),
    ] {
        header(&mut out, name, help);
        for (id, state) in &inventory.collectors {
            let value = match name {
                "host_software_collector_success" => u8::from(state.success) as f64,
                "host_software_collector_last_attempt_timestamp_seconds" => {
                    state.last_attempt_timestamp_seconds as f64
                }
                "host_software_collector_last_success_timestamp_seconds" => {
                    state.last_success_timestamp_seconds.unwrap_or(0) as f64
                }
                "host_software_collector_duration_seconds" => state.duration_seconds,
                _ => state.software.len() as f64,
            };
            writeln!(
                out,
                "{name}{{scope=\"{}\",source=\"{}\"}} {value}",
                escape(id),
                escape(&state.source)
            )
            .unwrap();
        }
    }
    header(
        &mut out,
        "host_software_initial_scan_complete",
        "Whether every configured collector has been attempted at least once.",
    );
    writeln!(
        out,
        "host_software_initial_scan_complete {}",
        u8::from(inventory.initial_scan_complete)
    )
    .unwrap();
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Collector, model::Software};
    #[test]
    fn escaping_and_failed_refresh_preserve_inventory() {
        assert_eq!(escape("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
        let c = Collector {
            id: "os".into(),
            kind: Kind::Dpkg,
            path: "/usr/bin/dpkg-query".into(),
            max_depth: 1,
        };
        let mut inv = Inventory::default();
        inv.apply(
            &c,
            Ok(vec![Software::new(&c, "demo", "1", "", None, "test", "")]),
            100,
            0.1,
        );
        inv.apply(&c, Err(anyhow::anyhow!("failed")), 200, 0.2);
        assert_eq!(
            inv.collectors["os"].last_success_timestamp_seconds,
            Some(100)
        );
        let metrics = render(&inv, &Config::default());
        assert!(metrics.contains("version=\"1\""));
        assert!(
            metrics.contains("host_software_collector_success{scope=\"os\",source=\"dpkg\"} 0")
        );
        inv.apply(&c, Ok(vec![]), 300, 0.1);
        assert!(!render(&inv, &Config::default()).contains("version=\"1\""));
    }
    #[test]
    fn filters_only_metrics_and_deduplicates_samples() {
        let c = Collector {
            id: "fs".into(),
            kind: Kind::Filesystem,
            path: "/opt".into(),
            max_depth: 1,
        };
        let item = Software::new(&c, "demo", "", "", None, "test", "");
        let mut inv = Inventory::default();
        inv.apply(&c, Ok(vec![item.clone(), item]), 1, 0.0);
        let mut cfg = Config::default();
        assert!(!render(&inv, &cfg).contains("name=\"demo\""));
        cfg.export_filesystem = true;
        assert_eq!(render(&inv, &cfg).matches("name=\"demo\"").count(), 1);
        cfg.include_names = vec!["other".into()];
        assert!(!render(&inv, &cfg).contains("name=\"demo\""));
        assert_eq!(inv.collectors["fs"].software.len(), 1);
    }
}
