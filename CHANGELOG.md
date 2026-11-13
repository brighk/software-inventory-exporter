# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-13

### Added
- Vulnerability assessment through [OSV.dev](https://osv.dev) for Debian and Ubuntu
  (dpkg), AlmaLinux, Rocky Linux, RHEL and openSUSE (rpm), and Python, npm and Cargo
  packages on any host. Query results and advisories are cached in the database and
  refreshed every 6 hours (`--osv-refresh-seconds`); `--no-osv` and `--osv-url` control it.
- `--no-arch` disables the Arch security tracker.
- Agents report the source package of dpkg and rpm packages, and the registry of Cargo
  installs. `/v1/installations` returns `source_package` and `source_version`.
- Findings carry `source` (`arch` or `osv`) and `advisory_url`; both are labels on
  `software_inventory_vulnerability_info`. New metrics `software_inventory_osv_success`
  and `software_inventory_osv_last_success_timestamp_seconds`; `/v1/assessment-status`
  has an `osv` object.

### Changed
- Database schema version 4 (migrated automatically). Arch advisories are stored in the
  database, so new inventory is assessed with the last imported feed even while a
  download is failing; the failure stays visible in the assessment status.
- Packages without a cached advisory result are `not_assessed`, never `no_known_match`.
- Debian/Ubuntu and openSUSE packages need an agent from this release (source packages);
  older agents' dpkg records are `unsupported` for those hosts.
- Grafana dashboard: advisory links follow `advisory_url`, a Source column, and the
  "Advisory feeds" stat covers both the Arch tracker and OSV.

## [0.1.0] - 2026-11-13

First release.

### Added
- Central inventory: `agent` pushes complete snapshots with durable delivery; `server`
  stores them in SQLite behind per-host upload tokens and a read token.
- Arch Linux assessment (`assess`) against the Arch security tracker with ALPM version
  ordering. New inventory is assessed within a minute.
- CVSS enrichment from the NIST NVD API 2.0, cached and rate-limited, with an optional
  API key and per-CVE retries.
- Prometheus `/metrics` on the server: packages, findings with CVSS, host freshness,
  feed and NVD status.
- Kubernetes manifests with a ServiceMonitor and a Grafana dashboard (all software,
  software needing a patch).
- systemd units for agent, server and assessment.
- Agent detects hostname and OS from the kernel and `/etc/os-release`. `--ca-cert`
  trusts an internal CA.
- `/v1/findings?status=` filtering; scan summaries are kept for 24 hours.
- Container image, release workflow (static amd64/arm64 binaries, GHCR image).
- Standalone exporter mode (`scan` / `serve`): dpkg, rpm, pacman, apk, Snap, Flatpak,
  Python, npm, Cargo and filesystem collectors with cached Prometheus and JSON endpoints.

[Unreleased]: https://github.com/brighk/software-inventory-exporter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/brighk/software-inventory-exporter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/brighk/software-inventory-exporter/releases/tag/v0.1.0
