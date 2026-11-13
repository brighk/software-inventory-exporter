# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/brighk/software-inventory-exporter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brighk/software-inventory-exporter/releases/tag/v0.1.0
