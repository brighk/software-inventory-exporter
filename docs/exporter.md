# Standalone exporter mode (`scan` and `serve`)

Before the central inventory existed, this project was a single-host Prometheus
exporter, and that mode is still supported. `serve` collects locally and exposes
cached `/metrics` and `/inventory` endpoints for Prometheus to scrape. `scan` prints
one inventory and exits. Neither needs the central server, and neither assesses
vulnerabilities. For fleet inventory with CVE/CVSS assessment, use the agent and
server described in the [README](../README.md).

```bash
cargo build --release --locked
./target/release/software-inventory-exporter scan
./target/release/software-inventory-exporter serve
curl --fail http://127.0.0.1:9898/metrics
curl --fail http://127.0.0.1:9898/inventory
```

Without a config file, the app discovers supported OS package tools, Snap and
Flatpak at standard paths, plus `/usr/local/bin` and `/opt` if present. It does
**not** scan every home directory or search for every virtual environment.
Language installations require configured roots. Filesystem candidates are
included in JSON but excluded from Prometheus by default.

```bash
./target/release/software-inventory-exporter --config examples/config.toml scan
./target/release/software-inventory-exporter --config examples/config.toml scan --format metrics
./target/release/software-inventory-exporter --include-path --path /srv/apps scan
```

`--path` accepts absolute directories and can be repeated. `--include-path`
adds absolute directories from this process's PATH, scanning one level deep.
Neither option executes discovered programs.

Exit codes: **0** all collectors succeeded; **2** inventory was produced but one
or more collectors failed; **1** startup/configuration/runtime failure. Clap also
uses code 2 for invalid CLI arguments, without producing an inventory document.

Collector configuration is shared with the agent; see
[Collectors](../README.md#collectors) in the README.

## Prometheus

The default listener is **127.0.0.1:9898**, with no TLS or authentication. For a
local Prometheus process, merge `examples/prometheus.yml` into your configuration.
If Prometheus runs in Kubernetes or a container, its `localhost` is not the host:
bind the exporter to a reachable private address, for example
`serve --listen 10.0.0.20:9898`, and restrict access with a firewall or an
authenticated proxy. JSON reveals installation paths. Avoid public access.

```prometheus
host_software_info{name="nginx",version="1.26.2",source="dpkg",scope="os",architecture="amd64",installation_id="..."} 1
```

The `1` means observed, not running or healthy. The version is a string label;
Prometheus cannot order package versions or determine vulnerability status from it.
`scope` identifies the configured collector. `installation_id` is a stable 96-bit
truncated SHA-256 of discovery identity, **not a binary checksum**. It avoids putting
full paths in labels but is not a privacy boundary for guessable paths.

| Metric | Meaning |
|---|---|
| `host_software_info` | One sample per exported installation/version |
| `host_software_collector_success` | Latest attempt succeeded (0 before any attempt) |
| `host_software_collector_last_attempt_timestamp_seconds` | Last attempt start |
| `host_software_collector_last_success_timestamp_seconds` | Successful snapshot's observation time, or 0 |
| `host_software_collector_duration_seconds` | Duration of the last attempt |
| `host_software_collector_items` | Cached records, before metric filters |
| `host_software_initial_scan_complete` | Every collector was attempted at least once |

```promql
# Installed versions of nginx by host
host_software_info{name="nginx"}

# Number of distinct observed versions for each software name/source
count by (name, source) (count by (name, source, version) (host_software_info))

# Only inventories whose most recent collector attempt succeeded
host_software_info and on (job, instance, scope) (host_software_collector_success == 1)
```

Each distinct label set creates a series, and all OS libraries are included. Start
with a few hosts, then use `include_names` (exact names) to limit series if needed.
`export_filesystem = true` opts filesystem candidates into metrics; JSON is unaffected
by metric filters. `examples/alerts.yml` contains exporter-down, collector-failure and
stale-inventory alerts. Validate with `promtool check config` / `promtool check rules`.

## Scan and failure behavior

A background task scans at startup, then waits `interval_seconds` (default 900) after
each complete pass. Collectors run sequentially, so scans never overlap. HTTP handlers
return pre-encoded cached bytes; scrapes never trigger scans.

Each collector replaces its cache only on success. A successful empty scan removes
previous records. A failed scan keeps the previous successful records, sets
`success=false` and records an error. `/healthz` indicates HTTP is responding; `/readyz`
returns 503 until the first pass completes.

## Running as a service

`examples/software-inventory-exporter.service` is a hardened systemd template for
`serve`. Create the `software-inventory` account, install the binary to
`/usr/local/bin/` and a reviewed config to `/etc/software-inventory-exporter/config.toml`.
Grant read access only to the metadata roots you intend to inventory. Other users'
Flatpak installs are not visible to the service user. Running inside a container
would inventory the container, not the host.
