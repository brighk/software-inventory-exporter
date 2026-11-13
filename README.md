# Software Inventory Exporter

A read-only software inventory agent and central inventory service written in Rust.
Collect Linux packages and configured language installations, store complete host
inventories in SQLite, and assess Arch packages against the Arch security tracker.
The existing cached Prometheus and JSON exporter remains available.

**Developing on macOS, collecting from Arch:** start with the
[central inventory guide](docs/central-inventory.md). It includes a local Mac setup,
agent delivery, database queries, the initial Arch assessment worker, and coverage
limits. This remains an initial implementation, not a complete asset-management,
vulnerability-scanning, or audit-history system.

## Quick start

Linux package collection requires Linux. Development, central storage and assessment
work on macOS and Linux with a current stable Rust toolchain (tested with Rust 1.99.1).
This project uses Rust edition 2024. The included lockfile records the dependencies tested for this release.

```bash
cargo build --release --locked
./target/release/software-inventory-exporter scan
./target/release/software-inventory-exporter serve
```

In another terminal:

```bash
curl --fail http://127.0.0.1:9898/metrics
curl --fail http://127.0.0.1:9898/inventory
```

Without a config file, the app discovers supported OS package tools, Snap and
Flatpak at standard paths, plus `/usr/local/bin` and `/opt` if present. It does
**not** scan every home directory or search for every virtual environment.
Language installations require configured roots. Filesystem candidates are
included in JSON but excluded from Prometheus by default.

Try a one-shot scan before running a service:

```bash
./target/release/software-inventory-exporter --config examples/config.toml scan
./target/release/software-inventory-exporter --config examples/config.toml scan --format metrics
./target/release/software-inventory-exporter --include-path --path /srv/apps scan
```

`--path` accepts absolute directories and can be repeated. `--include-path`
adds absolute directories from this process's PATH, scanning one level deep.
Neither option executes discovered programs. Empty/relative PATH entries are
ignored. Duplicate roots are avoided for PATH additions; overlapping explicit
collectors remain independent observations.

Exit codes: **0** all collectors succeeded; **2** inventory was produced but one
or more collectors failed; **1** startup/configuration/runtime failure. Clap also
uses code 2 for invalid CLI arguments, without producing an inventory document.

## Configure the scope

Edit `examples/config.toml` to match the server. An explicit `collectors` array
replaces the automatic defaults; `collectors = []` intentionally scans nothing.
Unknown configuration keys and duplicate collector IDs are rejected. Paths are
literal absolute paths: no shell, `~`, or environment substitution.

| Kind | `path` means | Coverage |
|---|---|---|
| `dpkg` | `/usr/bin/dpkg-query` | Installed packages; excludes removed packages with leftover config |
| `rpm` | `/usr/bin/rpm` | Installed packages, architecture, epoch/version/release |
| `pacman` | `/usr/bin/pacman` | Installed packages and versions |
| `apk` | `/lib/apk/db/installed` | Installed APK database, read directly |
| `snap` | `/usr/bin/snap` | Active installations from `snap list`; revision in JSON evidence |
| `flatpak` | `/usr/bin/flatpak` | App/runtime refs visible to the service user; separates branch and installation |
| `python` | An exact `site-packages` or `dist-packages` directory | `.dist-info/METADATA` and `.egg-info` metadata; never imports Python code |
| `npm` | An exact `node_modules` directory | Installed immediate children, including scoped packages; reads package.json |
| `cargo` | A Cargo install root, commonly `/home/alice/.cargo` | `.crates.toml` entries with at least one corresponding binary still present |
| `filesystem` | Directory to inspect | Regular files with executable bits, to `max_depth`; unknown versions |

Python roots can come from system installations, user installations, virtualenvs,
uv, pipx, or Conda environments; specify each actual metadata directory. `.egg`
archives, editable installs without these metadata formats, and arbitrary source
trees are not covered. Two roots should use distinct stable IDs such as
`api-python` and `worker-python`.

The npm collector reads installed files, not package-lock.json declarations. It
includes immediate packages physically present (including hoisted dependencies),
but does not recursively traverse nested node_modules, pnpm's internal store, or
Yarn Plug'n'Play. Configure additional roots if needed. Symlinked direct packages
are read through their package.json.

Cargo metadata is an implementation detail and may change in future Cargo
versions. `cargo install --no-track` installations are not covered by this
collector. Filesystem discovery may still find their binaries with unknown
versions. Cargo metadata is evidence, not proof that a binary was not replaced.

Filesystem depth 1 means direct children; depth 4 means up to four path
components under the root. Directory symlinks are not followed. Executable
symlinks resolve to a canonical target and are deduplicated **within that
collector**; multi-call binary aliases are not separate software entries.
Broken symlinks are skipped. Metadata paths must be regular files. An unknown
executable is a candidate, not a confirmed application.

## Prometheus

The default listener is **127.0.0.1:9898**, with no TLS or authentication. For a
local Prometheus process, merge `examples/prometheus.yml` into your existing
configuration. If Prometheus is in Kubernetes or a container, its `localhost`
is not the host: use a reachable private host address and bind the exporter to
that specific address, for example:

```bash
./target/release/software-inventory-exporter serve --listen 192.168.1.20:9898
```

Use your host's actual address. Changing the listen address exposes inventory
on that interface; restrict access to the Prometheus server using your firewall
or an authenticated proxy. JSON reveals installation paths. Avoid public access.

Before reloading an existing Prometheus configuration, validate it (if promtool
is installed):

```bash
promtool check config /etc/prometheus/prometheus.yml
promtool check rules examples/alerts.yml
```

Keep a copy of the old configuration. Reload using your existing service's
normal mechanism. Revert that configuration and reload to roll back. The example
rules are not installed automatically.

Example metric (illustrative version):

```prometheus
host_software_info{name="nginx",version="1.26.2",source="dpkg",scope="os",architecture="amd64",installation_id="..."} 1
```

The `1` means observed, not running or healthy. The version is a string label;
Prometheus cannot perform package-manager version ordering or determine
vulnerability status from it. `instance` and `job` are added by Prometheus.
`scope` identifies the configured collector. `installation_id` is a stable
96-bit truncated SHA-256 of discovery identity, **not a binary checksum**. It
avoids putting full paths in metric labels. Renaming collector IDs changes
series identities. It is not a privacy boundary for guessable paths.

Metric families:

- `host_software_info`: one sample per exported installation/version.
- `host_software_collector_success`: latest attempt succeeded (0 before any attempt).
- `host_software_collector_last_attempt_timestamp_seconds`: last attempt start.
- `host_software_collector_last_success_timestamp_seconds`: successful snapshot's
  observation time, or 0 if never successful.
- `host_software_collector_duration_seconds`: duration of the last attempt.
- `host_software_collector_items`: cached records, before metric filters.
- `host_software_initial_scan_complete`: every collector was attempted at least once.

Useful PromQL:

```promql
# Installed versions of nginx by host; use an instant table in Grafana.
host_software_info{name="nginx"}

# Number of distinct observed versions for each software name/source.
count by (name, source) (
  count by (name, source, version) (host_software_info)
)

# Only inventories whose most recent collector attempt succeeded.
host_software_info
  and on (job, instance, scope)
  (host_software_collector_success == 1)

# Hosts where a selected dpkg package is missing from a successful OS scan.
# Adjust scope="os" to match your config; allowlist must include nginx if used.
(host_software_collector_success{source="dpkg",scope="os"} == 1)
  unless on (job, instance, scope)
  host_software_info{source="dpkg",scope="os",name="nginx"}
```

The missing-package query assumes package names match exactly and the inventory
has not been filtered to exclude that package. Multiarch Debian names can include
an architecture suffix. Gate incident-sensitive queries on freshness as well as
success. `examples/alerts.yml` contains exporter-down, collector-failure, and stale
inventory alerts.

Each distinct label set creates a series. All OS libraries are included, not
just applications. Start with a few hosts, then use `include_names` (exact names)
if needed. Versions create new series on upgrades; old series remain until
Prometheus retention expires. `export_filesystem = true` opts filesystem
candidates into metrics; JSON is unaffected by either metric filter. Detailed
per-project inventories are generally better kept in JSON than scraped fleet-wide.

## Scan and failure behavior

A background task scans immediately on startup, then waits 900 seconds after
each complete pass (configurable). Collectors run sequentially, so scans never
overlap. HTTP handlers return pre-encoded cached bytes; scrapes do not trigger
scans or run package managers. A completed pass is published atomically.

Each collector replaces its cache only on success. A successful empty scan
removes its previous records. A failed scan keeps the previous successful
records, sets `success=false`, and records an error. A first-ever failed scan
has no records. Last-known data remains in memory until recovery or restart;
use success/freshness metrics to avoid treating it as current. The standalone exporter has no persistent cache. Central database storage is
available through the separate `agent` and `server` commands.

`/healthz` indicates that HTTP is responding. `/readyz` returns 503 until the
first pass completes, then 200 even if some collectors failed; inspect collector
metrics for completeness. `/inventory` exposes per-collector boundaries,
last-success times, errors, evidence and paths. Before the first pass it contains
configured collectors with no observations.

Commands have time and output limits, null stdin, C locale, and checked exit
statuses. Only configured package-manager executables run; do not configure
untrusted programs or shell wrappers. On a timeout the direct child is killed
and reaped. This is not a process sandbox and does not supervise arbitrary
wrapper descendants.

Passive scans have depth/entry/aggregate metadata-byte limits and cooperative
deadlines. A limit or read/parse error fails the entire collector rather than
silently replacing a good snapshot with partial results. Filesystem syscalls
on stuck network mounts cannot be forcibly interrupted by the cooperative
check; scan local disks. A snapshot can race concurrent installs/upgrades;
there is no transaction spanning all package systems. Failures can recover on
the next pass.

Cross-source observations are intentionally not merged: a Python distribution
may also belong to an OS package, and a filesystem candidate may be the binary
provided by either. Package ownership correlation is a future enhancement.
Do not sum all records and interpret that as a count of unique applications.

## Running as a service

`examples/software-inventory-exporter.service` is a systemd template. Before
installing it, confirm the release binary works with `--config ... scan` under
the intended unprivileged service account. Grant read access only to the metadata
roots you intend to inventory. Other users' Flatpak installs are not discovered
merely by running as root; service-user visibility matters.

To deploy, create the `software-inventory` service account, place the binary at
`/usr/local/bin/software-inventory-exporter`, place a reviewed configuration at
`/etc/software-inventory-exporter/config.toml`, and install the unit in your
normal systemd unit directory. Review paths, permissions and network exposure
before enabling it. The template makes system paths read-only and drops Linux
capabilities; it may require adjustment for the host's package manager. It
does not grant permission to private home directories.

Enabling the unit starts a new listener and background scans; it does not change
installed packages. Rollback is to stop/disable this unit and restore/remove its
configuration and binary. Nothing is installed by building or running the tests.
No Docker image is included: running this inside a container would normally
inventory the container, not the host.

## How the Rust code fits together

- `main.rs`: Clap CLI, background scan loop, shared cached bytes, Axum routes,
  Ctrl-C/SIGTERM handling.
- `config.rs`: collector definitions, auto-detection, validation and limits.
- `collectors.rs`: one parser/reader per source, producing `Vec<Software>`.
- `command.rs`: bounded asynchronous package-manager process execution.
- `model.rs`: normalized records and success/failure cache replacement.
- `metrics.rs`: Prometheus text encoding, escaping, deduplication and filtering.

`Option<String>` represents a known or unknown version. `Result<Vec<Software>>`
means a collector either returns a valid snapshot or an explicit error.
`Arc<RwLock<Cache>>` shares the most recent serialized snapshot: the scan loop
briefly takes a write lock to replace it; HTTP handlers briefly take a read lock
and clone reference-counted bytes. Blocking filesystem work runs outside the
async executor's worker threads.

## Development and validation

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/smoke.py target/debug/software-inventory-exporter
python3 tests/central_smoke.py target/debug/software-inventory-exporter
```

Tests cover removed dpkg packages, malformed records, multiple package formats,
Flatpak branch identities, Python/npm/Cargo metadata, passive filesystem scans,
symlink loops/deduplication, output/time limits, metric escaping, cached failures,
successful removals, and live HTTP/CLI behavior. The smoke test uses temporary
fixtures and a loopback listener. See `VALIDATION.md` for the checks actually run
for this archive. Other distributions still need testing on real hosts.

## References

- [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)
- [Python installed-project metadata](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)
- [Cargo home metadata](https://doc.rust-lang.org/cargo/guide/cargo-home.html)
- [Flatpak command reference](https://docs.flatpak.org/en/latest/flatpak-command-reference.html)
- [RPM query formats](https://rpm.org/docs/latest/man/rpm-queryformat.7.html)
