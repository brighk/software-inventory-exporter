# Software Inventory Exporter

[![CI](https://github.com/brighk/software-inventory-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/brighk/software-inventory-exporter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Know what software runs on every host, and which of it needs a patch.

A small agent on each Linux host reports every installed package to a central server.
The server checks Arch Linux packages against the
[Arch security tracker](https://security.archlinux.org/), scores the matching CVEs with
[NIST NVD](https://nvd.nist.gov/) CVSS, and exposes everything to Prometheus. A ready-made
Grafana dashboard shows all software and the software that needs patching.

- **One static binary.** It runs as agent, server, assessment worker or standalone
  exporter. SQLite is bundled, so there is no database service to run.
- **Push, not scrape.** Agents need no open port. Snapshots are saved to disk and
  delivered after outages.
- **Arch-aware matching.** Versions are compared with ALPM ordering (epochs, package
  releases). Uncertain matches are labelled `needs_review` rather than hidden or overstated.
- **CVSS from NVD.** Cached and rate-limited, with an optional free API key.
- **Prometheus and Grafana built in.** Includes a ServiceMonitor and a dashboard for
  kube-prometheus-stack.
- **Locked down by default.** Per-host upload tokens and a separate read token. The
  agent runs as an unprivileged systemd unit; the containers are non-root with
  read-only filesystems.

> **Status:** early (0.x). Vulnerability assessment currently covers **Arch Linux pacman
> packages only**. Inventory collection also supports dpkg, rpm, apk, Snap, Flatpak,
> Python, npm and Cargo. See [coverage limits](docs/operations.md#coverage-limits).

## How it works

```
  every host                         central (Kubernetes or any Linux host)
 ┌────────────────────┐   HTTPS    ┌──────────────────────────────────────────┐
 │ agent (systemd)    │ ─────────► │ server ── SQLite ── assess               │
 │  pacman -Q / dpkg… │  push, 12h │   │                   ├ Arch tracker (1h)│
 │  durable snapshot  │            │   │ /metrics          └ NIST NVD CVSS    │
 └────────────────────┘            └───┼──────────────────────────────────────┘
                                       ▼
                               Prometheus ──► Grafana dashboard
```

## Quickstart

### 1. Central server on Kubernetes (kube-prometheus-stack)

```sh
git clone https://github.com/brighk/software-inventory-exporter && cd software-inventory-exporter
kubectl apply -f deploy/k3s/inventory.yaml
READ=$(openssl rand -hex 32); HOST=$(openssl rand -hex 32)
kubectl create secret generic software-inventory-credentials -n software-inventory \
  --from-literal=read_token="$READ" \
  --from-literal=credentials.json="{\"read_token\":\"$READ\",\"hosts\":{\"web-01\":\"$HOST\"}}"
kubectl apply -f deploy/k3s/grafana-dashboard.yaml
```

See [deploy/k3s](deploy/k3s/README.md) for prerequisites, exposing the API to other hosts,
the optional NVD API key, and rollback. Without Kubernetes, run `server` and `assess` as
systemd units: see [fleet deployment](docs/operations.md#fleet-deployment-with-systemd).

### 2. Agent on each host

Download the binary for your architecture from
[Releases](https://github.com/brighk/software-inventory-exporter/releases), then:

```sh
sudo install -m 755 software-inventory-exporter /usr/local/bin/
sudo install -d /etc/software-inventory-exporter
sudo install -m 644 examples/arch.toml /etc/software-inventory-exporter/agent.toml
printf 'INVENTORY_TOKEN=%s\n' "$HOST" | sudo install -m 600 /dev/stdin /etc/software-inventory-exporter/agent.env
sudo install -m 644 examples/software-inventory-agent.service /etc/systemd/system/
sudo systemctl edit --full software-inventory-agent   # set --server and --host-id web-01
sudo systemctl enable --now software-inventory-agent
journalctl -u software-inventory-agent -f              # "Submitted inventory sequence 1"
```

Hostname and OS are detected from the kernel and `/etc/os-release`. For an internal or
self-signed CA, add `--ca-cert /path/to/ca.pem`.

### 3. Look at it

Open the **Software Inventory** dashboard in Grafana:

- **Software that needs a patch:** advisory matches with CVSS score and severity,
  installed and fixed versions, and links to the Arch advisory and NVD entry. Sorted by
  CVSS.
- **All software:** every package on every host, with its assessment status. It can be
  filtered by host and package name.
- **Health:** hosts reporting, oldest report, findings with CVSS ≥ 7, and the status of
  the tracker and NVD lookups.

To try everything on one machine without Kubernetes, follow
[local development](docs/operations.md#local-development).

## Assessment statuses

| Status | Meaning |
|---|---|
| `affected` | Installed version equals the advisory's affected version |
| `needs_review` | Possible match: below a fixed version, no fix published, or uncertain data |
| `no_known_match` | No applicable advisory. **Not proof of safety** |
| `pending` | New inventory arrived; it is assessed within a minute |
| `unsupported` | Not an Arch host, or not a pacman package |
| `not_assessed` / `stale_inventory` | No assessment yet / the collector failed or was removed |

## Prometheus metrics

All metrics come from the server's `/metrics` endpoint, which requires the read token.

| Metric | Labels / value |
|---|---|
| `software_inventory_package_info` | `host_id`, `hostname`, `collector`, `name`, `version`, `status` |
| `software_inventory_vulnerability_info` | package labels plus `advisory`, `severity`, `cves`, `fixed_version`, `patch_available`, `finding_status`, `tracker_status`, `cvss_score`, `cvss_severity`, `cvss_version`, `cvss_cve` |
| `software_inventory_vulnerability_cvss_score` | highest NVD CVSS base score of a finding |
| `software_inventory_host_last_seen_timestamp_seconds` | server receipt time of the latest upload |
| `software_inventory_collector_success` | latest collector attempt succeeded |
| `software_inventory_assessment_success`, `…_last_success_timestamp_seconds` | Arch tracker import |
| `software_inventory_nvd_success`, `…_last_success_timestamp_seconds`, `software_inventory_nvd_pending_cves` | NVD lookups |

```promql
# Findings with a fix available, highest CVSS first
sort_desc(software_inventory_vulnerability_cvss_score
  and on (host_id, name, version, advisory)
  software_inventory_vulnerability_info{patch_available="true"})

# Hosts that missed a 12 h reporting cycle
time() - software_inventory_host_last_seen_timestamp_seconds > 13 * 3600
```

## Collectors

The agent (and the standalone exporter) read a TOML config. An explicit `collectors`
array replaces automatic discovery. Unknown keys and duplicate IDs are rejected, and paths
are literal absolute paths. Nothing discovered is executed. Only the configured package
manager binaries are run, with time and output limits.

```toml
interval_seconds = 43200   # agent: scan and upload every 12 hours
timeout_seconds = 30

[[collectors]]
id = "os"
kind = "pacman"
path = "/usr/bin/pacman"
```

| Kind | `path` | Coverage |
|---|---|---|
| `pacman` | `/usr/bin/pacman` | All installed packages, including dependencies |
| `dpkg` | `/usr/bin/dpkg-query` | Installed packages; excludes removed packages with leftover config |
| `rpm` | `/usr/bin/rpm` | Installed packages, architecture, epoch/version/release |
| `apk` | `/lib/apk/db/installed` | Installed APK database, read directly |
| `snap` | `/usr/bin/snap` | Active installations |
| `flatpak` | `/usr/bin/flatpak` | Apps/runtimes visible to the service user |
| `python` | a `site-packages` / `dist-packages` dir | `.dist-info` / `.egg-info` metadata; never imports code |
| `npm` | a `node_modules` dir | Immediate packages (including scoped), from package.json |
| `cargo` | a Cargo install root | `.crates.toml` entries whose binary still exists |
| `filesystem` | a directory | Executable files up to `max_depth`; versions unknown |

Records from different sources are not merged. A Python package may also belong to an
OS package, so don't sum records to count unique applications. See
[`examples/config.toml`](examples/config.toml).

## Security model

- **Tokens:** each host has its own upload token, which can only submit inventory for
  that host ID. A separate read token covers queries and `/metrics`. Tokens are compared
  in constant time.
- **Transport:** the server speaks HTTP and binds to loopback by default. Agents require
  HTTPS for anything that isn't loopback, so put the server behind a TLS reverse proxy
  or a VPN.
- **Least privilege:** the agent only reads package databases, as an unprivileged
  `DynamicUser`. Containers run as non-root with read-only root filesystems and all
  capabilities dropped.
- **Untrusted input:** uploads are validated, size-limited and applied atomically.
  Sequence numbers stop replays and stale overwrites.

Please report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Documentation

- [Operations guide](docs/operations.md): agent, server, API, database semantics,
  assessment, NVD, systemd fleet deployment
- [Kubernetes / k3s deployment](deploy/k3s/README.md): manifests, ServiceMonitor,
  Grafana dashboard
- [Standalone exporter mode](docs/exporter.md): single-host `serve` / `scan` for Prometheus
- [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Building from source

Requires stable Rust 1.95+. Linux package collection requires Linux. Development and
the server also work on macOS.

```sh
cargo build --release --locked
docker build -t software-inventory-exporter .   # static musl image, ~8 MB
```

## License

[MIT](LICENSE)
