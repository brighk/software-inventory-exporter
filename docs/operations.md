# Operations guide

One binary, five roles:

| Role | Runs on | Does |
|---|---|---|
| `agent` | every host (systemd) | collects packages, pushes complete snapshots to the server |
| `server` | central host / cluster | authenticated API, SQLite database, Prometheus `/metrics` |
| `assess` | next to the server | Arch security tracker and OSV.dev matching, NIST NVD CVSS lookups |
| `serve` / `scan` | any host | standalone exporter mode, see [exporter.md](exporter.md) |

`server` and `assess` share one SQLite file, so they must run on the same machine or
pod with a local disk (not a network filesystem). SQLite is bundled; no database
service is needed.

## Local development

Linux or macOS with stable Rust (1.95 or newer):

```sh
cargo build --locked
python3 examples/setup_dev.py          # creates dev-data/ (git-ignored); never overwrites
```

The setup script generates a read token, an upload token for host `dev-01`, and a
synthetic npm package to inventory.

```sh
# Terminal 1: server
./target/debug/software-inventory-exporter server \
  --database dev-data/inventory.db --credentials dev-data/credentials.json

# Terminal 2: agent (one shot)
export INVENTORY_TOKEN="$(python3 -c 'import json; print(json.load(open("dev-data/credentials.json"))["hosts"]["dev-01"])')"
./target/debug/software-inventory-exporter --config dev-data/dev.toml agent \
  --server http://127.0.0.1:9899 --host-id dev-01 --state dev-data/agent-state.json --once

# Terminal 3: assessment (one pass) and queries
./target/debug/software-inventory-exporter assess --database dev-data/inventory.db --once
export INVENTORY_READ_TOKEN="$(python3 -c 'import json; print(json.load(open("dev-data/credentials.json"))["read_token"])')"
curl -H "Authorization: Bearer $INVENTORY_READ_TOKEN" http://127.0.0.1:9899/v1/hosts
```

On an Arch machine, use `--config examples/arch.toml` to inventory real pacman packages.
The npm fixture is looked up in OSV.dev; add `--no-osv` to stay offline (it then reports
`unsupported`).

## Agent

```sh
software-inventory-exporter --config /etc/software-inventory-exporter/agent.toml agent \
  --server https://inventory.example.internal --host-id web-01 \
  --state /var/lib/software-inventory-agent/state.json
```

| Option | Meaning |
|---|---|
| `--server` | API origin. HTTPS, or plain HTTP only to a loopback address |
| `--host-id` | Stable, unique, provisioned identity (letters, digits, `-`, `_`; max 128) |
| `--hostname`, `--os`, `--os-version` | Override detection (kernel hostname; `ID` / `VERSION_ID` from `/etc/os-release`, `rolling` if absent) |
| `--ca-cert` | PEM bundle of extra CAs to trust for the server certificate (system roots stay trusted) |
| `--state` | Private, writable state file. Keep it across restarts; never copy it to another host |
| `--once` | Retry a pending snapshot or submit one new snapshot, then exit |
| `INVENTORY_TOKEN` (env) | This host's upload token (at least 32 characters) |

The scan interval comes from `interval_seconds` in the config file
(`examples/arch.toml`: 12 hours). `ID_LIKE` is deliberately ignored: EndeavourOS,
Manjaro, Linux Mint or Pop!_OS report their own ID and are not assessed against their
parent distribution's advisories.

### Delivery semantics

The agent stores a sequence counter and at most one pending snapshot. It writes and
syncs the snapshot before sending, and clears it only after a matching
acknowledgment. A file lock prevents two agents sharing a state file. Failed
deliveries retry after `interval_seconds` or 5 minutes, whichever is shorter. New
scans wait while a snapshot is pending.

Authentication errors, malformed requests and sequence conflicts (HTTP 4xx) stop the
agent with the pending snapshot intact: fix the cause and restart it. Do not delete the
state file to resolve a conflict. Resetting the counter cannot overwrite newer server
records. If state is lost, recover it or provision a new host ID.

## Server

```sh
software-inventory-exporter server --database /var/lib/software-inventory/inventory.db \
  --credentials /etc/software-inventory-exporter/credentials.json --listen 127.0.0.1:9899
```

The credentials file holds one read token and one upload token per host ID:

```json
{"read_token": "<openssl rand -hex 32>", "hosts": {"web-01": "<openssl rand -hex 32>"}}
```

Tokens must be unique and at least 32 printable characters. The server reads the file
at startup; restart it after adding hosts or rotating tokens. An upload token can only
submit inventory for its own host ID.

The server speaks plain HTTP. Expose it to other hosts through an HTTPS reverse proxy
(e.g. Traefik, nginx, Caddy) or over a VPN. Agents accept an internal or self-signed
CA through `--ca-cert`.

### API

All endpoints except `/healthz` need `Authorization: Bearer <token>`.

| Endpoint | Token | Purpose |
|---|---|---|
| `POST /v1/inventory` | host upload | Submit a snapshot (used by the agent) |
| `GET /v1/hosts` | read | Hosts, OS metadata, `last_seen` (server receipt time) |
| `GET /v1/installations?host_id=&name=` | read | Current installations (exact filters) |
| `GET /v1/collectors?host_id=` | read | Collector success, errors and activity for a host |
| `GET /v1/findings?host_id=&status=` | read | Assessment per installation, with findings and CVSS |
| `GET /v1/assessment-status` | read | Tracker import success, time, feed digest, error |
| `GET /metrics` | read | Prometheus exposition (see the README) |
| `GET /healthz` | none | Liveness |

List endpoints take `limit` (1–1000, default 100) and `offset`. `status` is a
comma-separated list of the statuses below. It is applied before pagination.
Pagination is not a snapshot across concurrent writes.

### Database semantics

A snapshot is applied in one transaction. Successful collectors replace their records;
a successful empty result clears them. Failed collectors keep their last server-side
records. Collectors omitted from a later configuration become inactive but stay visible.
Hosts that stop reporting keep their inventory, so check `last_seen` for freshness.

Identical retries are accepted without changes. Reusing a sequence with different
content, or sending an older sequence, returns HTTP 409. Ordering uses the persisted
counter, not the host clock.

Scan summaries older than 24 hours are deleted hourly (`--scan-retention-seconds`),
always keeping each host's latest one so a retried upload is still recognised as a
duplicate. Inventory, assessments and CVE details are current state, not history.
Schema migrations run automatically at startup; back up the database before upgrades.

| Table | Content |
|---|---|
| `hosts` | Identity, OS metadata, `last_seen`, latest sequence |
| `scans` | Accepted sequences (24 h retention), success, payload digest |
| `collectors` | Latest attempt, last success, error, active flag |
| `installations` | Current or last-known records per host and collector, with source package |
| `advisories` | Latest imported Arch advisories |
| `assessments` | Per-installation status and advisory/CVE matches |
| `assessment_state` | Tracker import status |
| `nvd_cves` | Cached NVD details and selected CVSS per CVE |
| `nvd_state` | NVD enrichment status |
| `osv_queries` | Cached OSV advisory IDs per (ecosystem, package, version) |
| `osv_vulns` | Cached OSV advisory summaries: CVEs, aliases, severity, fixed versions |
| `osv_state` | OSV query pass status |

## Assessment

```sh
software-inventory-exporter assess --database /var/lib/software-inventory/inventory.db
```

Each installation is assessed by one advisory source:

| Host `os` / collector | Source | Package looked up |
|---|---|---|
| `arch` / `pacman` | Arch security tracker | package name |
| `debian` / `dpkg` | OSV `Debian:<major>` | source package and version |
| `ubuntu` / `dpkg` | OSV `Ubuntu:<VERSION_ID>[:LTS]` | source package and version |
| `almalinux`, `rocky` / `rpm` | OSV `AlmaLinux:<major>`, `Rocky Linux:<major>` | binary package |
| `rhel` / `rpm` | OSV `Red Hat:enterprise_linux:<major>::baseos` and `::appstream` | binary package |
| `opensuse-leap`, `opensuse-tumbleweed` / `rpm` | OSV `openSUSE:Leap <VERSION_ID>`, `openSUSE:Tumbleweed` | source package |
| any / `python` | OSV `PyPI` | distribution name |
| any / `npm` | OSV `npm` | package name |
| any / `cargo` | OSV `crates.io` (crates.io installs only) | crate name |

Everything else (Alpine, Snap, Flatpak, Fedora, SLES, git/path Cargo installs, and
filesystem entries) is `unsupported`. The host `os` is the os-release `ID`; derivatives
(`ID_LIKE`) are deliberately not mapped, because their package versions differ.

Every `--interval-seconds` (default 3600) the worker downloads the
[Arch security tracker feed](https://security.archlinux.org/issues/all.json) and stores
it in the database. It checks every minute for newly uploaded inventory, queries OSV for
packages it has not seen, and re-assesses everything against the stored advisories. A
failed download keeps the previously imported feed in use and is reported in
`/v1/assessment-status` and `software_inventory_assessment_success` until the next
successful download. `--feed-file` uses a local feed instead (for tests). `--no-arch`
disables the tracker; pacman packages are then `unsupported`.

| Status | Meaning |
|---|---|
| `affected` | OSV: the installed version is inside an affected range. Arch: it equals the advisory's affected version (Vulnerable or Fixed) |
| `needs_review` | Possible Arch match: below a fixed version, no fixed version, or uncertain tracker data |
| `no_known_match` | No applicable advisory. **Not proof of safety** |
| `unsupported` | No advisory source for this host and collector (see the table above) |
| `not_assessed` | Not assessed yet (no feed imported, OSV not queried yet), or unknown version |
| `pending` | The host uploaded newer inventory since the last assessment |
| `stale_inventory` | The collector failed or is inactive |

Versions at or above a valid fixed version are excluded using ALPM version ordering
(epochs and package releases included). The tracker gives an affected version, not an
introduction bound, so lower versions are review candidates rather than confirmed.
Many tracker entries stay "Vulnerable" without a fixed version for years. Treat them as
review items.

### OSV.dev

[OSV.dev](https://osv.dev/) aggregates advisories from Debian, Ubuntu, AlmaLinux, Rocky
Linux, Red Hat, SUSE, the GitHub Advisory Database, PyPA and RustSec. The worker sends
each distinct (ecosystem, package, version) to the querybatch API, up to 1000 per
request. OSV evaluates the version ranges itself, with each ecosystem's ordering rules
(dpkg, RPM, PEP 440, SemVer), so every returned advisory is `affected`. Advisory records
are fetched once and refetched only when OSV reports a newer `modified` time.

- **Caching:** results are stored in `osv_queries` and `osv_vulns`. A package version is
  re-queried after `--osv-refresh-seconds` (default 6 hours). Results for versions no
  longer installed anywhere are deleted.
- **Failures:** a failed pass keeps cached results, shows as `software_inventory_osv_success 0`
  and under `osv` in `/v1/assessment-status`, and is retried after 10 minutes. Packages
  never queried stay `not_assessed`.
- **Duplicates:** one vulnerability often has several IDs (a GHSA and a PYSEC record for
  the same CVE). Findings that alias each other or cover exactly the same CVEs are
  reported once. Distro notices that bundle several CVEs (DSA, USN) are kept beside
  per-CVE records.
- **Fixed version:** the advisory's fix for the installed release branch. When an advisory
  lists fixes for several branches, the lowest one above the installed version is shown.
- **Privacy:** only ecosystem, package name and version are sent, never host IDs,
  hostnames or paths. `--no-osv` disables OSV; `--osv-url` points at a mirror.
- **Agents:** Debian, Ubuntu and openSUSE advisories name source packages, which agents
  report from this release on. dpkg records from older agents are `unsupported` until the
  agent is upgraded.

Debian and Ubuntu track every CVE that touches a package, including unfixed and
"unimportant" ones, so expect many more findings on those hosts than on Arch. The
`severity` is the distribution's urgency or priority where OSV provides it (GitHub's
severity for language packages).

### CVSS from NIST NVD

The worker also looks up CVEs referenced by `affected` and `needs_review` findings in
the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) and caches them.
A pass runs at startup and every 10 minutes: never-seen CVEs first, cached records
refreshed after 7 days (`--nvd-refresh-seconds`). Without an API key it waits 6 seconds
between requests, as NVD asks. With a [free key](https://nvd.nist.gov/developers/request-an-api-key)
in `NVD_API_KEY` it waits 0.7 seconds. Network errors and 5xx responses are retried twice
per CVE. A 403/429 or repeated failure ends the pass, keeps cached scores, and shows as
`software_inventory_nvd_success 0`. `--no-nvd` disables lookups.

Each finding gets `cvss`: the highest base score among its CVEs, with that CVE, the
version, vector, the scoring `source`, and `primary` (NVD's own score rather than a
CNA-supplied one such as Red Hat's). CVSS v3.1 is preferred, then v3.0, v4.0 and v2.
Within a version, NVD's Primary score wins. `cvss` is `null` until looked up, or if NVD
has not scored the CVE ("Awaiting Analysis", "Deferred").

### Coverage limits

Arch packages are matched by name, so AUR or custom builds with an official package's
name are matched too. OSV coverage follows the table above: Alpine, Fedora, SLES, Snap
and Flatpak are not assessed, and RHEL packages outside BaseOS and AppStream (CodeReady,
EUS streams) are not matched. Python, npm and Cargo coverage is limited to what the
collectors find (immediate `node_modules` entries, the configured `site-packages`
directories, binaries installed with `cargo install`), not dependencies vendored into
applications. Nothing here assesses exploitability or whether vulnerable code is running. An empty findings list is not a
clean bill of health: check feed status, assessment time and host freshness. This is a
triage tool, not a complete vulnerability scanner.

## Fleet deployment with systemd

| Host | Units (`examples/`) |
|---|---|
| Central | `software-inventory-server.service`, `software-inventory-assess.service`, `software-inventory-agent.service` |
| Every other host | `software-inventory-agent.service` |

1. On the central host, write the credentials file (mode 600) and enable the server
   and assess units. Put an HTTPS reverse proxy in front, or bind to a VPN address.
2. On each host, install the binary, `/etc/software-inventory-exporter/agent.toml`
   (from `examples/arch.toml`) and `/etc/software-inventory-exporter/agent.env`
   containing `INVENTORY_TOKEN=...` (mode 600, root). Set `--host-id` and `--server`
   in the agent unit; add `--ca-cert` for an internal CA.
3. `systemctl daemon-reload && systemctl enable --now software-inventory-agent`.

The agent unit uses `DynamicUser=yes`: no account to create, and read access to
`/var/lib/pacman` is enough. For Kubernetes, see [deploy/k3s](../deploy/k3s/README.md).

## Validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/smoke.py target/debug/software-inventory-exporter
python3 tests/central_smoke.py target/debug/software-inventory-exporter
python3 tests/tls_smoke.py target/debug/software-inventory-exporter   # needs openssl
```

The smoke tests run a real server, synthetic pacman, a local advisory feed, a fake NVD
API (including 503 and 429 responses) and an HTTPS endpoint with a private CA. They make
no network requests.
