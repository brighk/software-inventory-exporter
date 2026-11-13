# Central inventory development

The same Rust binary now provides five independent roles:

- `scan`: inspect once and print JSON or metrics (existing behavior).
- `serve`: periodically collect and serve local exporter endpoints (existing behavior).
- `server`: receive inventory and provide authenticated database queries.
- `agent`: collect and push complete snapshots, with a durable pending submission.
- `assess`: periodically import Arch advisories and assess the central inventory.

Develop and test all roles on macOS. The real Arch host uses the pacman collector;
macOS does not require pacman or libalpm. The assessment worker uses the
[Arch ALPM Rust types](https://docs.rs/alpm-types/0.14.0/alpm_types/struct.Version.html)
for version comparison. Rust 1.95 or later is required by that dependency; CI
uses stable Rust. SQLite is bundled, so no database service or SQLite development
headers are needed.

## Run locally on the Mac

From the repository root:

```sh
cargo build --locked
python3 examples/setup_dev.py
```

The setup script creates `dev-data/` and refuses to overwrite an existing directory.
It generates separate random read and per-host upload credentials and a synthetic
npm package. This is a development fixture, not discovery of all Mac applications.
`dev-data/` is ignored by Git.

Terminal 1 — server:

```sh
./target/debug/software-inventory-exporter server \
  --database dev-data/inventory.db \
  --credentials dev-data/credentials.json
```

Terminal 2 — agent:

```sh
export INVENTORY_TOKEN="$(python3 -c 'import json; print(json.load(open("dev-data/credentials.json"))["hosts"]["mac-dev"])')"
./target/debug/software-inventory-exporter --config dev-data/mac.toml agent \
  --server http://127.0.0.1:9899 \
  --host-id mac-dev --hostname mac-dev --os macos --os-version development \
  --state dev-data/mac-state.json --once
```

Remove `--once` for continuous scans. Edit the fixture's package.json version and
submit again to observe replacement. Remove its `demo` directory and resubmit to
observe removal. Broken metadata causes a failed collector; its previous database
records remain. All packages are uploaded regardless of Prometheus filters.

Terminal 3 — queries:

```sh
export INVENTORY_READ_TOKEN="$(python3 -c 'import json; print(json.load(open("dev-data/credentials.json"))["read_token"])')"
curl --fail -H "Authorization: Bearer $INVENTORY_READ_TOKEN" \
  http://127.0.0.1:9899/v1/hosts
curl --fail -H "Authorization: Bearer $INVENTORY_READ_TOKEN" \
  'http://127.0.0.1:9899/v1/installations?host_id=mac-dev'
curl --fail -H "Authorization: Bearer $INVENTORY_READ_TOKEN" \
  'http://127.0.0.1:9899/v1/installations?name=demo'
curl --fail -H "Authorization: Bearer $INVENTORY_READ_TOKEN" \
  'http://127.0.0.1:9899/v1/collectors?host_id=mac-dev'
```

`hosts`, `installations`, and `findings` accept `limit` (1–1000; default 100) and
`offset` (default 0). Installations support exact `host_id` and `name` filters.
Findings support `host_id`. Follow pagination to obtain a complete list. Pagination
is not a snapshot across concurrent writes.

## Connect the Arch machine

Build the binary on Arch with `cargo build --release --locked`; the Mac executable
cannot run on Linux. Use `examples/arch.toml`, which collects **all installed pacman
packages, including dependencies**. Upload credentials are provisioned by stable
host ID in the server JSON file. The development setup includes `arch-01` for this
purpose; transfer only that host's upload token to Arch, not the read token or
other hosts' tokens. The server reads credentials at startup; restart it to rotate
credentials or provision hosts.

Use HTTPS through a reverse proxy for remote connections. The Rust server itself
serves HTTP and defaults to loopback. For development, an SSH tunnel from Arch to
the Mac lets the agent retain a loopback HTTP URL:

```sh
# On Arch; replace MAC_USER and MAC_ADDRESS. Requires SSH access to the Mac.
ssh -N -L 9899:127.0.0.1:9899 MAC_USER@MAC_ADDRESS
```

In another Arch terminal, set `INVENTORY_TOKEN` securely, then run:

```sh
./target/release/software-inventory-exporter --config examples/arch.toml agent \
  --server http://127.0.0.1:9899 \
  --host-id arch-01 --hostname YOUR_ARCH_HOSTNAME --os arch --os-version rolling \
  --state /ABSOLUTE/WRITABLE/PRIVATE/DIRECTORY/agent-state.json
```

Host metadata is explicit configuration, not auto-detected. Use real values on
real hosts. Keep each host's ID stable and unique. Never clone an agent state file
onto another host. `os=arch` selects Arch assessment; other distributions must not
be labeled Arch just because they use pacman.

## Delivery and database semantics

The agent stores a sequence counter and at most one pending snapshot in its state
file. It writes and syncs the snapshot before transmission, and clears it only
after a matching acknowledgment. A file lock prevents two processes using the same
state file. Network/server failures retain the snapshot and continuous mode retries
after the configured interval. While a snapshot is pending, new scans wait; this is
a current-inventory system, not a complete observation history.

`--once` retries pending data first and then exits. Run it again for a fresh scan.
It exits nonzero on delivery failure or if a delivered snapshot includes failed
collectors. Authentication, malformed requests, and sequence conflicts stop the
agent with the pending snapshot intact. Fix the cause and restart it.

Keep the state file across restarts and upgrades. Do not delete it to resolve a
conflict: resetting the counter cannot overwrite newer server records. Recovery
from lost state requires an operator to recover the original state or provision a
new host ID. Use one agent per host ID and a private writable state directory.

The server uses one SQLite database with shared tables:

| Table | Content |
|---|---|
| `hosts` | Stable identity, OS metadata, server receipt time, latest sequence |
| `scans` | Accepted sequence, receipt time, success and payload digest |
| `collectors` | Latest attempt, last success, error, active configuration status |
| `installations` | Complete current or last-known records per host/collector |
| `advisories` | Latest successfully imported Arch advisory records |
| `assessments` | Per-installation assessment and advisory/CVE matches |
| `assessment_state` | Worker success, timestamps, source, feed digest and error |

A snapshot is applied in one transaction. Successful collectors replace their
records; a successful empty result clears them. Failed collectors retain server-side
records and never seed the database from agent-side cached data. Collectors omitted
from a later configuration become inactive and retain records for inspection.
Queries expose collector success and activity. Hosts that stop reporting retain
inventory; consumers must check `last_seen` against their required freshness.

Identical retries are accepted without adding scans or changing freshness.
Sequence reuse with changed content and unseen older sequences return HTTP 409.
Ordering uses the persisted counter, not the host clock. Observation timestamps
still depend on the host clock; host `last_seen` uses server receipt time.

Schema migrations run automatically at database open (`PRAGMA user_version`).
Back up the database before upgrades. This version stores scan summaries, not
historical software snapshots. Scan summaries currently have no retention policy.
SQLite WAL supports the API and local assessment process sharing the database;
use a local disk, not a network filesystem. This is a single-server starting point,
not a high-availability deployment.

## Initial Arch vulnerability assessment

Run a separate process beside the server, using the same database path:

```sh
./target/debug/software-inventory-exporter assess \
  --database dev-data/inventory.db --once
```

Omit `--once` to refresh and assess hourly, or set `--interval-seconds`. The worker
re-evaluates all stored installations on each pass, so new inventory is assessed
on the next pass. It imports the [Arch security tracker feed](https://security.archlinux.org/issues/all.json).
Feed downloads have timeout/size limits. Failed imports preserve the last successful
results and record failure in `/v1/assessment-status`.

```sh
curl --fail -H "Authorization: Bearer $INVENTORY_READ_TOKEN" \
  http://127.0.0.1:9899/v1/assessment-status
curl --fail -H "Authorization: Bearer $INVENTORY_READ_TOKEN" \
  'http://127.0.0.1:9899/v1/findings?host_id=arch-01'
```

Despite the endpoint name, `findings` returns an assessment for **every current
installation**, including unsupported/unassessed installations. Each has a
`findings` array with advisory ID, CVE aliases, severity and fixed version.

| Status | Meaning |
|---|---|
| `affected` | Exact affected version matched an advisory marked Vulnerable or Fixed |
| `needs_review` | Potential match; range, version or tracker status is uncertain |
| `no_known_match` | No applicable match in the imported feed; **not proof of safety** |
| `unsupported` | Host is not Arch or collector is not pacman |
| `not_assessed` | No assessment for this installation/version, or unknown version |
| `pending` | Inventory sequence changed since the stored assessment |
| `stale_inventory` | Collector failed or is inactive |

The tracker supplies an affected version, not a guaranteed introduction bound.
Versions below a known fixed version are therefore review candidates, not
unconditionally confirmed vulnerabilities. Unknown tracker status also requires
review. Versions at or above a valid fixed version are excluded using ALPM version
ordering, including epochs and package releases.

**Coverage limits:** this initial matcher does not establish whether a package is
from an official repository or AUR, does not cover every AUR/custom package, and
does not assess exploitability or whether vulnerable code is running. Package-name
matches for custom builds need review. It does not assess npm, Python, Debian or
RPM packages yet. The Mac npm fixture correctly reports `unsupported`.

A successful feed download proves retrieval, not that the tracker is complete or
up to date. The feed has no source freshness guarantee in this implementation.
Check worker status, assessment timestamp, host freshness and source coverage;
do not treat an empty findings list as a clean security bill. This is an initial
triage tool, not a production vulnerability scanner.

## Repeatable validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/smoke.py target/debug/software-inventory-exporter
python3 tests/central_smoke.py target/debug/software-inventory-exporter
```

The central smoke test runs a temporary server, a synthetic pacman command and a
local advisory feed on macOS or Linux. It tests offline/restart delivery, credentials,
retry identity, updates, removals, collector failures, and assessment invalidation.
It does not access the real Arch host or download a live advisory feed. For manual
fixture assessment, use `assess --feed-file /absolute/path/to/arch-feed.json`.
