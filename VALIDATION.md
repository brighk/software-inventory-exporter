# Validation — 2026-11-13

Executed in a Linux x86_64 development environment with Rust 1.100.0:

- `cargo fmt --check`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo test --locked`: 10 unit tests passed.
- `cargo build --release --locked`: passed.
- `python3 tests/smoke.py ...`: passed against debug and release executables.
  Checked live JSON/metrics endpoints, readiness, version changes, stable IDs,
  failed-scan cache retention, successful removal, unknown-route 404, graceful
  SIGTERM, and scan exit code 2 with structured failure output.
- Parsed generated metrics with the Prometheus Python client parser: all seven
  families accepted; quotes and backslashes in labels survived a round trip.
- Live filesystem scans of `/usr/local/bin` and `/opt` succeeded.
- Live dpkg invocation succeeded but the environment's package database contained
  no records. Nonempty dpkg data was tested with fixtures, not a real installed
  package set.

RPM, pacman, APK, Snap and Flatpak parsers were tested with representative
fixtures. Python, npm and Cargo collectors were tested with temporary on-disk
metadata. Full real-host integration for those systems, permissions under the
provided systemd unit, a real Prometheus scrape, fleet scale, and long-duration
operation have not been validated. The example alert rules were not evaluated
by a running Prometheus server.

No deployment, package installation on your hosts, or changes to your Prometheus
configuration were performed. The archive contains source and examples; build
artifacts and machine-specific scan results are excluded.


## Central inventory extension — macOS, 2026-11-13

Executed locally with Rust 1.99.1:

- `cargo fmt --check`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo test --locked`: 13 tests passed, including database ordering, retry
  identity, failed-collector retention, inactive collectors, persistence, multiple
  package versions, and Arch epoch/release comparisons.
- `cargo build --locked`: passed.
- Existing `tests/smoke.py`: passed on macOS.
- New `tests/central_smoke.py`: passed on macOS. Exercised a real loopback API,
  per-host authorization, durable upload after a server outage and agent restart,
  duplicate/conflicting submissions, inventory updates and removals, failed
  collection, assessment fixtures, failed feed import, assessment invalidation,
  API validation and database persistence.
- Live Arch feed downloaded and imported into a temporary database: 2,444
  advisory records accepted. This confirms feed compatibility, not completeness
  or source freshness. No real host vulnerability assessment was performed.

CI now has Ubuntu and macOS jobs running the same checks; those remote jobs have
not been executed in this session. The Arch machine was not accessed and no
service was deployed. Real pacman output and the eventual network deployment
still need validation on that host. Tests use a synthetic pacman executable and
advisory fixtures. The original validation notes above describe the earlier archive.
