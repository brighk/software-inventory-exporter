# Contributing

Thanks for helping. Bug reports, distro coverage and documentation fixes are all welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security problems: do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development

Requires stable Rust 1.95+, Python 3 and `openssl` (for the TLS test). Linux or macOS.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/smoke.py target/debug/software-inventory-exporter
python3 tests/central_smoke.py target/debug/software-inventory-exporter
python3 tests/tls_smoke.py target/debug/software-inventory-exporter
```

CI runs exactly these on Ubuntu and macOS, plus a container build. The smoke tests use
local fixtures and fake servers; they must never depend on the network.

To try the full system locally, see [local development](docs/operations.md#local-development).

## Code map

| File | Role |
|---|---|
| `src/main.rs` | CLI, standalone `scan` / `serve` exporter |
| `src/config.rs`, `src/collectors.rs`, `src/command.rs` | Collector config and parsers, bounded process execution |
| `src/model.rs`, `src/metrics.rs` | Inventory records; standalone exporter metrics |
| `src/agent.rs`, `src/protocol.rs` | Agent with durable delivery; versioned upload contract |
| `src/server.rs`, `src/database.rs`, `src/*.sql` | API, SQLite schema and migrations |
| `src/assessment.rs` | Arch tracker import and matching; the assessment pass |
| `src/osv.rs` | OSV.dev ecosystem mapping, queries, cache and findings |
| `src/nvd.rs` | NVD CVSS enrichment |
| `src/fleet_metrics.rs` | Central `/metrics` |
| `deploy/k3s/` | Kubernetes manifests and Grafana dashboard generator |

## Guidelines

- Fail closed: a collector or feed error must keep the last good data and stay visible,
  never silently replace good data with partial results.
- Don't overstate findings: uncertain matches are `needs_review`, not `affected`.
- Schema changes need a new `src/*-schema.sql` migration and a `user_version` bump.
- Add tests for new parsers, collectors and API behavior. Update the docs and
  `CHANGELOG.md` in the same pull request.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:` …).

## Adding vulnerability coverage for another distro

Arch uses the Arch security tracker (`src/assessment.rs`); everything else goes through
OSV.dev (`src/osv.rs`). If OSV publishes an ecosystem for the distribution (see
[ecosystems.txt](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)),
coverage is usually a new arm in `osv::queries`: map the os-release `ID`/`VERSION_ID` to
the ecosystem string and decide whether its advisories name binary or source packages.
Verify the mapping against the live API before opening a pull request. Alpine (`apk`) is
the obvious next one; it needs the origin package from the APK database.

## Releases

Maintainers tag `vX.Y.Z`. The release workflow publishes static binaries, a multi-arch
image to `ghcr.io/brighk/software-inventory-exporter`, and a GitHub release.
