mod agent;
mod assessment;
mod collectors;
mod command;
mod config;
mod database;
mod fleet_metrics;
mod metrics;
mod model;
mod nvd;
mod protocol;
mod server;

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use clap::{Parser, Subcommand, ValueEnum};
use config::{Collector, Config, Kind};
use model::{CollectorState, Inventory};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(
    version,
    about = "Software inventory agent, central server, Arch assessment and Prometheus exporter"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Add a passive executable directory scan (repeatable).
    #[arg(long, global = true)]
    path: Vec<PathBuf>,
    /// Add current PATH directories, one level deep; does not execute their binaries.
    #[arg(long, global = true)]
    include_path: bool,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the central inventory API and SQLite database.
    Server {
        #[arg(long, default_value = "inventory.db")]
        database: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9899")]
        listen: String,
        #[arg(long)]
        credentials: PathBuf,
        /// Delete scan summaries older than this (checked hourly). Each host's
        /// latest scan is always kept so agent retries stay safe.
        #[arg(long, default_value_t = 86400)]
        scan_retention_seconds: u64,
    },
    /// Collect and reliably submit inventory to the central server.
    Agent(agent::Options),
    /// Assess stored inventory against the Arch security tracker.
    Assess(assessment::Options),
    /// Scan once. Exit code 2 indicates one or more failed collectors.
    Scan {
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
    },
    /// Serve cached /metrics, /inventory, /healthz and /readyz endpoints.
    Serve {
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        interval_seconds: Option<u64>,
    },
}
#[derive(Clone, ValueEnum)]
enum Format {
    Json,
    Metrics,
}

#[derive(Clone)]
struct Cache {
    json: Bytes,
    metrics: Bytes,
    ready: bool,
}
type Shared = Arc<RwLock<Cache>>;
fn cache(inv: &Inventory, config: &Config) -> Result<Cache> {
    Ok(Cache {
        json: serde_json::to_vec_pretty(inv)?.into(),
        metrics: metrics::render(inv, config).into(),
        ready: inv.initial_scan_complete,
    })
}
async fn inventory_handler(State(state): State<Shared>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        state.read().await.json.clone(),
    )
}
async fn metrics_handler(State(state): State<Shared>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.read().await.metrics.clone(),
    )
}
async fn ready_handler(State(state): State<Shared>) -> StatusCode {
    if state.read().await.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn scan(inv: &mut Inventory, config: &Config) {
    for c in &config.collectors {
        let timestamp = model::now();
        let start = Instant::now();
        let result = collectors::collect(c, config).await;
        if let Err(ref error) = result {
            eprintln!("collector {} failed: {error:#}", c.id);
        }
        inv.apply(c, result, timestamp, start.elapsed().as_secs_f64());
    }
    inv.initial_scan_complete = true;
}
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("register SIGTERM");
    tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = term.recv() => () }
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Action::Server {
        database,
        listen,
        credentials,
        scan_retention_seconds,
    } = &cli.command
    {
        return server::serve(
            database.clone(),
            listen,
            credentials,
            *scan_retention_seconds,
        )
        .await;
    }
    if let Action::Assess(options) = cli.command {
        return tokio::select! { result = assessment::run(options) => result, _ = shutdown() => Ok(()) };
    }
    let mut config = match cli.config {
        Some(path) => toml::from_str::<Config>(
            &std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
        )?,
        None => Config::default(),
    };
    for path in cli.path {
        config.collectors.push(Collector {
            id: format!("extra-{}", config.collectors.len()),
            kind: Kind::Filesystem,
            path,
            max_depth: 4,
        });
    }
    if cli.include_path {
        let mut paths: Vec<_> =
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .filter(|p| p.is_absolute())
                .collect();
        paths.sort();
        paths.dedup();
        for (index, path) in paths.into_iter().enumerate() {
            if !config
                .collectors
                .iter()
                .any(|c| c.kind == Kind::Filesystem && c.path == path)
            {
                config.collectors.push(Collector {
                    id: format!("path-{index}"),
                    kind: Kind::Filesystem,
                    path,
                    max_depth: 1,
                });
            }
        }
    }
    if let Action::Serve {
        listen,
        interval_seconds,
    } = &cli.command
    {
        if let Some(listen) = listen {
            config.listen = listen.clone();
        }
        if let Some(interval) = interval_seconds {
            config.interval_seconds = *interval;
        }
    }
    config.validate()?;
    let mut inv = Inventory {
        schema_version: 1,
        ..Inventory::default()
    };
    for c in &config.collectors {
        inv.collectors.insert(
            c.id.clone(),
            CollectorState {
                max_depth: c.max_depth,
                source: c.kind.name().into(),
                path: c.path.clone(),
                ..CollectorState::default()
            },
        );
    }
    match cli.command {
        Action::Server { .. } | Action::Assess(_) => unreachable!(),
        Action::Agent(options) => {
            tokio::select! {
                result = agent::run(options, config) => result?,
                _ = shutdown() => (),
            }
        }
        Action::Scan { format } => {
            scan(&mut inv, &config).await;
            match format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&inv)?),
                Format::Metrics => print!("{}", metrics::render(&inv, &config)),
            }
            if inv.collectors.values().any(|s| !s.success) {
                std::process::exit(2);
            }
        }
        Action::Serve { .. } => {
            let listener = tokio::net::TcpListener::bind(&config.listen).await?;
            eprintln!(
                "Listening on {}; scan interval {}s",
                listener.local_addr()?,
                config.interval_seconds
            );
            let state = Arc::new(RwLock::new(cache(&inv, &config)?));
            let worker_state = state.clone();
            let worker = tokio::spawn(async move {
                loop {
                    scan(&mut inv, &config).await;
                    match cache(&inv, &config) {
                        Ok(next) => *worker_state.write().await = next,
                        Err(e) => eprintln!("cannot encode inventory: {e}"),
                    }
                    // Delay after completion prevents overlap and catch-up storms.
                    tokio::time::sleep(Duration::from_secs(config.interval_seconds)).await;
                }
            });
            let app = Router::new()
                .route("/metrics", get(metrics_handler))
                .route("/inventory", get(inventory_handler))
                .route("/healthz", get(|| async { "ok\n" }))
                .route("/readyz", get(ready_handler))
                .with_state(state);
            let result = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown())
                .await;
            worker.abort();
            let _ = worker.await;
            result?;
        }
    }
    Ok(())
}
