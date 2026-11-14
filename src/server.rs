use crate::{
    database::Database,
    protocol::{MAX_BODY, Submission, valid_id},
};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

type ApiError = (StatusCode, &'static str);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    read_token: String,
    hosts: BTreeMap<String, String>,
}
#[derive(Clone)]
struct App {
    db: Arc<Mutex<Database>>,
    credentials: Arc<Credentials>,
}

fn matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(token) = headers
        .get("authorization")
        .and_then(|v: &axum::http::HeaderValue| v.to_str().ok())
        .and_then(|v: &str| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let actual: sha2::digest::Output<Sha256> = Sha256::digest(token.as_bytes());
    let expected: sha2::digest::Output<Sha256> = Sha256::digest(expected.as_bytes());
    actual
        .iter()
        .zip(expected)
        .fold(0u8, |diff: u8, (a, b): (&u8, u8)| diff | (a ^ b))
        == 0
}

async fn database<T: Send + 'static>(
    app: App,
    work: impl FnOnce(&mut Database) -> Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(move || -> Result<T> {
        let mut db: std::sync::MutexGuard<'_, Database> = app.db.lock().map_err(
            |_: std::sync::PoisonError<std::sync::MutexGuard<'_, Database>>| {
                anyhow::anyhow!("database lock poisoned")
            },
        )?;
        work(&mut db)
    })
    .await
    .map_err(|e: tokio::task::JoinError| {
        eprintln!("database task: {e}");
        (StatusCode::INTERNAL_SERVER_ERROR, "database unavailable")
    })?
    .map_err(|e: anyhow::Error| {
        if e.downcast_ref::<crate::database::Conflict>().is_some() {
            return (
                StatusCode::CONFLICT,
                "sequence conflict; preserve agent state and use one agent per host ID",
            );
        }
        eprintln!("database error: {e:#}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "database operation failed",
        )
    })
}

async fn ingest(
    State(app): State<App>,
    headers: HeaderMap,
    Json(payload): Json<Submission>,
) -> Result<Json<Value>, ApiError> {
    if !app
        .credentials
        .hosts
        .get(&payload.host.id)
        .is_some_and(|token: &String| matches(&headers, token))
    {
        return Err((StatusCode::UNAUTHORIZED, "invalid host credential"));
    }
    payload
        .validate()
        .map_err(|_: anyhow::Error| (StatusCode::BAD_REQUEST, "invalid submission"))?;
    let sequence: i64 = payload.sequence;
    let inserted: bool = database(app, move |db: &mut Database| db.ingest(&payload)).await?;
    Ok(Json(
        json!({"sequence":sequence,"accepted":true,"duplicate":!inserted}),
    ))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    host_id: Option<String>,
    name: Option<String>,
    /// Comma-separated effective statuses, e.g. affected,needs_review.
    status: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}
impl Filter {
    fn page(&self) -> Result<(i64, i64), ApiError> {
        let limit: i64 = self.limit.unwrap_or(100);
        let offset: i64 = self.offset.unwrap_or(0);
        if !(1..=1000).contains(&limit) || offset < 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                "limit must be 1..1000 and offset nonnegative",
            ));
        }
        Ok((limit, offset))
    }
}
fn authorize_read(app: &App, headers: &HeaderMap) -> Result<(), ApiError> {
    if !matches(headers, &app.credentials.read_token) {
        return Err((StatusCode::UNAUTHORIZED, "read credential required"));
    }
    Ok(())
}
async fn hosts(
    State(app): State<App>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&app, &headers)?;
    if filter.status.is_some() {
        return Err((StatusCode::BAD_REQUEST, "status applies only to findings"));
    }
    let (limit, offset): (i64, i64) = filter.page()?;
    let rows: Vec<Value> = database(app, move |db: &mut Database| db.hosts(limit, offset)).await?;
    Ok(Json(json!({"hosts":rows,"limit":limit,"offset":offset})))
}
async fn installations(
    State(app): State<App>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&app, &headers)?;
    if filter.status.is_some() {
        return Err((StatusCode::BAD_REQUEST, "status applies only to findings"));
    }
    let (limit, offset): (i64, i64) = filter.page()?;
    let rows: Vec<Value> = database(app, move |db: &mut Database| {
        db.installations(
            filter.host_id.as_deref(),
            filter.name.as_deref(),
            limit,
            offset,
        )
    })
    .await?;
    Ok(Json(
        json!({"installations":rows,"limit":limit,"offset":offset}),
    ))
}
async fn collectors(
    State(app): State<App>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&app, &headers)?;
    let host: String = filter
        .host_id
        .ok_or((StatusCode::BAD_REQUEST, "host_id required"))?;
    let rows: Vec<Value> = database(app, move |db: &mut Database| db.collectors(&host)).await?;
    Ok(Json(json!({"collectors":rows})))
}

const STATUSES: [&str; 7] = [
    "affected",
    "needs_review",
    "no_known_match",
    "unsupported",
    "not_assessed",
    "pending",
    "stale_inventory",
];

async fn findings(
    State(app): State<App>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&app, &headers)?;
    let (limit, offset): (i64, i64) = filter.page()?;
    if let Some(status) = &filter.status
        && !status.split(',').all(|s: &str| STATUSES.contains(&s))
    {
        return Err((StatusCode::BAD_REQUEST, "unknown assessment status"));
    }
    let rows: Vec<Value> = database(app, move |db: &mut Database| {
        db.findings(
            filter.host_id.as_deref(),
            filter.status.as_deref(),
            limit,
            offset,
        )
    })
    .await?;
    Ok(Json(
        json!({"assessments":rows,"limit":limit,"offset":offset}),
    ))
}
async fn assessment_status(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize_read(&app, &headers)?;
    Ok(Json(
        database(app, |db: &mut Database| db.assessment_status()).await?,
    ))
}

/// How often expired scan summaries are deleted.
const PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

/// Prometheus exposition of the whole inventory; requires the read credential.
async fn metrics(
    State(app): State<App>,
    headers: HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], String), ApiError> {
    authorize_read(&app, &headers)?;
    let body: String = database(app, |db: &mut Database| db.render_metrics()).await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

pub async fn serve(
    path: PathBuf,
    listen: &str,
    credentials: &Path,
    scan_retention_seconds: u64,
) -> Result<()> {
    if scan_retention_seconds == 0 || scan_retention_seconds > i64::MAX as u64 {
        bail!("scan retention must be positive");
    }
    let credentials: Credentials = serde_json::from_slice::<Credentials>(
        &std::fs::read(credentials).context("read server credentials")?,
    )?;
    let mut tokens: HashSet<&String> = HashSet::new();
    for token in std::iter::once(&credentials.read_token).chain(credentials.hosts.values()) {
        if token.len() < 32
            || !token.bytes().all(|b: u8| b.is_ascii_graphic())
            || !tokens.insert(token)
        {
            bail!("credentials must be unique tokens of at least 32 printable ASCII characters");
        }
    }
    if credentials.hosts.keys().any(|id: &String| !valid_id(id)) {
        bail!("invalid credential host ID");
    }
    let db: Database =
        tokio::task::spawn_blocking(move || -> Result<Database> { Database::open(&path) })
            .await??;
    let app: App = App {
        db: Arc::new(Mutex::new(db)),
        credentials: Arc::new(credentials),
    };
    let pruner: tokio::task::JoinHandle<()> = {
        let db: Arc<Mutex<Database>> = app.db.clone();
        tokio::spawn(async move {
            let mut tick: tokio::time::Interval = tokio::time::interval(PRUNE_EVERY);
            loop {
                tick.tick().await;
                let db: Arc<Mutex<Database>> = db.clone();
                let result: Result<Result<usize>, tokio::task::JoinError> =
                    tokio::task::spawn_blocking(move || -> Result<usize> {
                        let cutoff: i64 = (crate::model::now() as i64)
                            .saturating_sub(scan_retention_seconds as i64);
                        db.lock()
                            .map_err(
                                |_: std::sync::PoisonError<std::sync::MutexGuard<'_, Database>>| {
                                    anyhow::anyhow!("database lock poisoned")
                                },
                            )?
                            .prune_scans(cutoff)
                    })
                    .await;
                match result {
                    Ok(Ok(0)) => {}
                    Ok(Ok(n)) => eprintln!("Pruned {n} expired scan summaries"),
                    Ok(Err(e)) => eprintln!("scan pruning failed: {e:#}"),
                    Err(e) => eprintln!("scan pruning task: {e}"),
                }
            }
        })
    };
    let router: Router = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/metrics", get(metrics))
        .route("/v1/inventory", post(ingest))
        .route("/v1/findings", get(findings))
        .route("/v1/assessment-status", get(assessment_status))
        .route("/v1/hosts", get(hosts))
        .route("/v1/installations", get(installations))
        .route("/v1/collectors", get(collectors))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(app);
    let listener: tokio::net::TcpListener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("Inventory server listening on {}", listener.local_addr()?);
    let result: std::io::Result<()> = axum::serve(listener, router)
        .with_graceful_shutdown(crate::shutdown())
        .await;
    pruner.abort();
    Ok(result?)
}
