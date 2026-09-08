use std::sync::{Arc, Mutex};

use anyhow::Result;
use papra_vector_search::{
    AppState, auth::Authenticator, config::Config, embeddings, storage::Storage, telemetry,
};

#[tokio::main]
async fn main() -> Result<()> {
    if std::path::Path::new(".env").exists() {
        dotenvy::dotenv()?;
        tracing::debug!("loaded environment from .env");
    }
    telemetry::init_logging();
    tracing::info!("starting Papra vector search");
    let config = Config::from_env()?;
    tracing::trace!(config = ?config, "validated configuration");
    let mut model = embeddings::initialize()?;
    let probe = embeddings::embed(&mut model, "dimension probe")?;
    let dimension = probe.len();
    if dimension == 0 {
        anyhow::bail!("embedding model returned a zero-dimensional vector");
    }
    let storage = Storage::open(
        &config.database_url,
        &config.sqlite_vec_extension_path,
        embeddings::MODEL_NAME,
        dimension,
    )?;
    let metrics = telemetry::Metrics::new(config.otel_exporter_endpoint.as_deref());
    let state = AppState {
        auth: Arc::new(Authenticator::new(&config)),
        config: Arc::new(config),
        storage: Arc::new(Mutex::new(storage)),
        embeddings: Arc::new(Mutex::new(model)),
        metrics,
        http: reqwest::Client::new(),
    };
    let worker_handle = tokio::runtime::Handle::current();
    let worker_state = state.clone();
    std::thread::Builder::new()
        .name("embedding-worker".into())
        .spawn(move || {
            worker_handle.block_on(papra_vector_search::api::embedding_worker(worker_state))
        })?;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!(address = %listener.local_addr()?, "server ready");
    axum::serve(listener, papra_vector_search::router(state)).await?;
    Ok(())
}
