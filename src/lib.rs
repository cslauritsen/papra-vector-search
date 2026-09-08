//! Papra document vector indexing and search service.

#[cfg(not(target_arch = "wasm32"))]
/// HTTP API handlers.
pub mod api;
#[cfg(target_arch = "wasm32")]
/// Leptos client application.
pub mod app;
#[cfg(not(target_arch = "wasm32"))]
/// OAuth authentication support.
pub mod auth;
#[cfg(not(target_arch = "wasm32"))]
/// Environment-based application configuration.
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
/// Embedding model helpers.
pub mod embeddings;
#[cfg(not(target_arch = "wasm32"))]
/// Papra API client.
pub mod papra_api;
#[cfg(not(target_arch = "wasm32"))]
/// SQLite document and job storage.
pub mod storage;
#[cfg(not(target_arch = "wasm32"))]
/// Metrics and logging setup.
pub mod telemetry;
#[cfg(not(target_arch = "wasm32"))]
/// Papra webhook validation and mapping.
pub mod webhook;

#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};

#[cfg(not(target_arch = "wasm32"))]
use axum::{Extension, Router, middleware, routing::get};
#[cfg(not(target_arch = "wasm32"))]
use fastembed::TextEmbedding;
#[cfg(not(target_arch = "wasm32"))]
use tower_http::services::ServeDir;

#[cfg(not(target_arch = "wasm32"))]
use crate::{auth::Authenticator, config::Config, storage::Storage};

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
/// Shared state used by HTTP handlers and the embedding worker.
pub struct AppState {
    /// Application configuration.
    pub config: Arc<Config>,
    /// SQLite-backed document and job storage.
    pub storage: Arc<Mutex<Storage>>,
    /// Loaded embedding model.
    pub embeddings: Arc<Mutex<TextEmbedding>>,
    /// OAuth authenticator.
    pub auth: Arc<Authenticator>,
    /// Application metrics.
    pub metrics: telemetry::Metrics,
    /// HTTP client for Papra and identity-provider requests.
    pub http: reqwest::Client,
}

#[cfg(not(target_arch = "wasm32"))]
/// Builds the HTTP router and attaches the shared application state.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(api::health))
        .route("/oidc/login", get(api::oidc_login))
        .route("/oidc/callback", get(api::oidc_callback))
        .route("/webhook/papra", axum::routing::post(api::papra_webhook))
        .route("/api/search", get(api::search))
        .route(
            "/api/embeddings/batch",
            axum::routing::post(api::enqueue_batch),
        )
        .layer(Extension(state.metrics.clone()))
        .layer(middleware::from_fn(api::access_log))
        .fallback_service(
            ServeDir::new("dist").fallback(tower_http::services::ServeFile::new("dist/index.html")),
        )
        .with_state(state)
}

#[cfg(all(target_arch = "wasm32", feature = "csr"))]
#[wasm_bindgen::prelude::wasm_bindgen]
/// Mounts the Leptos frontend into the document body.
pub fn mount() {
    leptos::mount::mount_to_body(|| leptos::view! { <app::App/> });
}
