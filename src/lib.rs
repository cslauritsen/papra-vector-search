#[cfg(not(target_arch = "wasm32"))]
pub mod api;
#[cfg(target_arch = "wasm32")]
pub mod app;
#[cfg(not(target_arch = "wasm32"))]
pub mod auth;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod embeddings;
#[cfg(not(target_arch = "wasm32"))]
pub mod storage;
#[cfg(not(target_arch = "wasm32"))]
pub mod telemetry;
#[cfg(not(target_arch = "wasm32"))]
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
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Arc<Mutex<Storage>>,
    pub embeddings: Arc<Mutex<TextEmbedding>>,
    pub auth: Arc<Authenticator>,
    pub metrics: telemetry::Metrics,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(api::health))
        .route("/oidc/login", get(api::oidc_login))
        .route("/oidc/callback", get(api::oidc_callback))
        .route("/webhook/papra", axum::routing::post(api::papra_webhook))
        .route("/api/search", get(api::search))
        .layer(Extension(state.metrics.clone()))
        .layer(middleware::from_fn(api::access_log))
        .fallback_service(
            ServeDir::new("dist").fallback(tower_http::services::ServeFile::new("dist/index.html")),
        )
        .with_state(state)
}

#[cfg(all(target_arch = "wasm32", feature = "csr"))]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn mount() {
    leptos::mount::mount_to_body(|| leptos::view! { <app::App/> });
}
