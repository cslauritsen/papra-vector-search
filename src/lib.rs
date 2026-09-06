pub mod api;
pub mod auth;
pub mod config;
pub mod embeddings;
pub mod storage;
pub mod telemetry;
pub mod ui;
pub mod webhook;

use std::sync::{Arc, Mutex};

use axum::{Extension, Router, middleware, routing::get};
use fastembed::TextEmbedding;

use crate::{auth::Authenticator, config::Config, storage::Storage};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub storage: Arc<Mutex<Storage>>,
    pub embeddings: Arc<Mutex<TextEmbedding>>,
    pub auth: Arc<Authenticator>,
    pub metrics: telemetry::Metrics,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(api::health))
        .route("/ui", get(leptos_axum::render_app_to_stream(ui::App)))
        .route("/oidc/login", get(api::oidc_login))
        .route("/oidc/callback", get(api::oidc_callback))
        .route("/webhook/papra", axum::routing::post(api::papra_webhook))
        .route("/api/search", get(api::search))
        .layer(Extension(state.metrics.clone()))
        .layer(middleware::from_fn(api::access_log))
        .with_state(state)
}
