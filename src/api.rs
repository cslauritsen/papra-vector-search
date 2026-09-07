use std::time::Instant;

use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{AppState, embeddings, storage, webhook};

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "auth_enabled": state.config.auth_enabled,
    }))
}

#[derive(Debug, Deserialize)]
pub struct OidcLoginQuery {
    pub format: Option<String>,
}

pub async fn oidc_login(
    State(state): State<AppState>,
    Query(query): Query<OidcLoginQuery>,
) -> Result<Response, ApiError> {
    let state_token = Uuid::new_v4().to_string();
    let authorization_url = state
        .auth
        .authorization_url(&state_token)
        .map_err(ApiError::internal)?;
    let mut response = if query.format.as_deref() == Some("json") {
        Json(json!({ "authorization_url": authorization_url })).into_response()
    } else {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::FOUND;
        response.headers_mut().insert(
            axum::http::header::LOCATION,
            authorization_url
                .parse()
                .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid OAuth URL")))?,
        );
        response
    };
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        format!("oidc_state={state_token}; Path=/oidc; HttpOnly; SameSite=Lax; Max-Age=600")
            .parse()
            .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid OAuth cookie")))?,
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = query.error {
        tracing::warn!(error = %error, "OIDC provider returned an error");
        return Err(ApiError::unauthorized("OIDC authorization was denied"));
    }
    let code = query
        .code
        .ok_or_else(|| ApiError::bad_request("missing OAuth authorization code"))?;
    let returned_state = query
        .state
        .ok_or_else(|| ApiError::bad_request("missing OAuth state"))?;
    let expected_state = cookie_value(&headers, "oidc_state")
        .ok_or_else(|| ApiError::unauthorized("missing OAuth state cookie"))?;
    if expected_state
        .as_bytes()
        .ct_eq(returned_state.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(ApiError::unauthorized("invalid OAuth state"));
    }
    let tokens = state
        .auth
        .exchange_code(&code)
        .await
        .map_err(ApiError::internal)?;
    let token_payload = serde_json::to_string(&tokens)
        .map_err(|error| ApiError::internal(anyhow::Error::new(error)))?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let callback_html = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Signing in…</title>\
         <p>Completing sign-in…</p><script>\
         const tokens = {token_payload};\
         if (window.opener) {{ window.opener.postMessage(tokens, '*'); window.close(); }}\
         else {{ document.querySelector('p').textContent = 'Sign-in complete. You can close this window.'; }}\
         </script>"
    );
    let mut response = Response::new(axum::body::Body::from(callback_html));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        "oidc_state=; Path=/oidc; HttpOnly; SameSite=Lax; Max-Age=0"
            .parse()
            .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid OAuth cookie")))?,
    );
    Ok(response)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

pub async fn papra_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    tracing::trace!(
        "webhook request received: headers={:?}",
        headers
    );
    
    let id = header(&headers, "webhook-id")?;
    let timestamp = header(&headers, "webhook-timestamp")?;
    let signature = headers
        .get("webhook-signature")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-signature").and_then(|v| v.to_str().ok()))
        .ok_or_else(|| ApiError::unauthorized("missing webhook signature"))?;
    
    tracing::trace!(
        webhook_id = %id,
        webhook_timestamp = %timestamp,
        webhook_signature = %signature,
        body_bytes = body.len(),
        "webhook signature validation started"
    );
    
    webhook::verify_signature(
        state.config.papra_webhook_secret.expose_secret().as_bytes(),
        &id,
        &timestamp,
        signature,
        &body,
        state.config.webhook_timestamp_tolerance_seconds,
        webhook::current_unix_time(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "webhook signature verification failed");
        ApiError::unauthorized(e.to_string())
    })?;
    
    tracing::trace!("webhook signature verified successfully");
    
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to parse webhook JSON payload");
            tracing::trace!(body_str = %String::from_utf8_lossy(&body), "raw body content");
            ApiError::bad_request("invalid JSON payload")
        })?;
    
    tracing::trace!(payload = %serde_json::to_string(&payload).unwrap_or_default(), "webhook payload parsed");
    
    let (_, mut input) = webhook::map_event(
        &payload,
        &state.config.papra_organization_id,
        state.config.papra_base_url.as_deref(),
        Utc::now().to_rfc3339(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to map webhook event");
        ApiError::bad_request(e.to_string())
    })?;
    
    if input.title.is_none() || input.content.is_none() {
        tracing::debug!(
            document_id = %input.papra_document_id,
            "document is missing title or content, fetching from Papra API"
        );
        if let Err(e) = enrich_document_from_papra(&state, &mut input).await {
            tracing::warn!(
                document_id = %input.papra_document_id,
                error = %e,
                "failed to fetch document from Papra API"
            );
        }
    }
    
    let canonical = {
        let storage = storage::lock(&state.storage).map_err(ApiError::internal)?;
        let mut input_for_resolution = input.clone();
        storage
            .resolve_input(&mut input_for_resolution)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        input = input_for_resolution;
        let should_embed = storage
            .needs_embedding(&input)
            .map_err(ApiError::internal)?;
        (
            should_embed,
            embeddings::canonical_embedding_input(
                input.title.as_deref().unwrap_or(""),
                input.content.as_deref().unwrap_or(""),
            ),
        )
    };
    let vector = if canonical.0 {
        let mut model = state
            .embeddings
            .lock()
            .map_err(|_| ApiError::internal(anyhow::anyhow!("embedding lock poisoned")))?;
        Some(embeddings::embed(&mut model, &canonical.1).map_err(ApiError::internal)?)
    } else {
        None
    };
    let mut storage = storage::lock(&state.storage).map_err(ApiError::internal)?;
    storage
        .upsert(&input, vector.as_deref())
        .map_err(ApiError::internal)?;
    Ok((StatusCode::OK, Json(json!({"status": "processed"}))))
}

async fn enrich_document_from_papra(
    state: &AppState,
    input: &mut storage::DocumentUpsert,
) -> Result<(), ApiError> {
    let document = crate::papra_api::fetch_document(
        state,
        &input.organization_id,
        &input.papra_document_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            document_id = %input.papra_document_id,
            error = %e,
            "Papra API fetch failed"
        );
        ApiError::internal(e)
    })?;
    
    if input.title.is_none() {
        input.title = document.name;
    }
    if input.content.is_none() {
        input.content = document.text;
    }
    
    tracing::debug!(
        document_id = %input.papra_document_id,
        has_title = input.title.is_some(),
        has_content = input.content.is_some(),
        "document enriched from Papra API"
    );
    
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub organization_id: String,
    pub papra_document_id: String,
    pub title: String,
    pub source_url: Option<String>,
    pub score: f32,
}

pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, ApiError> {
    let q = query.q.unwrap_or_default().trim().to_string();
    if q.is_empty() || q.chars().count() > 1_000 {
        state.metrics.search("invalid_query");
        return Err(ApiError::bad_request(
            "q must contain 1 to 1,000 characters",
        ));
    }
    let limit = query.limit.unwrap_or(state.config.search_result_limit);
    if limit == 0 || limit > 100 {
        state.metrics.search("invalid_query");
        return Err(ApiError::bad_request("limit must be between 1 and 100"));
    }
    if state.config.auth_enabled {
        state
            .auth
            .authenticate(headers.get("authorization").and_then(|v| v.to_str().ok()))
            .await
            .map_err(|_| {
                state.metrics.search("unauthorized");
                ApiError::unauthorized("authentication failed")
            })?;
    }
    let vector = {
        let mut model = state.embeddings.lock().map_err(|_| {
            state.metrics.search("error");
            ApiError::internal(anyhow::anyhow!("embedding lock poisoned"))
        })?;
        embeddings::embed(&mut model, &q).map_err(|error| {
            state.metrics.search("error");
            ApiError::internal(error)
        })?
    };
    let rows = storage::lock(&state.storage)
        .map_err(|error| {
            state.metrics.search("error");
            ApiError::internal(error)
        })?
        .search(&state.config.papra_organization_id, &vector, limit)
        .map_err(|error| {
            state.metrics.search("error");
            ApiError::internal(error)
        })?;
    state.metrics.search("success");
    Ok(Json(SearchResponse {
        results: rows
            .into_iter()
            .map(|r| SearchResult {
                organization_id: r.organization_id,
                papra_document_id: r.papra_document_id,
                title: r.title,
                source_url: r.source_url,
                score: r.score,
            })
            .collect(),
    }))
}

fn header(headers: &HeaderMap, name: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ApiError::bad_request(format!("missing or invalid {name} header")))
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }
    fn internal(_: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

pub async fn access_log(req: Request<axum::body::Body>, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().to_string();
    let route = match req.uri().path() {
        "/health" => "/health",
        "/api/search" => "/api/search",
        "/webhook/papra" => "/webhook/papra",
        _ => "/",
    };
    let metrics = req.extensions().get::<crate::telemetry::Metrics>().cloned();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    tracing::info!(%method, route, status, duration_ms = started.elapsed().as_millis() as u64, "http access");
    if let Some(metrics) = metrics {
        metrics.request(&method, route, status);
    }
    if status >= 400 {
        tracing::error!(%method, route, status, "http request failed");
    }
    response
}

pub fn route_name(method: &str, path: &str) -> &'static str {
    let _ = method;
    match path {
        "/health" => "/health",
        "/api/search" => "/api/search",
        "/webhook/papra" => "/webhook/papra",
        _ => "/",
    }
}
