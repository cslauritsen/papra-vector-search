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

/// Returns service health and authentication status.
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

/// Starts the OAuth login flow.
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

/// Completes the OAuth login flow and returns the token payload.
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

/// Validates and queues a Papra webhook for asynchronous processing.
pub async fn papra_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    tracing::trace!("webhook request received: headers={:?}", headers);

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

    let payload: Value = serde_json::from_slice(&body).map_err(|e| {
        tracing::error!(error = %e, "failed to parse webhook JSON payload");
        tracing::trace!(body_str = %String::from_utf8_lossy(&body), "raw body content");
        ApiError::bad_request("invalid JSON payload")
    })?;

    tracing::trace!(payload = %serde_json::to_string(&payload).unwrap_or_default(), "webhook payload parsed");

    validate_webhook_payload(&payload, &state.config.papra_organization_id)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;

    let document_id = payload["data"]["documentId"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("missing documentId in webhook payload"))?;
    storage::lock(&state.storage)
        .map_err(ApiError::internal)?
        .enqueue_embedding(document_id, &Utc::now().to_rfc3339())
        .map_err(ApiError::internal)?;

    Ok((StatusCode::ACCEPTED, Json(json!({"status": "accepted"}))))
}

#[derive(Debug, Deserialize)]
pub struct BatchEmbeddingRequest {
    pub document_ids: Vec<String>,
}

/// Queues multiple document IDs for authenticated batch embedding.
pub async fn enqueue_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BatchEmbeddingRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if state.config.auth_enabled {
        state
            .auth
            .authenticate(headers.get("authorization").and_then(|v| v.to_str().ok()))
            .await
            .map_err(|_| ApiError::unauthorized("authentication failed"))?;
    }
    if request.document_ids.is_empty() || request.document_ids.iter().any(|id| id.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "document_ids must contain at least one non-empty ID",
        ));
    }
    let received_at = Utc::now().to_rfc3339();
    let mut storage = storage::lock(&state.storage).map_err(ApiError::internal)?;
    for document_id in &request.document_ids {
        storage
            .enqueue_embedding(document_id, &received_at)
            .map_err(ApiError::internal)?;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "accepted", "count": request.document_ids.len()})),
    ))
}

fn validate_webhook_payload(payload: &Value, expected_org: &str) -> anyhow::Result<()> {
    let data = payload
        .get("data")
        .ok_or_else(|| anyhow::anyhow!("missing data field in webhook payload"))?;
    let doc_id = data
        .get("documentId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing documentId in webhook payload"))?;
    let org_id = data
        .get("organizationId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing organizationId in webhook payload"))?;
    if org_id != expected_org {
        return Err(anyhow::anyhow!(
            "webhook organization {} does not match configured organization {}",
            org_id,
            expected_org
        ));
    }
    tracing::debug!(document_id = %doc_id, organization_id = %org_id, "webhook payload validated");
    Ok(())
}

/// Polls and processes one eligible embedding job at a time.
pub async fn embedding_worker(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let cutoff = (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        let job = match storage::lock(&state.storage)
            .and_then(|mut storage| storage.claim_embedding_job(&cutoff))
        {
            Ok(job) => job,
            Err(error) => {
                tracing::error!(error = %error, "failed to claim embedding job");
                continue;
            }
        };
        let Some(job) = job else {
            continue;
        };
        let payload = json!({
            "data": {
                "documentId": job.document_id,
                "organizationId": state.config.papra_organization_id
            }
        });
        match process_webhook_document(state.clone(), payload).await {
            Ok(()) => {
                if let Err(error) = storage::lock(&state.storage)
                    .and_then(|mut storage| storage.finish_embedding_job(&job))
                {
                    tracing::error!(error = %error, document_id = %job.document_id, "failed to finish embedding job");
                }
            }
            Err(error) => {
                tracing::error!(error = %error, document_id = %job.document_id, "embedding job failed");
                if let Err(storage_error) = storage::lock(&state.storage).and_then(|mut storage| {
                    storage.fail_embedding_job(
                        &job,
                        &error.to_string(),
                        std::time::Duration::from_secs(60),
                    )
                }) {
                    tracing::error!(error = %storage_error, document_id = %job.document_id, "failed to update embedding job failure");
                }
            }
        }
    }
}

async fn process_webhook_document(state: AppState, payload: Value) -> anyhow::Result<()> {
    let org_id = &state.config.papra_organization_id;
    let document = extract_and_fetch_document(&state, &payload, org_id).await?;
    tracing::debug!(
        document_id = %document.papra_document_id,
        has_title = document.title.is_some(),
        has_content = document.content.is_some(),
        "document ready for indexing"
    );
    let canonical = {
        let storage = storage::lock(&state.storage)?;
        let mut input_for_resolution = document.clone();
        storage.resolve_input(&mut input_for_resolution)?;
        let should_embed = storage.needs_embedding(&input_for_resolution)?;
        (
            should_embed,
            embeddings::canonical_embedding_input(
                input_for_resolution.title.as_deref().unwrap_or(""),
                input_for_resolution.content.as_deref().unwrap_or(""),
            ),
        )
    };
    let vector = if canonical.0 {
        let mut model = state
            .embeddings
            .lock()
            .map_err(|_| anyhow::anyhow!("embedding lock poisoned"))?;
        Some(embeddings::embed(&mut model, &canonical.1)?)
    } else {
        None
    };
    let mut storage = storage::lock(&state.storage)?;
    storage.upsert(&document, vector.as_deref())?;
    Ok(())
}

async fn extract_and_fetch_document(
    state: &AppState,
    payload: &Value,
    expected_org: &str,
) -> anyhow::Result<storage::DocumentUpsert> {
    let data = payload
        .get("data")
        .ok_or_else(|| anyhow::anyhow!("missing data field in webhook payload"))?;

    let doc_id = data
        .get("documentId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing documentId in webhook payload"))?;

    let org_id = data
        .get("organizationId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing organizationId in webhook payload"))?;

    if org_id != expected_org {
        return Err(anyhow::anyhow!(
            "webhook organization {} does not match configured organization {}",
            org_id,
            expected_org
        ));
    }

    tracing::debug!(
        document_id = %doc_id,
        organization_id = %org_id,
        "fetching document from Papra API"
    );

    let papra_doc = crate::papra_api::fetch_document(state, org_id, doc_id).await?;

    tracing::trace!(
        document_id = %doc_id,
        papra_name = ?papra_doc.name,
        papra_content_len = ?papra_doc.content.as_ref().map(|t| t.len()),
        "fetched document from Papra API"
    );

    let hash = papra_doc
        .content
        .as_deref()
        .map(embeddings::content_hash)
        .unwrap_or_else(|| String::new());

    let title_for_hash = papra_doc.name.as_deref().unwrap_or("");
    let content_for_hash = papra_doc.content.as_deref().unwrap_or("");
    let input_hash = embeddings::embedding_input_hash(title_for_hash, content_for_hash);

    Ok(storage::DocumentUpsert {
        organization_id: org_id.to_string(),
        papra_document_id: doc_id.to_string(),
        title: papra_doc.name,
        content: papra_doc.content,
        content_hash: hash,
        embedding_input_hash: input_hash,
        tags: None,
        attributes: None,
        source_url: None,
        embedding_model: embeddings::MODEL_NAME.to_string(),
        updated_at: Utc::now().to_rfc3339(),
    })
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
    pub papra_base_url: Option<String>,
    pub score: f32,
}

/// Executes a vector search query against the configured organization.
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
                papra_base_url: state.config.papra_base_url.clone(),
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

/// Logs HTTP requests and records request metrics.
pub async fn access_log(req: Request<axum::body::Body>, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().to_string();
    let route = match req.uri().path() {
        "/health" => "/health",
        "/api/search" => "/api/search",
        "/api/embeddings/batch" => "/api/embeddings/batch",
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

/// Maps an HTTP method and path to the canonical metrics route name.
pub fn route_name(method: &str, path: &str) -> &'static str {
    let _ = method;
    match path {
        "/health" => "/health",
        "/api/search" => "/api/search",
        "/api/embeddings/batch" => "/api/embeddings/batch",
        "/webhook/papra" => "/webhook/papra",
        _ => "/",
    }
}
