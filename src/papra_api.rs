use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use secrecy::ExposeSecret;

use crate::AppState;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PapraDocument {
    pub id: String,
    pub name: Option<String>,
    pub organization_id: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PapraDocumentResponse {
    pub document: PapraDocument,
}

/// Fetches a document from the configured Papra API.
pub async fn fetch_document(
    state: &AppState,
    org_id: &str,
    document_id: &str,
) -> Result<PapraDocument> {
    let url = state
        .config
        .papra_api_base
        .join(&format!("organizations/{org_id}/documents/{document_id}"))
        .map_err(|e| anyhow!("failed to construct Papra API URL: {e}"))?;

    tracing::trace!(
        method = "GET",
        url = %url,
        organization_id = %org_id,
        document_id = %document_id,
        "fetching document from Papra API"
    );

    let response = state
        .http
        .get(url.clone())
        .bearer_auth(state.config.papra_api_key.expose_secret())
        .send()
        .await
        .map_err(|e| anyhow!("Papra API request failed: {e}"))?;

    let status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| anyhow!("failed to read Papra API response body: {e}"))?;

    tracing::trace!(
        method = "GET",
        status = %status,
        url = %url,
        response_body = %response_body,
        "received Papra API response"
    );

    if !status.is_success() {
        return Err(anyhow!(
            "Papra API request failed with status {}: {}",
            status,
            response_body
        ));
    }

    serde_json::from_str::<PapraDocumentResponse>(&response_body)
        .map(|response| response.document)
        .map_err(|e| anyhow!("failed to parse Papra API response: {e}"))
}
