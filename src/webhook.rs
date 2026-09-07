use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hex;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    embeddings::{content_hash, embedding_input_hash},
    storage::DocumentUpsert,
};

type HmacSha256 = Hmac<Sha256>;

pub fn verify_signature(
    secret: &[u8],
    webhook_id: &str,
    timestamp: &str,
    signature: &str,
    body: &[u8],
    tolerance_seconds: i64,
    now: i64,
) -> Result<()> {
    tracing::trace!(
        webhook_id = %webhook_id,
        timestamp = %timestamp,
        signature_prefix = %signature.chars().take(20).collect::<String>(),
        body_len = body.len(),
        tolerance_seconds = tolerance_seconds,
        now = now,
        "verifying webhook signature"
    );
    
    let ts = timestamp
        .parse::<i64>()
        .map_err(|_| {
            tracing::error!(timestamp = %timestamp, "failed to parse webhook timestamp");
            anyhow!("invalid webhook timestamp")
        })?;
    
    tracing::trace!(
        parsed_timestamp = ts,
        current_time = now,
        time_diff = (now - ts).abs(),
        "timestamp parsed and compared"
    );
    
    if (now - ts).abs() > tolerance_seconds {
        tracing::error!(
            time_diff = (now - ts).abs(),
            tolerance = tolerance_seconds,
            "webhook timestamp expired"
        );
        return Err(anyhow!("webhook timestamp expired"));
    }
    
    let payload = [
        webhook_id.as_bytes(),
        b".",
        timestamp.as_bytes(),
        b".",
        body,
    ]
    .concat();
    
    tracing::trace!(
        payload_len = payload.len(),
        "HMAC payload assembled"
    );
    
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| {
            tracing::error!("failed to create HMAC with provided secret");
            anyhow!("invalid webhook secret")
        })?;
    mac.update(&payload);
    let expected = mac.finalize().into_bytes();
    
    tracing::trace!(
        expected_signature_hex = %hex::encode(&expected),
        "computed HMAC signature"
    );
    
    let candidate = signature
        .split_whitespace()
        .find_map(|part| part.strip_prefix("v1,"))
        .ok_or_else(|| {
            tracing::error!(signature = %signature, "unsupported webhook signature format");
            anyhow!("unsupported webhook signature")
        })?;
    
    let decoded = STANDARD
        .decode(candidate)
        .or_else(|_| URL_SAFE_NO_PAD.decode(candidate))
        .map_err(|_| {
            tracing::error!(candidate = %candidate, "failed to decode webhook signature");
            anyhow!("malformed webhook signature")
        })?;
    
    tracing::trace!(
        decoded_signature_hex = %hex::encode(&decoded),
        expected_hex = %hex::encode(&expected),
        "decoded and comparing signatures"
    );
    
    if expected.as_slice().ct_eq(decoded.as_slice()).unwrap_u8() != 1 {
        tracing::error!(
            decoded_hex = %hex::encode(&decoded),
            expected_hex = %hex::encode(&expected),
            "webhook signature validation failed - mismatch"
        );
        return Err(anyhow!("invalid webhook signature"));
    }
    
    tracing::trace!("webhook signature validation successful");
    Ok(())
}

pub fn map_event(
    value: &Value,
    expected_org: &str,
    base_url: Option<&str>,
    now: String,
) -> Result<(String, DocumentUpsert)> {
    tracing::trace!(payload = %value, expected_org = %expected_org, "mapping webhook event");
    
    let event_type = value
        .get("type")
        .or_else(|| value.get("event_type"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            tracing::error!("event type field missing or not a string");
            anyhow!("event type is required")
        })?;
    
    tracing::trace!(event_type = %event_type, "event type resolved");
    
    if event_type != "document.created"
        && event_type != "document.updated"
        && event_type != "document_created"
        && event_type != "document_updated"
        && event_type != "document:created"
        && event_type != "document:updated"
    {
        tracing::error!(event_type = %event_type, "unsupported event type");
        return Err(anyhow!("unsupported event type"));
    }
    
    let document = value
        .get("data")
        .and_then(|v| v.get("document"))
        .or_else(|| value.get("document"))
        .or_else(|| value.get("data"))
        .ok_or_else(|| {
            tracing::error!("document payload not found in expected locations");
            tracing::trace!(payload_keys = ?value.as_object().map(|o| o.keys().collect::<Vec<_>>()), "available keys in payload");
            anyhow!("document payload is required")
        })?;
    
    let get = |names: &[&str]| names.iter().find_map(|name| document.get(*name));
    let string = |names: &[&str]| get(names).and_then(Value::as_str).map(ToOwned::to_owned);
    
    let org = string(&["organization_id", "organizationId", "org_id"])
        .ok_or_else(|| {
            tracing::error!(expected_org = %expected_org, "organization identifier missing");
            tracing::trace!(document_keys = ?document.as_object().map(|o| o.keys().collect::<Vec<_>>()), "available keys in document");
            anyhow!("organization identifier is required")
        })?;
    
    if org != expected_org {
        tracing::error!(provided_org = %org, expected_org = %expected_org, "organization mismatch");
        return Err(anyhow!("event organization is not configured organization"));
    }
    
    let id = string(&["id", "document_id", "documentId"])
        .ok_or_else(|| {
            tracing::error!("document identifier missing");
            anyhow!("document identifier is required")
        })?;
    
    tracing::trace!(document_id = %id, organization_id = %org, "document identifiers resolved");
    
    let title = string(&["title", "name"]);
    let content = string(&[
        "content",
        "text",
        "body",
        "searchable_text",
        "searchableText",
    ]);
    let hash = string(&["content_hash", "contentHash", "hash"])
        .or_else(|| content.as_deref().map(content_hash))
        .ok_or_else(|| anyhow!("content hash or searchable text is required"))?;
    let title_for_hash = title.as_deref().unwrap_or("");
    let content_for_hash = content.as_deref().unwrap_or("");
    let input_hash = embedding_input_hash(title_for_hash, content_for_hash);
    if title.is_none() || content.is_none() {
        // Existing rows may supply omitted fields; the storage layer resolves those values.
        // The hash is still required to make update processing idempotent.
        tracing::debug!("partial Papra document update received");
    }
    let tags = get(&["tags"]).cloned();
    let attributes = get(&[
        "attributes",
        "properties",
        "custom_properties",
        "customProperties",
    ])
    .cloned();
    let source_url = string(&["source_url", "sourceUrl", "url"]).or_else(|| {
        base_url.map(|base| format!("{}/documents/{}", base.trim_end_matches('/'), id))
    });
    let input = DocumentUpsert {
        organization_id: org,
        papra_document_id: id.clone(),
        title,
        content,
        content_hash: hash,
        embedding_input_hash: input_hash,
        tags,
        attributes,
        source_url,
        embedding_model: crate::embeddings::MODEL_NAME.to_string(),
        updated_at: now,
    };
    Ok((event_type.to_string(), input))
}

pub fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_signature_and_rejects_modified_body() {
        let body = br#"{"ok":true}"#;
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(b"id.100.");
        mac.update(body);
        let sig = format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()));
        assert!(verify_signature(b"secret", "id", "100", &sig, body, 10, 100).is_ok());
        assert!(verify_signature(b"secret", "id", "100", &sig, b"bad", 10, 100).is_err());
        assert!(verify_signature(b"secret", "id", "0", &sig, body, 10, 100).is_err());
    }
}
