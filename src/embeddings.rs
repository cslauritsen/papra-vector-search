use anyhow::{Result, anyhow};
use fastembed::{EmbeddingModel, TextEmbedding, TextInitOptions};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Name of the embedding model used for indexed documents.
pub const MODEL_NAME: &str = "all-MiniLM-L6-v2";

/// Builds the normalized text passed to the embedding model.
pub fn canonical_embedding_input(title: &str, content: &str) -> String {
    let raw = format!("Title: {}\n\nContent:\n{}", title.trim(), content.trim());
    raw.replace("\r\n", "\n")
        .replace('\r', "\n")
        .nfc()
        .collect()
}

/// Hashes the normalized embedding input for change detection.
pub fn embedding_input_hash(title: &str, content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_embedding_input(title, content).as_bytes());
    hex_encode(&hasher.finalize())
}

/// Hashes document content for persistence and change detection.
pub fn content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Initializes the configured fastembed model.
pub fn initialize() -> Result<TextEmbedding> {
    tracing::info!(model = MODEL_NAME, "initializing embedding model");
    TextEmbedding::try_new(TextInitOptions::new(EmbeddingModel::AllMiniLML6V2))
        .map_err(|e| anyhow!("failed to initialize embedding model: {e}"))
}

/// Generates one embedding vector for the supplied text.
pub fn embed(model: &mut TextEmbedding, text: &str) -> Result<Vec<f32>> {
    model
        .embed(vec![text], None)
        .map_err(|e| anyhow!("embedding generation failed: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("embedding model returned no vector"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_input_is_stable_and_title_sensitive() {
        assert_eq!(
            canonical_embedding_input("  Hello\r\n", "world\r\n"),
            "Title: Hello\n\nContent:\nworld"
        );
        assert_ne!(
            embedding_input_hash("A", "x"),
            embedding_input_hash("B", "x")
        );
        assert_eq!(
            embedding_input_hash("A", "x"),
            embedding_input_hash("A", "x")
        );
    }
}
