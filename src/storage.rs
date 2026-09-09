use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use leptos::attr::rows;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use crate::embeddings::MODEL_NAME;

#[derive(Clone, Debug)]
/// Document fields used to update persistent storage.
pub struct DocumentUpsert {
    /// Papra organization identifier.
    pub organization_id: String,
    /// Papra document identifier.
    pub papra_document_id: String,
    /// Optional document title.
    pub title: Option<String>,
    /// Optional searchable content.
    pub content: Option<String>,
    /// Hash of the document content.
    pub content_hash: String,
    /// Hash of the normalized embedding input.
    pub embedding_input_hash: String,
    /// Optional document tags.
    pub tags: Option<Value>,
    /// Optional document attributes.
    pub attributes: Option<Value>,
    /// Optional source URL.
    pub source_url: Option<String>,
    /// Embedding model used to generate the vector.
    pub embedding_model: String,
    /// Timestamp for the update.
    pub updated_at: String,
}

#[derive(Clone, Debug)]
/// Search result returned by the storage layer.
pub struct SearchResult {
    /// Papra organization identifier.
    pub organization_id: String,
    /// Papra document identifier.
    pub papra_document_id: String,
    /// Document title.
    pub title: String,
    /// Optional source URL.
    pub source_url: Option<String>,
    /// Vector distance score.
    pub score: f32,
}

#[derive(Clone, Debug)]
/// Persisted embedding job state.
pub struct EmbeddingJob {
    /// Papra document identifier.
    pub document_id: String,
    /// Timestamp of the latest enqueue operation.
    pub received_at: String,
    /// Number of attempts already made.
    pub attempts: i64,
}

/// SQLite storage for documents, vectors, and embedding jobs.
pub struct Storage {
    conn: Connection,
    /// Number of dimensions in stored vectors.
    pub dimension: usize,
}

impl Storage {
    /// Opens the SQLite database, loads sqlite-vec, and applies migrations.
    pub fn open(
        database_url: &str,
        extension_path: &Path,
        model: &str,
        dimension: usize,
    ) -> Result<Self> {
        let path = database_url
            .strip_prefix("sqlite://")
            .unwrap_or(database_url);
        let conn =
            Connection::open(path).with_context(|| format!("opening SQLite database {path}"))?;
        unsafe { conn.load_extension_enable()? };
        let loaded = unsafe { conn.load_extension(extension_path, Some("sqlite3_vec_init")) };
        let disabled = conn.load_extension_disable();
        loaded?;
        disabled?;
        tracing::info!(path = %path, "sqlite-vec extension loaded");
        let storage = Self { conn, dimension };
        storage.migrate(model)?;
        Ok(storage)
    }

    /// Opens a SQLite database without loading sqlite-vec, for lightweight tests.
    pub fn open_without_extension(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self { conn, dimension: 3 };
        storage.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                organization_id TEXT NOT NULL,
                papra_document_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                embedding_input_hash TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                attributes TEXT NOT NULL DEFAULT '{}',
                source_url TEXT,
                embedding_model TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                content_updated_at TEXT NOT NULL,
                embedding_updated_at TEXT NOT NULL,
                UNIQUE(organization_id, papra_document_id)
            );
            CREATE TABLE IF NOT EXISTS vec_documents (
                document_id INTEGER PRIMARY KEY,
                embedding BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS embedding_jobs (
                document_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );",
        )?;
        Ok(storage)
    }

    fn migrate(&self, model: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                organization_id TEXT NOT NULL,
                papra_document_id TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                embedding_input_hash TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                attributes TEXT NOT NULL DEFAULT '{}',
                source_url TEXT,
                embedding_model TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                content_updated_at TEXT NOT NULL,
                embedding_updated_at TEXT NOT NULL,
                UNIQUE(organization_id, papra_document_id)
            );
            CREATE TABLE IF NOT EXISTS embedding_jobs (
                document_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );",
        )?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT value FROM schema_meta WHERE key='embedding_model'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            if previous != model {
                return Err(anyhow!(
                    "database embedding model {previous} is incompatible with {model}"
                ));
            }
        }
        if let Some(previous_dimension) = tx
            .query_row(
                "SELECT value FROM schema_meta WHERE key='embedding_dimension'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            if previous_dimension != self.dimension.to_string() {
                return Err(anyhow!(
                    "database embedding dimension {previous_dimension} is incompatible with {}",
                    self.dimension
                ));
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('embedding_model', ?)",
            [model],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO schema_meta(key,value) VALUES('embedding_dimension', ?)",
            [self.dimension.to_string()],
        )?;
        tx.execute_batch(&format!(
            "CREATE VIRTUAL TABLE IF NOT EXISTS vec_documents USING vec0(
                document_id INTEGER PRIMARY KEY,
                embedding float[{}]
            );",
            self.dimension
        ))?;
        tx.commit()?;
        Ok(())
    }

    fn existing(
        &self,
        org: &str,
        doc: &str,
    ) -> Result<Option<(i64, String, String, String, String, String, String)>> {
        self.conn
            .query_row(
                "SELECT id,title,content,content_hash,embedding_input_hash,tags,attributes
             FROM documents WHERE organization_id=? AND papra_document_id=?",
                params![org, doc],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Reports whether the document needs a newly generated embedding.
    pub fn needs_embedding(&self, input: &DocumentUpsert) -> Result<bool> {
        Ok(self
            .existing(&input.organization_id, &input.papra_document_id)?
            .map(|row| row.4 != input.embedding_input_hash || self.vector_missing(row.0))
            .unwrap_or(true))
    }

    /// Fills omitted fields from an existing document and resolves its input hash.
    pub fn resolve_input(&self, input: &mut DocumentUpsert) -> Result<()> {
        if let Some(row) = self.existing(&input.organization_id, &input.papra_document_id)? {
            let title = input.title.clone().unwrap_or(row.1);
            let content = input.content.clone().unwrap_or(row.2);
            input.title = Some(title.clone());
            input.content = Some(content.clone());
            input.embedding_input_hash = crate::embeddings::embedding_input_hash(&title, &content);
        } else if input.title.is_none() || input.content.is_none() {
            return Err(anyhow!(
                "title and searchable text are required for a new document"
            ));
        }
        Ok(())
    }

    fn vector_missing(&self, id: i64) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM vec_documents WHERE document_id=?",
                [id],
                |_| Ok(()),
            )
            .is_err()
    }

    /// Inserts or updates a document and its optional embedding vector.
    pub fn upsert(&mut self, input: &DocumentUpsert, embedding: Option<&[f32]>) -> Result<()> {
        if input.embedding_model != MODEL_NAME {
            return Err(anyhow!("unsupported embedding model"));
        }
        let old = self.existing(&input.organization_id, &input.papra_document_id)?;
        let (id, title, content, content_changed, embedding_changed, tags, attributes) = match old {
            Some(row) => {
                let title = input.title.clone().unwrap_or(row.1);
                let content = input.content.clone().unwrap_or(row.2);
                let content_changed = row.3 != input.content_hash;
                let embedding_changed =
                    row.4 != input.embedding_input_hash || self.vector_missing(row.0);
                let tags = input
                    .tags
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(row.5);
                let attributes = input
                    .attributes
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(row.6);
                (
                    row.0,
                    title,
                    content,
                    content_changed,
                    embedding_changed,
                    tags,
                    attributes,
                )
            }
            None => {
                let title = input
                    .title
                    .clone()
                    .ok_or_else(|| anyhow!("title is required for a new document"))?;
                let content = input
                    .content
                    .clone()
                    .ok_or_else(|| anyhow!("content is required for a new document"))?;
                (
                    0,
                    title,
                    content,
                    true,
                    true,
                    input
                        .tags
                        .clone()
                        .unwrap_or(Value::Array(vec![]))
                        .to_string(),
                    input
                        .attributes
                        .clone()
                        .unwrap_or(Value::Object(Default::default()))
                        .to_string(),
                )
            }
        };
        if embedding_changed {
            let vector =
                embedding.ok_or_else(|| anyhow!("embedding required for changed input"))?;
            if vector.len() != self.dimension {
                return Err(anyhow!(
                    "embedding dimension {} does not match {}",
                    vector.len(),
                    self.dimension
                ));
            }
        }
        let tx = self.conn.transaction()?;
        let now = &input.updated_at;
        if id == 0 {
            tx.execute(
                "INSERT INTO documents(organization_id,papra_document_id,title,content,content_hash,embedding_input_hash,tags,attributes,source_url,embedding_model,created_at,updated_at,content_updated_at,embedding_updated_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?,?)",
                params![input.organization_id, input.papra_document_id, title, content, input.content_hash,
                    input.embedding_input_hash, tags, attributes, input.source_url, input.embedding_model, now, now, now, now],
            )?;
        } else {
            tx.execute(
                "UPDATE documents SET title=?,content=?,content_hash=?,embedding_input_hash=?,tags=?,attributes=?,
                    source_url=COALESCE(?,source_url),embedding_model=?,updated_at=?,
                    content_updated_at=CASE WHEN ? THEN ? ELSE content_updated_at END,
                    embedding_updated_at=CASE WHEN ? THEN ? ELSE embedding_updated_at END
                 WHERE id=?",
                params![title, content, input.content_hash, input.embedding_input_hash, tags, attributes,
                    input.source_url, input.embedding_model, now, content_changed, now, embedding_changed, now, id],
            )?;
        }
        let id = if id == 0 { tx.last_insert_rowid() } else { id };
        if embedding_changed {
            let bytes = embedding
                .unwrap()
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<_>>();
            tx.execute("DELETE FROM vec_documents WHERE document_id=?", [id])?;
            tx.execute(
                "INSERT INTO vec_documents(document_id,embedding) VALUES(?,?)",
                params![id, bytes],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Searches the vector index for documents in an organization.
    pub fn search(
        &self,
        organization: &str,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<SearchResult>> {
        if embedding.len() != self.dimension {
            return Err(anyhow!("query embedding dimension mismatch"));
        }
        let bytes = embedding
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        let mut stmt = self.conn.prepare(
            "SELECT d.organization_id,d.papra_document_id,d.title,d.source_url,v.distance
             FROM vec_documents v JOIN documents d ON d.id=v.document_id
             WHERE v.embedding MATCH ?1 AND v.k=?2 AND d.organization_id=?3
             ORDER BY v.distance ASC",
        )?;
        let mut ix = 0;
        let rows = stmt.query_map(params![bytes, limit as i64, organization], |row| {
            let r = SearchResult {
                organization_id: row.get(0)?,
                papra_document_id: row.get(1)?,
                title: row.get(2)?,
                source_url: row.get(3)?,
                score: row.get(4)?,
            };
            tracing::debug!("search result[{}] doc: {} distance: {}", ix, r.papra_document_id, r.score);
            ix += 1;
            Ok(r)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Returns the underlying SQLite connection.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Enqueues or refreshes a document's embedding job.
    pub fn enqueue_embedding(&mut self, document_id: &str, received_at: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO embedding_jobs(document_id,received_at,status,attempts,last_error)
             VALUES(?,?,'pending',0,NULL)
             ON CONFLICT(document_id) DO UPDATE SET
                 received_at=excluded.received_at,
                 status=CASE WHEN embedding_jobs.status='running' THEN 'running' ELSE 'pending' END,
                 attempts=CASE WHEN embedding_jobs.status='running' THEN embedding_jobs.attempts ELSE 0 END,
                 last_error=NULL",
            params![document_id, received_at],
        )?;
        Ok(())
    }

    /// Claims the oldest pending job received no later than `before`.
    pub fn claim_embedding_job(&mut self, before: &str) -> Result<Option<EmbeddingJob>> {
        let tx = self.conn.transaction()?;
        let job = tx
            .query_row(
                "SELECT document_id,received_at,attempts
                 FROM embedding_jobs
                 WHERE status='pending' AND received_at <= ?
                 ORDER BY received_at ASC
                 LIMIT 1",
                [before],
                |row| {
                    Ok(EmbeddingJob {
                        document_id: row.get(0)?,
                        received_at: row.get(1)?,
                        attempts: row.get(2)?,
                    })
                },
            )
            .optional()?;
        if let Some(job) = &job {
            tracing::info!(model = MODEL_NAME, "claiming embedding job");
            tx.execute(
                "UPDATE embedding_jobs SET status='running' WHERE document_id=? AND status='pending'",
                [&job.document_id],
            )?;
        }
        tx.commit()?;
        Ok(job)
    }

    /// Removes a completed job, preserving a newer update received while it ran.
    pub fn finish_embedding_job(&mut self, job: &EmbeddingJob) -> Result<()> {
        self.conn.execute(
            "DELETE FROM embedding_jobs
             WHERE document_id=? AND status='running' AND received_at=?",
            params![job.document_id, job.received_at],
        )?;
        self.conn.execute(
            "UPDATE embedding_jobs SET status='pending',attempts=0,last_error=NULL
             WHERE document_id=? AND status='running'",
            [&job.document_id],
        )?;
        Ok(())
    }

    /// Records a failure and schedules one retry before permanently failing the job.
    pub fn fail_embedding_job(
        &mut self,
        job: &EmbeddingJob,
        error: &str,
        retry_delay: Duration,
    ) -> Result<()> {
        let retry_at = chrono::Utc::now()
            .checked_add_signed(
                chrono::Duration::from_std(retry_delay)
                    .map_err(|e| anyhow!("invalid retry delay: {e}"))?,
            )
            .ok_or_else(|| anyhow!("retry timestamp overflow"))?
            .to_rfc3339();
        self.conn.execute(
            "UPDATE embedding_jobs
             SET status=CASE WHEN received_at != ? THEN 'pending'
                             WHEN attempts < 1 THEN 'pending'
                             ELSE 'failed' END,
                 received_at=CASE WHEN received_at != ? OR attempts < 1 THEN ? ELSE received_at END,
                 attempts=CASE WHEN received_at != ? THEN 0 ELSE attempts + 1 END,
                 last_error=?
             WHERE document_id=? AND status='running'",
            params![
                job.received_at,
                job.received_at,
                retry_at,
                job.received_at,
                error,
                job.document_id
            ],
        )?;
        Ok(())
    }
}

/// Locks shared storage and converts a poisoned mutex into an error.
pub fn lock(storage: &Mutex<Storage>) -> Result<MutexGuard<'_, Storage>> {
    storage.lock().map_err(|_| anyhow!("storage lock poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(title: &str, hash: &str) -> DocumentUpsert {
        DocumentUpsert {
            organization_id: "org".into(),
            papra_document_id: "doc".into(),
            title: Some(title.into()),
            content: Some("body".into()),
            content_hash: hash.into(),
            embedding_input_hash: format!("{title}-{hash}"),
            tags: Some(json!(["tag"])),
            attributes: None,
            source_url: None,
            embedding_model: MODEL_NAME.into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn upsert_is_idempotent_and_updates_metadata() {
        let mut storage = Storage::open_without_extension(":memory:").unwrap();
        let first = input("one", "h1");
        storage.upsert(&first, Some(&[1.0, 0.0, 0.0])).unwrap();
        assert!(!storage.needs_embedding(&first).unwrap());
        let mut second = input("two", "h1");
        second.tags = Some(json!(["new"]));
        storage.upsert(&second, Some(&[0.0, 1.0, 0.0])).unwrap();
        let row: (String, String, String) = storage.connection().query_row(
            "SELECT title,content_hash,tags FROM documents WHERE organization_id='org' AND papra_document_id='doc'",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(row.0, "two");
        assert_eq!(row.1, "h1");
        assert_eq!(row.2, r#"["new"]"#);
    }

    #[test]
    fn embedding_jobs_debounce_and_requeue_updates_during_processing() {
        let mut storage = Storage::open_without_extension(":memory:").unwrap();
        storage
            .enqueue_embedding("doc", "2026-01-01T00:00:00Z")
            .unwrap();
        let job = storage
            .claim_embedding_job("2026-01-01T00:01:00Z")
            .unwrap()
            .unwrap();
        storage
            .enqueue_embedding("doc", "2026-01-01T00:02:00Z")
            .unwrap();
        storage.finish_embedding_job(&job).unwrap();

        let row: (String, String) = storage
            .connection()
            .query_row(
                "SELECT status,received_at FROM embedding_jobs WHERE document_id='doc'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("pending".into(), "2026-01-01T00:02:00Z".into()));
    }
}
