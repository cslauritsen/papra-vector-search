use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use crate::embeddings::MODEL_NAME;

#[derive(Clone, Debug)]
pub struct DocumentUpsert {
    pub organization_id: String,
    pub papra_document_id: String,
    pub title: Option<String>,
    pub content: Option<String>,
    pub content_hash: String,
    pub embedding_input_hash: String,
    pub tags: Option<Value>,
    pub attributes: Option<Value>,
    pub source_url: Option<String>,
    pub embedding_model: String,
    pub updated_at: String,
}

#[derive(Clone, Debug)]
pub struct SearchResult {
    pub organization_id: String,
    pub papra_document_id: String,
    pub title: String,
    pub source_url: Option<String>,
    pub score: f32,
}

pub struct Storage {
    conn: Connection,
    pub dimension: usize,
}

impl Storage {
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

    pub fn needs_embedding(&self, input: &DocumentUpsert) -> Result<bool> {
        Ok(self
            .existing(&input.organization_id, &input.papra_document_id)?
            .map(|row| row.4 != input.embedding_input_hash || self.vector_missing(row.0))
            .unwrap_or(true))
    }

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
        let rows = stmt.query_map(params![bytes, limit as i64, organization], |row| {
            Ok(SearchResult {
                organization_id: row.get(0)?,
                papra_document_id: row.get(1)?,
                title: row.get(2)?,
                source_url: row.get(3)?,
                score: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

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
}
