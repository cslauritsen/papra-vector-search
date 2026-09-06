use fastembed::{TextEmbedding, TextInitOptions, EmbeddingModel};
use rusqlite::{ffi, Connection, Result};
use std::path::Path;

// --- DB helpers from our previous conversation ---
fn f32_slice_to_bytes(slice: &[f32]) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            slice.as_ptr() as *const u8,
            slice.len() * std::mem::size_of::<f32>(),
        )
    }
}

fn init_db() -> Result<Connection> {
    let conn = Connection::open(Path::new("papra_search.db"))?;
    unsafe { ffi::sqlite3_enable_load_extension(conn.handle(), 1); }
    let extension_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("deps/darwin-aarch64/vec0.dylib");
    unsafe { conn.load_extension(extension_path, None::<&str>)?; }

    // 384 dimensions matches the all-MiniLM-L6-v2 model exactly
    conn.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS vec_documents USING vec0(
            papra_id TEXT PRIMARY KEY,
            embedding float[384]
        );", [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS document_metadata (
            papra_id TEXT PRIMARY KEY,
            title TEXT,
            papra_url TEXT
        );", [],
    )?;
    Ok(conn)
}

fn insert_document(conn: &Connection, id: &str, title: &str, url: &str, embedding: &[f32]) -> Result<()> {
    conn.execute("INSERT OR REPLACE INTO document_metadata VALUES (?1, ?2, ?3)", [id, title, url])?;
    conn.execute("INSERT OR REPLACE INTO vec_documents VALUES (?1, ?2)", rusqlite::params![id, f32_slice_to_bytes(embedding)])?;
    Ok(())
}

fn query_similar_documents(conn: &Connection, query_vector: &[f32], limit: i32) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT m.title, m.papra_url, v.distance 
         FROM vec_documents v
         JOIN document_metadata m ON v.papra_id = m.papra_id
         WHERE embedding MATCH ?1 AND k = ?2",
    )?;

    let rows = stmt.query_map(rusqlite::params![f32_slice_to_bytes(query_vector), limit], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, f64>(2)?))
    })?;

    println!("\n--- Local Semantic Search Results ---");
    for row in rows {
        let (title, url, distance) = row?;
        println!("Document: {} | Link: {} (Distance: {:.4})", title, url, distance);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize the SQLite DB
    let conn = init_db()?;

    // 2. Initialize the Local Embedder
    // It safely downloads the tiny 90MB model file on the first run and caches it offline thereafter.
    let mut model = TextEmbedding::try_new(
        TextInitOptions::new(EmbeddingModel::AllMiniLML6V2).with_show_download_progress(true)
    )?;

    // 3. Simulating Papra ingestion: generate vectors out of raw document texts
    let doc_texts = vec![
        "Automobile financing contract terms and monthly repayment schedules.",
        "Internal staff kitchen guidelines and refrigerator cleanup policies."
    ];

    // Batch generate embeddings
    let embeddings = model.embed(doc_texts, None)?;

    insert_document(&conn, "doc_101", "Car Loan Agreement", "https://papra.local", &embeddings[0])?;
    insert_document(&conn, "doc_102", "Office Kitchen Rules", "https://papra.local", &embeddings[1])?;

    // 4. Perform search using a dynamic user query
    let user_query = vec!["loan documents"];
    let query_embeddings = model.embed(user_query, None)?;

    // Execute search with the target vector
    query_similar_documents(&conn, &query_embeddings[0], 5)?;

    Ok(())
}