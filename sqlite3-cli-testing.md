# Testing with the SQLite CLI

macOS's `/usr/bin/sqlite3` may be built with `OMIT_LOAD_EXTENSION`, which
means the `.load` command is unavailable. Use the Homebrew SQLite CLI instead:

```bash
/opt/homebrew/opt/sqlite/bin/sqlite3 papra_search.db
```

From the SQLite prompt, load the extension with its explicit entrypoint:

```sql
.load ./deps/darwin-aarch64/vec0.dylib sqlite3_vec_init
SELECT vec_version();
```

The `sqlite3_vec_init` entrypoint is required for this extension. Without
loading the extension, `.tables` can still show the vector table definitions
stored in the database, but querying them fails with:

```text
no such module: vec0
```

Useful checks:

```sql
.tables
SELECT * FROM document_metadata;
SELECT * FROM vec_documents;
```

To use the Homebrew CLI by default in the current shell:

```bash
export PATH="/opt/homebrew/opt/sqlite/bin:$PATH"
```
