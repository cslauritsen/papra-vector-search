# Papra Vector Search

Implementation specification for a Rust/Leptos service that indexes Papra documents and
provides authenticated semantic search over them.

## 1. Goal

Users authenticated with Google OIDC can search documents belonging to their Papra
organization. Papra sends document events to a webhook. The service embeds the document
text with `all-MiniLM-L6-v2`, stores the embedding in SQLite using `sqlite-vec`, and
returns the most similar documents for a query.

The service **must not store document files**. It stores searchable text, metadata needed
to identify/link the Papra document, and its vector embedding.

### Non-goals

- Replacing Papra as the source of truth.
- Editing, deleting, or downloading documents.
- Supporting multiple embedding models in the first version.
- Indexing documents without a valid organization and Papra document identifier.

## 2. Required technology

- Rust, edition 2024
- Leptos for the web UI and server integration
- `fastembed` for embeddings
- `all-MiniLM-L6-v2` model, used for both documents and queries
- SQLite with the `sqlite-vec` extension
- Tokio for asynchronous application work
- `secrecy` for secret configuration values
- OpenTelemetry for metrics
- `tracing` and `tracing-subscriber` for structured logs

The embedding dimension must be obtained from the selected model/library rather than
hard-coded in more than one place. The database schema must record the model name and
reject searches or writes made with an incompatible model.

## 3. Runtime configuration

Read configuration from environment variables at startup. Fail fast with a clear error
when a required value is missing.

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | yes | SQLite database path |
| `SQLITE_VEC_EXTENSION_PATH` | yes | Path to the loadable `sqlite-vec` extension |
| `PAPRA_WEBHOOK_SECRET` | yes | Shared secret for webhook HMAC verification |
| `PAPRA_ORGANIZATION_ID` | yes | Organization indexed and searched by this deployment |
| `GOOGLE_CLIENT_ID` | yes | Google OIDC audience/client ID |
| `GOOGLE_CLIENT_SECRET` | yes | Google OAuth client secret, protected with `secrecy` |
| `GOOGLE_REDIRECT_URI` | yes | OAuth callback URI, e.g. `http://localhost:3000/oidc/callback` |
| `GOOGLE_ISSUER` | yes | Expected issuer, normally `https://accounts.google.com` |
| `GOOGLE_ALLOWED_EMAILS` | yes | Comma-separated email addresses allowed to use the search UI |
| `PAPRA_BASE_URL` | no | Base URL used to construct Papra document links |
| `RUST_LOG` | no | Log filter; default to `info` |
| `WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS` | no | Accepted timestamp age; default to 300 |
| `SEARCH_RESULT_LIMIT` | no | Maximum results per request; default to 20, capped at 100 |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | OTLP metrics endpoint; disable export when unset |

Load secret values into `secrecy::SecretString` (or an equivalent `secrecy` secret type)
immediately when reading configuration. At minimum, `PAPRA_WEBHOOK_SECRET` and any OAuth
client secret must be protected. Use `secrecy`'s redacted `Debug` behavior whenever secret
configuration, authentication values, or secret-bearing payload fields are included in
diagnostic data. Do not expose secrets through errors, logs, metrics, tracing fields, or
serialized configuration.

## 4. Data model

Create migrations at startup before serving requests.

### `documents`

- `id`: internal integer primary key
- `organization_id`: Papra organization identifier, required
- `papra_document_id`: Papra document identifier, required
- `title`: display title, required
- `content`: normalized text used to create the embedding, required
- `content_hash`: hash supplied or calculated for the current document content, required
- `embedding_input_hash`: hash of the canonical title-plus-content text used for the
  current embedding, required
- `tags`: current Papra tags, stored as structured JSON
- `attributes`: current Papra custom properties/attributes, stored as structured JSON
- `source_url`: optional Papra URL or path
- `embedding_model`: required model identifier
- `created_at`, `updated_at`: UTC timestamps
- `content_updated_at`: timestamp of the last event that changed `content_hash`
- `embedding_updated_at`: timestamp of the last event that changed `embedding_input_hash`
- unique constraint on `(organization_id, papra_document_id)`

Store one current row per organization/document. A webhook is delivered for every
document update, not only document creation. Every accepted webhook must update the
document's current metadata, including title, tags, and custom properties/attributes, and
must store the current `content_hash`.

Construct the embedding input deterministically from the descriptive title and document
content:

```text
Title: {title}

Content:
{content}
```

Normalize this exact input, calculate its `embedding_input_hash`, and use it for the
embedding. A title change must therefore regenerate the embedding even when the raw
document `content_hash` is unchanged. Only regenerate and replace the vector when the
incoming `embedding_input_hash` differs from the stored hash, or when the document has no
vector yet. Changes to tags or custom properties do not trigger re-embedding unless they
are explicitly added to the canonical embedding input. Metadata updates and vector
replacement must remain atomic. The implementation must not overwrite current fields with
absent values when another Papra webhook processor owns those fields; map and persist fields
present in the event according to the Papra payload contract.

### Vector index

Create a `sqlite-vec` virtual table keyed by the document row ID. Store vectors in the
format required by the installed extension and query using cosine distance (or the
extension's equivalent). Return the distance as a score only if the API exposes it.
Database writes for metadata and its vector must be atomic.

## 5. Webhook API

### `POST /webhook/papra`

Accept JSON and retain the exact raw request bytes for signature verification before
deserialization. Require these headers:

- `webhook-id`
- `webhook-timestamp`
- `webhook-signature`

For compatibility, accept `x-signature` only when the Papra deployment uses the legacy
format documented by Papra.

For the current format, the signing payload is the exact UTF-8 body prefixed with:

```text
{webhook-id}.{webhook-timestamp}.
```

Verify `v1` HMAC-SHA256 using the shared secret and constant-time comparison. Decode the
signature using the format specified by Papra. Reject missing, malformed, unknown-version,
invalid, or expired timestamps with `401` or `400` as appropriate. Do not use lossy UTF-8
conversion when constructing the signing payload.

The handler must:

1. Verify the signature and timestamp before parsing or persisting the event.
2. Parse the event type and document payload.
3. Accept document-created and every document-updated event.
4. Extract organization ID, document ID, title, searchable text, content hash, tags, and
   custom properties/attributes when present.
5. Upsert current metadata and persist the document `content_hash` on every event.
6. Build the canonical title-plus-content embedding input and compare its hash.
7. Generate an embedding only when `embedding_input_hash` changed or no vector exists.
8. Commit metadata and any vector change in one transaction.
9. Return `200` for a successfully processed event and `4xx` for invalid input.

The payload adapter should isolate Papra-specific field names in one module. Missing
required identifiers, content hash, or searchable text must produce a descriptive client
error. Unknown event types should be acknowledged only if Papra requires acknowledgement;
otherwise return an explicit unsupported-event response.

Other Papra webhooks may independently update the same document's tags, content, title,
and custom properties/attributes. Treat webhook delivery as an update stream: use the
event's document version/timestamp when available, make processing idempotent, and avoid
reverting newer metadata with an older event. If Papra supplies no ordering/version
field, document and test the chosen last-write-wins behavior.

## 6. Search API

### `GET /api/search?q={query}&limit={limit}`

Require an `Authorization` header using the `Bearer` scheme and a Google OIDC token. Validate the token signature,
issuer, audience, expiration, and (when configured) email/domain or organization claims.
The first version searches only `PAPRA_ORGANIZATION_ID`; never trust an organization ID
supplied by the browser. Require the authenticated email to belong to
the case-insensitive `GOOGLE_ALLOWED_EMAILS` allowlist. A valid OIDC token for any other
email must be rejected with `401`.

Validation:

- `q` is required, trimmed, and must contain 1–1,000 Unicode characters.
- `limit` defaults to the configured value and is capped at 100.

Generate the query embedding with the same model used for indexing. Search only documents
the authenticated user is authorized to see. Return nearest documents ordered by ascending
distance:

```json
{
  "results": [
    {
      "organization_id": "org_123",
      "papra_document_id": "doc_456",
      "title": "Example document",
      "source_url": "https://papra.example/documents/doc_456",
      "score": 0.12
    }
  ]
}
```

Do not return stored content or embeddings. Return `400` for invalid query parameters,
`401` for missing/invalid authentication, and `500` only for unexpected server failures.

## 7. Google OIDC login flow

Implement the authorization-code flow with these endpoints:

- `GET /oidc/login`: generate a cryptographically random state, store it in an
  `HttpOnly`, `SameSite=Lax` cookie scoped to `/oidc`, and redirect to Google's
  authorization endpoint with `GOOGLE_CLIENT_ID`, `GOOGLE_REDIRECT_URI`, `openid email
  profile` scopes, and the state.
- `GET /oidc/callback`: require and constant-time-compare the returned state with the
  cookie, exchange the one-time code at Google's token endpoint using
  `GOOGLE_CLIENT_SECRET`, and clear the state cookie.

The callback returns the provider token response to the frontend over HTTPS; clients must
use the validated OIDC `id_token` as the bearer credential for `/api/search`. Never log
authorization codes, client secrets, access tokens, ID tokens, or state values. Reject
missing, expired, reused, or mismatched state and do not accept arbitrary redirect URIs.

## 8. Metrics

Instrument the service with OpenTelemetry and export metrics through OTLP when
`OTEL_EXPORTER_OTLP_ENDPOINT` is configured. Use an OpenTelemetry SDK/provider initialized
once at startup and flush/export on graceful shutdown.

Required custom instruments:

- `papra.search.count`: counter incremented once for every search request, with low-cardinality
  attributes such as `status` (`success`, `invalid_query`, `unauthorized`, `error`) and
  `result_count` only when represented by bounded buckets or omitted.
- `papra.http.request.count`: counter incremented once for every HTTP request, with
  `http.method`, normalized route (`/api/search`, `/webhook/papra`, or `/`), and
  `http.response.status_code` attributes.

Do not use query text, document IDs, user emails, bearer tokens, organization IDs, or
unbounded error messages as metric attributes. Ensure the request counter records the final
status code for both successful and failed requests.

## 9. Logging and tracing

Use structured `tracing` logs with a configured `tracing-subscriber` layer. Every HTTP
request must produce a standard access log containing the method, normalized route, status
code, duration, and response size when available. Emit a corresponding error log for
failed requests and unexpected handler failures with a request ID or trace ID when
available. Access and error logs must be emitted even when a handler returns a client
error.

Add trace-level instrumentation at important application boundaries, including startup
and shutdown, configuration loading, database migration and extension loading, embedding
model initialization, authentication decisions, webhook signature verification and
payload mapping, content-hash comparison, embedding decisions, database transactions,
vector searches, and response serialization. Include useful timing and decision fields,
but keep attributes bounded and avoid secrets.

Trace configuration on startup after validation. Log each configuration key and a safe
representation of its value, using `secrecy` redaction for secret values and omitting
credentials entirely. Do not log the raw environment, access tokens, HMAC signatures,
webhook secrets, or OAuth client secrets.

Payloads may be included at trace level for local diagnostics only through explicit
redacted DTOs. Never log raw request bodies. Before logging a webhook or API payload,
remove or redact document content, bearer tokens, signatures, cookies, secret properties,
and other sensitive fields; ensure secret-bearing values use `SecretString` so their
`Debug` representation is redacted. Document the redaction policy and test that sensitive
fields cannot appear in trace output. Production log configuration must default to
`info`, with trace payload logging opt-in.

## 10. Leptos UI

Provide a simple responsive page with:

- Google sign-in control for unauthenticated users.
- Search input and submit action for authenticated users.
- Loading, empty-result, validation-error, authentication-error, and server-error states.
- Result cards showing title, organization, similarity score, and a link to Papra when
  `source_url` is available.
- Keyboard submission and accessible labels/focus states.

The UI must send the bearer token on every API request. On `401`, clear the local
authentication state and redirect to the login flow. Do not put tokens in URLs, logs, or
server-rendered HTML.

### Serving the UI

The Axum server renders the Leptos page at `GET /ui`; `GET /` remains the JSON health
endpoint. Start the server with the normal command:

```sh
cargo run
```

Open `http://localhost:3000/ui` in a browser. The page is server-rendered by Leptos and
uses a small client-side script for the interactive search flow. Google sign-in opens the
OIDC flow in a same-origin popup so the callback's JSON response can be read by the
frontend without putting the ID token in a URL or server-rendered HTML. The token is kept
only in browser memory and is sent as a bearer header to `/api/search`.

## 11. Application structure

Keep these concerns separate:

- `config`: validated environment configuration
- `auth`: Google OIDC/JWT validation and authorization context
- `webhook`: raw-body handling, HMAC verification, and Papra payload mapping
- `embeddings`: model initialization and embedding generation
- `storage`: migrations, document upserts, and vector search
- `api`: typed request/response handlers
- `telemetry`: OpenTelemetry setup, metrics, and shutdown
- `logging`: tracing subscriber, access/error logs, startup configuration diagnostics,
  and payload redaction
- `ui`: Leptos components and authentication-aware search state

Initialize the embedding model and SQLite connection/extension once at application startup.
Do not load the model or extension per request. Use structured errors and return safe
messages to clients while logging actionable server-side context without secrets.

## 12. Acceptance criteria

An implementation is complete when:

1. A clean startup creates/updates the schema and fails clearly for invalid configuration.
2. A valid Papra webhook creates a searchable document; repeated updates refresh metadata
   and `content_hash` without duplication.
3. An unchanged embedding input hash does not trigger re-embedding, while a changed
   title or content changes the embedding input hash and does trigger re-embedding.
4. Invalid signatures, stale timestamps, malformed payloads, and missing identifiers are
   rejected before any database write.
5. Search embeds the query with the same model and returns correctly ordered results.
6. Unauthenticated and unauthorized requests cannot search or enumerate documents.
7. OIDC login validates state, exchanges the code using the configured client secret and
   redirect URI, and never exposes credentials in logs.
8. OpenTelemetry exports request counts with final status-code dimensions and search counts
   without high-cardinality or secret attributes.
9. Every request emits an access log and failed requests emit an error log with duration,
   status, and correlation context.
10. Startup emits redacted configuration diagnostics, and trace instrumentation covers the
   major application boundaries without leaking secrets or raw payloads.
11. The UI handles loading, empty, error, login, and result states accessibly.
12. Tests cover signature verification, timestamp rejection, payload validation, metadata
   updates, content-hash persistence, title/content embedding-input hashing, re-embedding
   decisions, upsert idempotency, model/dimension compatibility, authorization, metrics,
   access/error logs, configuration redaction, payload redaction, and search ordering.
