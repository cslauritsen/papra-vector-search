# Papra Webhook Format

## After updating notes

```json
{
  "data": {
    "documentId": "doc_a8dxa3m185hkjinyr7hwtgw3",
    "notes": "test update",
    "organizationId": "org_iwlcaxb9l59ez9r5ue87umgz"
  },
  "timestamp": "2026-09-07T15:34:51.143Z",
  "type": "document:updated"
}
```

The webhook endpoint validates the request and queues the document ID in SQLite,
then immediately returns `202 Accepted`. A background worker polls the queue
once per minute and embeds one document at a time after a one-minute debounce.

## Batch enqueue

Authenticated clients can enqueue document IDs with:

```http
POST /api/embeddings/batch
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "document_ids": ["doc_a8dxa3m185hkjinyr7hwtgw3", "doc_other"]
}
```

Failed jobs are retried once automatically. A second failure remains in the
queue with `status = failed`; submitting its ID to the batch endpoint resets it
for another attempt.