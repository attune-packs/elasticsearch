# Elasticsearch Attune Pack

Safe, curated REST actions for Elasticsearch 8 and 9. The pack uses Python's
standard library and has no undeclared runtime dependencies. It does not expose
a generic HTTP action, arbitrary cluster settings, scripts, mapping types, the
legacy `_all` index target, `optimize`, or Curator behavior.

## Scope

The transport requires the `X-Elastic-Product: Elasticsearch` response header.
OpenSearch is a separate product with divergent lifecycle APIs (ISM instead of
ILM), authentication, response contracts, and release behavior. It has not been
tested by this pack and is explicitly unsupported.

The native Elasticsearch 8/9 REST formats used here do not need compatibility
headers. Elasticsearch compatibility media types only emulate the immediately
previous Elasticsearch REST major; they are not an OpenSearch compatibility
mechanism.

## Actions

| Action | Operations |
| --- | --- |
| `elasticsearch.cluster` | `health`, `info`, `stats` |
| `elasticsearch.index` | `list`, `get`, `create`, `settings_get`, `settings_update`, `mappings_get`, `mappings_update`, `delete`, `open`, `close`, `refresh`, `forcemerge` |
| `elasticsearch.aliases` | `list`, `update` |
| `elasticsearch.document` | `get`, `index`, `update`, `delete`, `bulk` |
| `elasticsearch.search` | `search`, `count` |
| `elasticsearch.snapshot` | `repositories`, `list`, `create`, `status`, `restore`, `delete` |
| `elasticsearch.data_streams` | `list` |
| `elasticsearch.ilm` | `policy_get`, `policy_put`, `policy_delete`, `status`, `explain` |

Every success is a JSON object with `ok`, `operation`, `status`, and `data`.
List responses use `data.items` and `data.count`. Failures exit non-zero and put
only a bounded, redacted error on stderr.

## Credentials

Create an encrypted, pack-owned Attune Key. Action parameters contain only the
key reference, never credential material.

```bash
attune key create \
  --ref elasticsearch.production \
  --name "Production Elasticsearch API key" \
  --value '{"auth_type":"api_key","api_key":"BASE64_ENCODED_ELASTIC_API_KEY","allowed_endpoints":["https://es.example.com:9200"],"allow_private_hosts":false}' \
  --owner-type pack \
  --owner-pack-ref elasticsearch \
  --encrypt
```

Supported key values are:

```json
{"auth_type":"api_key","api_key":"encoded-id-and-key","allowed_endpoints":["https://es.example.com:9200"]}
{"auth_type":"bearer","token":"bearer-token","allowed_endpoints":["https://es.example.com:9200"]}
{"auth_type":"basic","username":"elastic-user","password":"password","allowed_endpoints":["https://es.example.com:9200"]}
```

Each action requests Attune's `standard` execution permission set. The worker
injects a short-lived `ATTUNE_API_TOKEN`, which the action uses to read only the
pack-owned key through `/api/v1/keys/{ref}`. The action fails closed if the
execution token is absent, the reference is outside `elasticsearch.*`, or the
API response does not identify the key owner as this pack.

## Connection

All actions require:

- `endpoint`: an HTTPS origin authorized by the selected key's exact
  `allowed_endpoints` list, such as `https://es.example.com:9200`.
- `credential_key_ref`: an `elasticsearch.*` pack key.
- `timeout_seconds`: 1 to 300 seconds. No request is retried.

The pack-owned key may contain `ca_file` for a custom CA bundle and
`allow_private_hosts: true` for an exact allowlisted private Elasticsearch
origin. Both settings are administrator-controlled rather than caller-controlled.

TLS certificate and hostname verification cannot be disabled. Redirects,
endpoint paths, URL credentials, query strings, private/reserved destinations
by default, and responses from non-Elasticsearch products are rejected.

## Examples

Cluster health:

```bash
attune action execute elasticsearch.cluster --watch --params-json '{
  "endpoint":"https://es.example.com:9200",
  "credential_key_ref":"elasticsearch.production",
  "operation":"health"
}'
```

Create an index with typeless mappings:

```json
{
  "endpoint": "https://es.example.com:9200",
  "credential_key_ref": "elasticsearch.production",
  "operation": "create",
  "index": "events-2026",
  "body": {
    "settings": {"number_of_shards": 3},
    "mappings": {"properties": {"message": {"type": "text"}}}
  }
}
```

Optimistic document replacement:

```json
{
  "endpoint": "https://es.example.com:9200",
  "credential_key_ref": "elasticsearch.production",
  "operation": "index",
  "index": "events-2026",
  "document_id": "event-42",
  "document": {"message": "updated"},
  "create_only": false,
  "if_seq_no": 7,
  "if_primary_term": 2
}
```

Bounded search with `search_after`:

```json
{
  "endpoint": "https://es.example.com:9200",
  "credential_key_ref": "elasticsearch.production",
  "operation": "search",
  "indices": ["events-2026"],
  "query": {"term": {"service": "api"}},
  "size": 100,
  "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
  "search_after": [1786700000000, "event-42"]
}
```

Restore always renames, excludes aliases and global state, and first checks for
existing indices, aliases, or data streams with the requested prefix:

```json
{
  "endpoint": "https://es.example.com:9200",
  "credential_key_ref": "elasticsearch.production",
  "operation": "restore",
  "repository": "backups",
  "snapshot": "nightly-2026-08-14",
  "indices": ["events-2026"],
  "rename_prefix": "restore-20260814-",
  "confirm": "CONFIRM:restore:backups/nightly-2026-08-14->restore-20260814-*"
}
```

## Safeguards

- Mutating targets are concrete names only; commas, wildcards, `_all`, hidden
  system indices, path syntax, and cross-cluster targets are rejected.
- Deletes, open/close, force merge, alias updates, bulk deletes, ILM policy
  deletes, and snapshot restore/delete require operation-specific confirmation.
- Force merge additionally requires `read_only_confirmed=true`.
- Snapshot create/restore accepts at most 20 concrete indices. Restore always
  renames, never restores aliases/global state, and performs a collision check.
- Requests are capped at 5 MiB, responses at 10 MiB, bulk at 1,000 operations,
  search pages at 500 hits, result windows at 10,000, target lists at 20, and
  query timeout/termination limits are always sent.
- Query-bearing JSON rejects scripts, runtime mappings, percolate and expensive
  regexp/wildcard/fuzzy/prefix queries, excessive nesting, and excessive clauses.
- Index setting updates are restricted to replicas, refresh interval, and ILM
  assignment settings. Cluster setting mutation is not exposed.
- ILM policy updates/deletes and lifecycle setting assignments require explicit
  confirmations because they can initiate later data deletion.
- Single-document overwrite requires sequence number and primary term. Bulk
  overwrite uses the same requirement. Automatic mutation retries do not occur.
- Backend errors expose only selected structured fields with credential-shaped
  text and sensitive keys redacted.

Restore's preflight collision check cannot eliminate a race with another writer.
Use a unique restore prefix and least-privilege Elasticsearch roles. A network
timeout on any mutation has an unknown outcome; inspect state before retrying
manually.

## Verification

```bash
python3 -m unittest tests/test_elasticsearch.py
python3 -m compileall -q actions tests
attune pack check /home/david/Codebase/attune-packs/elasticsearch
attune pack test /home/david/Codebase/attune-packs/elasticsearch
```

Tests use mocked transports only. No live Elasticsearch or OpenSearch service is
required or contacted.

## API References

- [Elasticsearch v8 API](https://www.elastic.co/docs/api/doc/elasticsearch/v8/)
- [Elasticsearch v9 API](https://www.elastic.co/docs/api/doc/elasticsearch/v9/)
- [REST API conventions](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/api-conventions)
- [Snapshot and restore](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore)
- [OpenSearch documentation](https://docs.opensearch.org/latest/) for scope comparison only

See `SOURCE.md` and `NOTICE` for historical source attribution.
