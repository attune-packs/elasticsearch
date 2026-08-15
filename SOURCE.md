# Source Metadata

| Field | Value |
| --- | --- |
| Attributed source | StackStorm Exchange Elasticsearch pack |
| URL | https://github.com/StackStorm-Exchange/stackstorm-elasticsearch |
| Version | `v2.0.1` |
| Revision | `9aba2b68da26ec356b6c533d902e560ff76c4980` |
| Revision date | `2025-02-16T19:36:32-06:00` |
| License | `Apache-2.0` |
| License file | https://github.com/StackStorm-Exchange/stackstorm-elasticsearch/blob/9aba2b68da26ec356b6c533d902e560ff76c4980/LICENSE |
| Verified | `2026-08-14` |

The attributed project was used for historical feature inventory and
attribution. No Curator implementation or source code was copied.

Explicitly excluded legacy behavior: Curator 5, `_all` index targets, optimize,
mapping types, and legacy Elasticsearch Python client assumptions.

Primary references are the official
[Elasticsearch v8 API](https://www.elastic.co/docs/api/doc/elasticsearch/v8/),
[Elasticsearch v9 API](https://www.elastic.co/docs/api/doc/elasticsearch/v9/),
and [REST API conventions](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/api-conventions).

Supported scope is Elasticsearch 8 and 9. OpenSearch is not supported or
tested. Compatibility headers are disabled because the pack uses native
current REST contracts.
