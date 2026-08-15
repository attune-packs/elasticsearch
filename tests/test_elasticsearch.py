import importlib.util
import io
import json
import os
import pathlib
import unittest
from urllib.error import HTTPError


MODULE_PATH = pathlib.Path(__file__).parents[1] / "actions" / "elasticsearch.py"
SPEC = importlib.util.spec_from_file_location("elasticsearch_action", MODULE_PATH)
es = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(es)


class FakeClient:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if self.responses:
            return self.responses.pop(0)
        return {"status": 200, "data": {"acknowledged": True}}


class FakeHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class FakeResponse:
    def __init__(self, payload, status=200, product="Elasticsearch"):
        self.body = json.dumps(payload).encode()
        self.status = status
        self.headers = FakeHeaders({"X-Elastic-Product": product})

    def read(self, size=-1):
        return self.body[:size] if size >= 0 else self.body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class DispatchTests(unittest.TestCase):
    def test_cluster_routes_are_fixed(self):
        client = FakeClient()
        result = es.cluster({"operation": "health"}, client)
        self.assertEqual(client.calls[0][0:2], ("GET", "/_cluster/health"))
        self.assertTrue(result["ok"])
        with self.assertRaises(es.ActionError):
            es.cluster({"operation": "settings"}, client)

    def test_index_delete_rejects_wildcard_and_requires_exact_confirmation(self):
        client = FakeClient()
        with self.assertRaises(es.ActionError):
            es.index({"operation": "delete", "index": "logs-*", "confirm": "x"}, client)
        with self.assertRaises(es.ActionError):
            es.index({"operation": "delete", "index": "logs-2026"}, client)
        es.index(
            {"operation": "delete", "index": "logs-2026", "confirm": "CONFIRM:delete:logs-2026"},
            client,
        )
        self.assertEqual(client.calls[-1][0:2], ("DELETE", "/logs-2026"))

    def test_index_settings_are_allowlisted(self):
        client = FakeClient()
        es.index(
            {"operation": "settings_update", "index": "logs", "body": {"refresh_interval": "5s"}},
            client,
        )
        with self.assertRaises(es.ActionError):
            es.index(
                {"operation": "settings_update", "index": "logs", "body": {"index.blocks.write": True}},
                client,
            )
        with self.assertRaises(es.ActionError):
            es.index(
                {"operation": "settings_update", "index": "logs", "body": {"index.lifecycle.name": "delete-old"}},
                client,
            )

    def test_mapping_updates_are_typeless_and_scriptless(self):
        client = FakeClient()
        with self.assertRaises(es.ActionError):
            es.index({"operation": "mappings_update", "index": "logs", "body": {"_doc": {}}}, client)
        with self.assertRaises(es.ActionError):
            es.index(
                {"operation": "mappings_update", "index": "logs", "body": {"script": "bad"}},
                client,
            )

    def test_forcemerge_requires_read_only_attestation_and_confirmation(self):
        params = {
            "operation": "forcemerge",
            "index": "archive",
            "read_only_confirmed": True,
            "confirm": "CONFIRM:forcemerge:archive",
            "max_num_segments": 1,
        }
        client = FakeClient()
        es.index(params, client)
        self.assertEqual(client.calls[0][1], "/archive/_forcemerge")
        params["read_only_confirmed"] = False
        with self.assertRaises(es.ActionError):
            es.index(params, client)

    def test_alias_update_disallows_remove_index(self):
        client = FakeClient()
        with self.assertRaises(es.ActionError):
            es.aliases(
                {
                    "operation": "update",
                    "actions": [{"remove_index": {"index": "logs"}}],
                    "confirm": "CONFIRM:update:remove_index:unknown@unknown",
                },
                client,
            )
        es.aliases(
            {
                "operation": "update",
                "actions": [{"add": {"index": "logs", "alias": "current"}}],
                "confirm": "CONFIRM:update:add:current@logs",
            },
            client,
        )
        self.assertEqual(client.calls[-1][1], "/_aliases")

    def test_document_index_defaults_to_create_only(self):
        client = FakeClient()
        es.document(
            {"operation": "index", "index": "logs", "document_id": "1", "document": {"message": "x"}},
            client,
        )
        self.assertEqual(client.calls[0][2]["query"], {"op_type": "create"})
        with self.assertRaises(es.ActionError):
            es.document(
                {
                    "operation": "index",
                    "index": "logs",
                    "document_id": "1",
                    "document": {"message": "replace"},
                    "create_only": False,
                },
                client,
            )

    def test_document_overwrite_supports_optimistic_concurrency(self):
        client = FakeClient()
        es.document(
            {
                "operation": "index",
                "index": "logs",
                "document_id": "1",
                "document": {"message": "replace"},
                "create_only": False,
                "if_seq_no": 4,
                "if_primary_term": 2,
            },
            client,
        )
        self.assertEqual(client.calls[0][2]["query"], {"if_seq_no": 4, "if_primary_term": 2})

    def test_document_fields_named_script_are_data_not_execution(self):
        client = FakeClient()
        es.document(
            {
                "operation": "index",
                "index": "logs",
                "document_id": "1",
                "document": {"script": "stored as ordinary source"},
            },
            client,
        )
        self.assertEqual(client.calls[0][2]["body"]["script"], "stored as ordinary source")

    def test_bulk_is_ndjson_bounded_and_delete_confirmed(self):
        client = FakeClient()
        params = {
            "operation": "bulk",
            "index": "logs",
            "operations": [
                {"action": "create", "document_id": "1", "document": {"a": 1}},
                {"action": "delete", "document_id": "2"},
            ],
            "confirm": "CONFIRM:bulk_delete:logs/2",
        }
        es.document(params, client)
        call = client.calls[0]
        self.assertEqual(call[1], "/logs/_bulk")
        self.assertEqual(call[2]["content_type"], "application/x-ndjson")
        self.assertTrue(call[2]["body"].endswith(b"\n"))
        params.pop("confirm")
        with self.assertRaises(es.ActionError):
            es.document(params, client)

    def test_bulk_index_overwrite_requires_concurrency(self):
        with self.assertRaises(es.ActionError):
            es.document(
                {
                    "operation": "bulk",
                    "index": "logs",
                    "operations": [{"action": "index", "document_id": "1", "document": {"a": 1}}],
                },
                FakeClient(),
            )

    def test_search_is_bounded_and_scriptless(self):
        client = FakeClient()
        es.search(
            {
                "operation": "search",
                "indices": ["logs-2026"],
                "query": {"term": {"status": "ok"}},
                "size": 500,
                "from": 9500,
            },
            client,
        )
        self.assertEqual(client.calls[0][1], "/logs-2026/_search")
        self.assertEqual(client.calls[0][2]["body"]["track_total_hits"], 10000)
        with self.assertRaises(es.ActionError):
            es.search(
                {"operation": "search", "indices": ["logs"], "query": {"script_score": {}}},
                client,
            )
        with self.assertRaises(es.ActionError):
            es.search({"operation": "search", "indices": ["logs-*"], "query": {}}, client)
        with self.assertRaises(es.ActionError):
            es.search(
                {"operation": "search", "indices": ["logs"], "sort": [{"_script": {}}]},
                client,
            )
        with self.assertRaises(es.ActionError):
            es.search(
                {"operation": "search", "indices": ["logs"], "query": {"wildcard": {"message": "*x*"}}},
                client,
            )

    def test_count_sends_termination_limit(self):
        client = FakeClient()
        es.search(
            {"operation": "count", "indices": ["logs"], "terminate_after": 123},
            client,
        )
        self.assertEqual(client.calls[0][2]["query"], {"terminate_after": 123})

    def test_search_after_controls(self):
        client = FakeClient()
        es.search(
            {
                "operation": "search",
                "indices": ["logs"],
                "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
                "search_after": [123, "abc"],
            },
            client,
        )
        body = client.calls[0][2]["body"]
        self.assertNotIn("from", body)
        with self.assertRaises(es.ActionError):
            es.search(
                {"operation": "search", "indices": ["logs"], "sort": ["_id"], "search_after": [1, 2]},
                client,
            )

    def test_snapshot_create_excludes_global_state(self):
        client = FakeClient()
        es.snapshot(
            {
                "operation": "create",
                "repository": "repo",
                "snapshot": "nightly",
                "indices": ["logs", "metrics"],
            },
            client,
        )
        body = client.calls[0][2]["body"]
        self.assertFalse(body["include_global_state"])
        self.assertEqual(body["indices"], "logs,metrics")

    def test_snapshot_restore_renames_and_checks_collisions(self):
        no_collision = {"status": 200, "data": {"indices": [], "aliases": [], "data_streams": []}}
        client = FakeClient([no_collision])
        params = {
            "operation": "restore",
            "repository": "repo",
            "snapshot": "nightly",
            "indices": ["logs"],
            "rename_prefix": "restored-",
            "confirm": "CONFIRM:restore:repo/nightly->restored-*",
        }
        es.snapshot(params, client)
        self.assertEqual(client.calls[0][0], "GET")
        restore_body = client.calls[1][2]["body"]
        self.assertEqual(restore_body["rename_replacement"], "restored-$1")
        self.assertFalse(restore_body["include_aliases"])
        collision = {"status": 200, "data": {"indices": [{"name": "restored-logs"}]}}
        with self.assertRaises(es.ActionError):
            es.snapshot(params, FakeClient([collision]))

    def test_ilm_policy_contract_and_delete_confirmation(self):
        client = FakeClient()
        es.ilm(
            {
                "operation": "policy_put",
                "policy": "logs",
                "body": {"policy": {"phases": {"hot": {}}}},
                "confirm": "CONFIRM:policy_put:logs",
            },
            client,
        )
        with self.assertRaises(es.ActionError):
            es.ilm({"operation": "policy_put", "policy": "logs", "body": {}}, client)
        with self.assertRaises(es.ActionError):
            es.ilm({"operation": "policy_delete", "policy": "logs"}, client)

    def test_elasticsearch_9_uses_post_to_resolve_restore_collisions(self):
        no_collision = {"status": 200, "data": {"indices": [], "aliases": [], "data_streams": []}}
        client = FakeClient([no_collision])
        client.major = 9
        es.snapshot(
            {
                "operation": "restore",
                "repository": "repo",
                "snapshot": "nightly",
                "indices": ["logs"],
                "rename_prefix": "restored-",
                "confirm": "CONFIRM:restore:repo/nightly->restored-*",
            },
            client,
        )
        self.assertEqual(client.calls[0][0], "POST")

    def test_list_results_are_normalized_to_object(self):
        client = FakeClient([{"status": 200, "data": [{"index": "a"}, {"index": "b"}]}])
        result = es.index({"operation": "list", "limit": 1}, client)
        self.assertEqual(result["data"], {"items": [{"index": "a"}], "count": 1})


class SecurityTests(unittest.TestCase):
    def test_auth_encodings(self):
        self.assertEqual(es._authorization({"auth_type": "api_key", "api_key": "abc"}), "ApiKey abc")
        self.assertEqual(es._authorization({"auth_type": "bearer", "token": "abc"}), "Bearer abc")
        value = es._authorization({"auth_type": "basic", "username": "u", "password": "p"})
        self.assertEqual(value, "Basic dTpw")

    def test_endpoint_requires_https_allowlist_and_public_address_by_default(self):
        base = {"endpoint": "https://es.example.test"}
        credential = {
            "auth_type": "api_key",
            "api_key": "x",
            "allowed_endpoints": ["https://es.example.test"],
        }
        public = lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))]
        client = es.ElasticsearchClient(base, credential, opener=lambda *a, **k: None, resolver=public)
        self.assertEqual(client.host, "es.example.test")
        with self.assertRaises(es.ActionError):
            es.ElasticsearchClient(
                {**base, "endpoint": "http://es.example.test"},
                credential,
                opener=lambda *a, **k: None,
                resolver=public,
            )
        with self.assertRaises(es.ActionError):
            es.ElasticsearchClient(
                {"endpoint": "https://other.example.test"},
                credential,
                opener=lambda *a, **k: None,
                resolver=public,
            )
        private = lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.1", 443))]
        with self.assertRaises(es.ActionError):
            es.ElasticsearchClient(base, credential, opener=lambda *a, **k: None, resolver=private)

    def test_private_address_requires_explicit_opt_in(self):
        params = {"endpoint": "https://es.internal"}
        credential = {
            "auth_type": "api_key",
            "api_key": "x",
            "allowed_endpoints": ["https://es.internal"],
            "allow_private_hosts": True,
        }
        private = lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.1", 443))]
        client = es.ElasticsearchClient(params, credential, opener=lambda *a, **k: None, resolver=private)
        self.assertEqual(client.host, "es.internal")

    def test_transport_requires_elasticsearch_product_header(self):
        params = {"endpoint": "https://es.example.test"}
        credential = {"auth_type": "api_key", "api_key": "x", "allowed_endpoints": ["https://es.example.test"]}
        public = lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))]
        opener = lambda *args, **kwargs: FakeResponse({"version": {"number": "2.0"}}, product="OpenSearch")
        client = es.ElasticsearchClient(params, credential, opener=opener, resolver=public)
        with self.assertRaises(es.ActionError):
            client.request("GET", "/")

    def test_transport_redacts_structured_output(self):
        params = {"endpoint": "https://es.example.test"}
        credential = {"auth_type": "api_key", "api_key": "x", "allowed_endpoints": ["https://es.example.test"]}
        public = lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))]
        opener = lambda *args, **kwargs: FakeResponse({"token": "secret", "safe": "yes"})
        client = es.ElasticsearchClient(params, credential, opener=opener, resolver=public)
        result = client.request("GET", "/")
        self.assertEqual(result["data"], {"token": "[REDACTED]", "safe": "yes"})

    def test_server_version_is_limited_to_elasticsearch_8_and_9(self):
        params = {"endpoint": "https://es.example.test"}
        credential = {"auth_type": "api_key", "api_key": "x", "allowed_endpoints": ["https://es.example.test"]}
        public = lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))]
        supported = es.ElasticsearchClient(
            params,
            credential,
            opener=lambda *a, **k: FakeResponse({"version": {"number": "9.1.0"}}),
            resolver=public,
        )
        supported.verify_server()
        unsupported = es.ElasticsearchClient(
            params,
            credential,
            opener=lambda *a, **k: FakeResponse({"version": {"number": "7.17.0"}}),
            resolver=public,
        )
        with self.assertRaises(es.ActionError):
            unsupported.verify_server()

    def test_http_error_does_not_leak_authorization(self):
        params = {"endpoint": "https://es.example.test"}
        credential = {"auth_type": "bearer", "token": "topsecret", "allowed_endpoints": ["https://es.example.test"]}
        public = lambda *args, **kwargs: [(None, None, None, None, ("8.8.8.8", 443))]

        def opener(request, timeout):
            payload = json.dumps({"error": {"type": "x", "reason": "Bearer topsecret denied"}}).encode()
            raise HTTPError(request.full_url, 401, "denied", {}, io.BytesIO(payload))

        client = es.ElasticsearchClient(params, credential, opener=opener, resolver=public)
        with self.assertRaises(es.ActionError) as context:
            client.request("GET", "/")
        self.assertNotIn("topsecret", str(context.exception))

    def test_attune_key_must_be_pack_owned(self):
        previous = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(previous)))
        os.environ["ATTUNE_API_URL"] = "https://attune.example.test"
        os.environ["ATTUNE_API_TOKEN"] = "execution-token"
        good = lambda *args, **kwargs: FakeResponse(
            {"data": {"owner_pack_ref": "elasticsearch", "value": {"auth_type": "api_key", "api_key": "x"}}}
        )
        self.assertEqual(es._attune_key("elasticsearch.production", good)["api_key"], "x")
        bad = lambda *args, **kwargs: FakeResponse(
            {"data": {"owner_pack_ref": "other", "value": {"auth_type": "api_key", "api_key": "x"}}}
        )
        with self.assertRaises(es.ActionError):
            es._attune_key("elasticsearch.production", bad)
        with self.assertRaises(es.ActionError):
            es._attune_key("other.production", good)

    def test_response_size_limit(self):
        class LargeResponse(FakeResponse):
            def read(self, size=-1):
                return b"x" * (size + 1)

        with self.assertRaises(es.ActionError):
            es._read_limited(LargeResponse({}), 10)


if __name__ == "__main__":
    unittest.main()
