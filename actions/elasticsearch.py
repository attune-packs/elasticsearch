#!/usr/bin/env python3
"""Curated, dependency-free Elasticsearch 8/9 REST actions."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


MAX_REQUEST_BYTES = 5 * 1024 * 1024
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_BULK_OPERATIONS = 1000
MAX_SEARCH_SIZE = 500
MAX_QUERY_CLAUSES = 200
MAX_QUERY_DEPTH = 20
MAX_TARGETS = 20
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")
RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
SENSITIVE_KEY_RE = re.compile(
    r"(authorization|password|passwd|secret|token|api[_-]?key|access[_-]?key)", re.I
)


class ActionError(Exception):
    """Safe error suitable for action output."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ActionError("HTTP redirects are not allowed")


def _required(params: dict[str, Any], name: str) -> Any:
    value = params.get(name)
    if value is None or value == "" or value == []:
        raise ActionError(f"Missing required parameter: {name}")
    return value


def _object(params: dict[str, Any], name: str, default: Any = None) -> dict[str, Any]:
    value = params.get(name, default if default is not None else {})
    if not isinstance(value, dict):
        raise ActionError(f"Parameter {name} must be a JSON object")
    return value


def _list(params: dict[str, Any], name: str, default: Any = None) -> list[Any]:
    value = params.get(name, default if default is not None else [])
    if not isinstance(value, list):
        raise ActionError(f"Parameter {name} must be a JSON array")
    return value


def _integer(params: dict[str, Any], name: str, default: int, low: int, high: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ActionError(f"Parameter {name} must be an integer from {low} to {high}")
    return value


def _segment(value: str, kind: str, *, lower: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise ActionError(f"{kind} must be a non-empty string")
    pattern = NAME_RE if lower else RESOURCE_RE
    if not pattern.fullmatch(value) or value in {".", "..", "_all", "*"}:
        raise ActionError(f"Invalid concrete {kind}")
    if lower and value.startswith("."):
        raise ActionError(f"System or hidden {kind} names are not allowed")
    return quote(value, safe="")


def _index(value: str) -> str:
    return _segment(value, "index", lower=True)


def _targets(values: list[Any], kind: str = "index") -> str:
    if not values or len(values) > MAX_TARGETS:
        raise ActionError(f"targets must contain 1 to {MAX_TARGETS} concrete names")
    encoded = [_index(value) if kind == "index" else _segment(value, kind) for value in values]
    if len(set(encoded)) != len(encoded):
        raise ActionError("Duplicate targets are not allowed")
    return ",".join(encoded)


def _confirm(params: dict[str, Any], operation: str, subject: str) -> None:
    expected = f"CONFIRM:{operation}:{subject}"
    if params.get("confirm") != expected:
        raise ActionError(f"Destructive operation requires confirm={expected}")


def _reject_scripts(value: Any, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    if depth > MAX_QUERY_DEPTH:
        raise ActionError(f"JSON nesting exceeds {MAX_QUERY_DEPTH} levels")
    if isinstance(value, dict):
        for key, child in value.items():
            count[0] += 1
            if count[0] > MAX_QUERY_CLAUSES:
                raise ActionError(f"JSON object exceeds {MAX_QUERY_CLAUSES} clauses")
            normalized = str(key).lower()
            if "script" in normalized or normalized in {"runtime_mappings", "percolate"}:
                raise ActionError("Scripts, runtime mappings, and percolate queries are disabled")
            _reject_scripts(child, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for child in value:
            _reject_scripts(child, depth=depth + 1, count=count)


def _validate_query(value: dict[str, Any]) -> None:
    _reject_scripts(value)
    expensive = {"regexp", "wildcard", "fuzzy", "prefix"}

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower() in expensive:
                    raise ActionError("Regexp, wildcard, fuzzy, and prefix queries are disabled")
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)


def _redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]"
            if SENSITIVE_KEY_RE.search(str(key))
            else _redact(child, secrets)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, str):
        redacted = re.sub(r"(?i)\b(?:ApiKey|Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]", value)
        for secret in secrets:
            if secret:
                redacted = redacted.replace(secret, "[REDACTED]")
        return redacted
    return value


def _safe_error_payload(raw: bytes, secrets: tuple[str, ...] = ()) -> str:
    try:
        payload = json.loads(raw.decode("utf-8"))
        error = payload.get("error", payload) if isinstance(payload, dict) else payload
        if isinstance(error, dict):
            safe = {
                key: error[key]
                for key in ("type", "reason", "root_cause")
                if key in error
            }
            return json.dumps(_redact(safe, secrets), separators=(",", ":"))[:2000]
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "response body omitted"


def _read_limited(response: Any, limit: int) -> bytes:
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ActionError(f"Response exceeds {limit} bytes")
    return raw


def _attune_key(ref: str, opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    if not isinstance(ref, str) or not re.fullmatch(r"elasticsearch\.[a-z0-9_-]+", ref):
        raise ActionError("credential_key_ref must be an elasticsearch.* pack key")
    api_url = os.environ.get("ATTUNE_API_URL", "").rstrip("/")
    token = os.environ.get("ATTUNE_API_TOKEN", "")
    if not api_url or not token:
        raise ActionError("Attune execution API access is unavailable")
    parsed = urlsplit(api_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ActionError("ATTUNE_API_URL is invalid")
    request = Request(
        f"{api_url}/api/v1/keys/{quote(ref, safe='')}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    open_request = opener or build_opener(ProxyHandler({}), NoRedirect()).open
    try:
        with open_request(request, timeout=10) as response:
            payload = json.loads(_read_limited(response, 64 * 1024).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActionError("Unable to retrieve the Attune credential key") from exc
    key = payload.get("data", payload) if isinstance(payload, dict) else None
    if not isinstance(key, dict) or key.get("owner_pack_ref") != "elasticsearch":
        raise ActionError("Credential key is not owned by the elasticsearch pack")
    value = key.get("value")
    if not isinstance(value, dict):
        raise ActionError("Credential key value must be a JSON object")
    return value


def _authorization(credential: dict[str, Any]) -> str:
    auth_type = credential.get("auth_type")
    if auth_type == "api_key":
        value = credential.get("api_key")
        prefix = "ApiKey"
    elif auth_type == "bearer":
        value = credential.get("token")
        prefix = "Bearer"
    elif auth_type == "basic":
        username = credential.get("username")
        password = credential.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise ActionError("Basic credential requires username and password strings")
        value = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        prefix = "Basic"
    else:
        raise ActionError("Credential auth_type must be api_key, bearer, or basic")
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise ActionError("Credential value is invalid")
    return f"{prefix} {value}"


class ElasticsearchClient:
    """HTTPS client with endpoint pinning, bounded IO, and no retries or redirects."""

    def __init__(
        self,
        params: dict[str, Any],
        credential: dict[str, Any],
        *,
        opener: Callable[..., Any] | None = None,
        resolver: Callable[..., Any] = socket.getaddrinfo,
    ) -> None:
        endpoint = str(_required(params, "endpoint")).rstrip("/")
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ActionError("endpoint must be an HTTPS origin without credentials or a path")
        allowed_endpoints = _list(credential, "allowed_endpoints")
        if not allowed_endpoints or len(allowed_endpoints) > 20:
            raise ActionError("Credential must allow 1 to 20 exact HTTPS origins")
        normalized_endpoints = {str(origin).rstrip("/") for origin in allowed_endpoints}
        if endpoint not in normalized_endpoints:
            raise ActionError("endpoint is not authorized by the credential key")
        self.host = parsed.hostname.rstrip(".").lower()
        try:
            addresses = {
                item[4][0]
                for item in resolver(self.host, parsed.port or 443, type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError) as exc:
            raise ActionError("Unable to resolve endpoint host") from exc
        if not addresses:
            raise ActionError("Endpoint host did not resolve")
        if not credential.get("allow_private_hosts", False):
            for address in addresses:
                ip = ipaddress.ip_address(address)
                if not ip.is_global:
                    raise ActionError("Private, loopback, link-local, and reserved endpoints are blocked")
        self.endpoint = endpoint
        self.timeout = _integer(params, "timeout_seconds", 30, 1, 300)
        self.authorization = _authorization(credential)
        ca_file = credential.get("ca_file")
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise ActionError("Unable to load the custom CA file") from exc
        self.opener = opener or build_opener(
            ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context)
        ).open

    def verify_server(self) -> None:
        response = self.request("GET", "/")
        data = response.get("data", {})
        version = data.get("version", {}).get("number") if isinstance(data, dict) else None
        try:
            major = int(str(version).split(".", 1)[0])
        except (TypeError, ValueError) as exc:
            raise ActionError("Elasticsearch version response is invalid") from exc
        if major not in {8, 9}:
            raise ActionError("Only Elasticsearch major versions 8 and 9 are supported")
        self.major = major

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        encoded: bytes | None = None
        if body is not None:
            if content_type == "application/x-ndjson":
                encoded = body if isinstance(body, bytes) else str(body).encode("utf-8")
            else:
                encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            if len(encoded) > MAX_REQUEST_BYTES:
                raise ActionError(f"Request exceeds {MAX_REQUEST_BYTES} bytes")
        url = f"{self.endpoint}{path}"
        if query:
            clean_query = {key: value for key, value in query.items() if value is not None}
            url += "?" + urlencode(clean_query)
        headers = {
            "Accept": "application/json",
            "Authorization": self.authorization,
            "X-Opaque-Id": "attune-elasticsearch",
        }
        if encoded is not None:
            headers["Content-Type"] = content_type
        request = Request(url, data=encoded, headers=headers, method=method)
        try:
            with self.opener(request, timeout=self.timeout) as response:
                product = response.headers.get("X-Elastic-Product")
                if product != "Elasticsearch":
                    raise ActionError("Endpoint did not identify as Elasticsearch")
                raw = _read_limited(response, MAX_RESPONSE_BYTES)
                status = getattr(response, "status", 200)
        except HTTPError as exc:
            raw = _read_limited(exc, min(MAX_RESPONSE_BYTES, 1024 * 1024))
            raise ActionError(
                f"Elasticsearch HTTP {exc.code}: "
                f"{_safe_error_payload(raw, (self.authorization, self.authorization.split(' ', 1)[-1]))}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ActionError("Elasticsearch request failed; outcome may be unknown for mutations") from exc
        if not raw:
            data: Any = {}
        else:
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ActionError("Elasticsearch returned invalid JSON") from exc
        return {"status": status, "data": _redact(data)}


def _result(operation: str, response: dict[str, Any]) -> dict[str, Any]:
    data = response["data"]
    if isinstance(data, list):
        data = {"items": data, "count": len(data)}
    return {
        "ok": True,
        "operation": operation,
        "status": response["status"],
        "data": data,
    }


def cluster(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    paths = {"health": "/_cluster/health", "info": "/", "stats": "/_cluster/stats"}
    if operation not in paths:
        raise ActionError("Unsupported cluster operation")
    query = {"level": "cluster"} if operation == "health" else None
    return _result(operation, client.request("GET", paths[operation], query=query))


def index(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    if operation == "list":
        limit = _integer(params, "limit", 100, 1, 1000)
        response = client.request(
            "GET",
            "/_cat/indices",
            query={
                "format": "json",
                "h": "health,status,index,uuid,pri,rep,docs.count,store.size",
                "s": "index",
                "bytes": "b",
                "expand_wildcards": "open",
            },
        )
        if isinstance(response["data"], list):
            response["data"] = response["data"][:limit]
        return _result(operation, response)

    name = str(_required(params, "index"))
    target = _index(name)
    if operation == "get":
        return _result(operation, client.request("GET", f"/{target}"))
    if operation == "settings_get":
        return _result(operation, client.request("GET", f"/{target}/_settings", query={"flat_settings": "true"}))
    if operation == "mappings_get":
        return _result(operation, client.request("GET", f"/{target}/_mapping"))
    if operation == "create":
        body = _object(params, "body")
        _reject_scripts(body)
        if any(key not in {"settings", "mappings", "aliases"} for key in body):
            raise ActionError("Index create body supports only settings, mappings, and aliases")
        return _result(operation, client.request("PUT", f"/{target}", body=body))
    if operation == "settings_update":
        settings = _object(params, "body")
        allowed = {
            "index.number_of_replicas",
            "number_of_replicas",
            "index.refresh_interval",
            "refresh_interval",
            "index.lifecycle.name",
            "index.lifecycle.rollover_alias",
        }
        if not settings or any(key not in allowed for key in settings):
            raise ActionError("Index settings update contains a non-curated setting")
        if any("lifecycle" in key for key in settings):
            _confirm(params, operation, name)
        return _result(operation, client.request("PUT", f"/{target}/_settings", body=settings))
    if operation == "mappings_update":
        body = _object(params, "body")
        _reject_scripts(body)
        if not body or any(key in body for key in ("_doc", "doc", "type")):
            raise ActionError("Mapping body must be typeless")
        return _result(operation, client.request("PUT", f"/{target}/_mapping", body=body))
    if operation in {"delete", "close", "open"}:
        _confirm(params, operation, name)
        method = "DELETE" if operation == "delete" else "POST"
        suffix = "" if operation == "delete" else f"/_{operation}"
        return _result(operation, client.request(method, f"/{target}{suffix}"))
    if operation == "refresh":
        return _result(operation, client.request("POST", f"/{target}/_refresh"))
    if operation == "forcemerge":
        if params.get("read_only_confirmed") is not True:
            raise ActionError("forcemerge requires read_only_confirmed=true")
        _confirm(params, operation, name)
        segments = _integer(params, "max_num_segments", 1, 1, 10)
        return _result(
            operation,
            client.request("POST", f"/{target}/_forcemerge", query={"max_num_segments": segments, "flush": "true"}),
        )
    raise ActionError("Unsupported index operation")


def aliases(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    if operation == "list":
        return _result(operation, client.request("GET", "/_alias"))
    if operation != "update":
        raise ActionError("Unsupported aliases operation")
    actions = _list(params, "actions")
    if not actions or len(actions) > 100:
        raise ActionError("actions must contain 1 to 100 alias changes")
    for item in actions:
        if not isinstance(item, dict) or len(item) != 1:
            raise ActionError("Each alias action must contain exactly one operation")
        action, detail = next(iter(item.items()))
        if action not in {"add", "remove"} or not isinstance(detail, dict):
            raise ActionError("Only add and remove alias actions are allowed")
        _index(detail.get("index"))
        _segment(detail.get("alias"), "alias")
        _reject_scripts(detail)
        if isinstance(detail.get("filter"), dict):
            _validate_query(detail["filter"])
    subject = ",".join(
        f"{action}:{detail['alias']}@{detail['index']}"
        for item in actions
        for action, detail in item.items()
    )
    _confirm(params, operation, subject)
    return _result(operation, client.request("POST", "/_aliases", body={"actions": actions}))


def _concurrency(params: dict[str, Any]) -> dict[str, Any]:
    seq = params.get("if_seq_no")
    term = params.get("if_primary_term")
    if (seq is None) != (term is None):
        raise ActionError("if_seq_no and if_primary_term must be provided together")
    if seq is None:
        return {}
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (seq, term)):
        raise ActionError("Optimistic concurrency values must be non-negative integers")
    return {"if_seq_no": seq, "if_primary_term": term}


def document(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    name = str(_required(params, "index"))
    target = _index(name)
    if operation == "bulk":
        return _bulk(params, client, target, name)
    document_id = _segment(str(_required(params, "document_id")), "document ID")
    path = f"/{target}/_doc/{document_id}"
    if operation == "get":
        return _result(operation, client.request("GET", path))
    query = _concurrency(params)
    if operation == "index":
        body = _object(params, "document")
        if params.get("create_only", True):
            query["op_type"] = "create"
        elif not query:
            raise ActionError("Overwrite indexing requires optimistic concurrency values")
        return _result(operation, client.request("PUT", path, query=query, body=body))
    if operation == "update":
        body = _object(params, "document")
        if not body:
            raise ActionError("document update cannot be empty")
        update = {"doc": body, "doc_as_upsert": bool(params.get("doc_as_upsert", False))}
        return _result(operation, client.request("POST", f"/{target}/_update/{document_id}", query=query, body=update))
    if operation == "delete":
        _confirm(params, operation, f"{name}/{params['document_id']}")
        return _result(operation, client.request("DELETE", path, query=query))
    raise ActionError("Unsupported document operation")


def _bulk(
    params: dict[str, Any], client: ElasticsearchClient, target: str, index_name: str
) -> dict[str, Any]:
    operations = _list(params, "operations")
    if not operations or len(operations) > MAX_BULK_OPERATIONS:
        raise ActionError(f"operations must contain 1 to {MAX_BULK_OPERATIONS} items")
    lines: list[str] = []
    has_delete = False
    for item in operations:
        if not isinstance(item, dict):
            raise ActionError("Each bulk item must be an object")
        action = item.get("action")
        if action not in {"create", "index", "update", "delete"}:
            raise ActionError("Bulk action must be create, index, update, or delete")
        document_id = item.get("document_id")
        metadata: dict[str, Any] = {}
        if document_id is not None:
            _segment(str(document_id), "document ID")
            metadata["_id"] = str(document_id)
        if action in {"update", "delete"} and document_id is None:
            raise ActionError(f"Bulk {action} requires document_id")
        if item.get("if_seq_no") is not None or item.get("if_primary_term") is not None:
            concurrent = _concurrency(item)
            metadata.update(concurrent)
        if action == "index" and "if_seq_no" not in metadata:
            raise ActionError("Bulk index overwrite requires optimistic concurrency values")
        lines.append(json.dumps({action: metadata}, separators=(",", ":")))
        if action != "delete":
            body = item.get("document")
            if not isinstance(body, dict):
                raise ActionError(f"Bulk {action} requires a document object")
            if action == "update":
                body = {"doc": body, "doc_as_upsert": bool(item.get("doc_as_upsert", False))}
            lines.append(json.dumps(body, separators=(",", ":"), ensure_ascii=True))
        else:
            has_delete = True
    if has_delete:
        _confirm(params, "bulk_delete", f"{index_name}/{len(operations)}")
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return _result(
        "bulk",
        client.request("POST", f"/{target}/_bulk", body=payload, content_type="application/x-ndjson"),
    )


def search(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    targets = _list(params, "indices")
    path_target = _targets(targets)
    query = _object(params, "query", {"match_all": {}})
    _validate_query(query)
    timeout_ms = _integer(params, "query_timeout_ms", 5000, 100, 60000)
    terminate_after = _integer(params, "terminate_after", 10000, 1, 10000)
    if operation == "count":
        body = {"query": query}
        return _result(
            operation,
            client.request(
                "POST",
                f"/{path_target}/_count",
                query={"terminate_after": terminate_after},
                body=body,
            ),
        )
    if operation != "search":
        raise ActionError("Unsupported search operation")
    size = _integer(params, "size", 10, 0, MAX_SEARCH_SIZE)
    offset = _integer(params, "from", 0, 0, 10000)
    if offset + size > 10000:
        raise ActionError("from + size cannot exceed 10000; use search_after")
    sort = _list(params, "sort")
    _reject_scripts(sort)
    search_after = _list(params, "search_after")
    if search_after and (not sort or len(search_after) != len(sort) or len(sort) > 10):
        raise ActionError("search_after requires a matching sort array of at most 10 fields")
    if search_after and offset:
        raise ActionError("from and search_after cannot be combined")
    source = _list(params, "source_fields")
    if len(source) > 100 or any(not isinstance(field, str) or not field for field in source):
        raise ActionError("source_fields must contain at most 100 field names")
    body: dict[str, Any] = {
        "query": query,
        "size": size,
        "from": offset,
        "track_total_hits": 10000,
    }
    if sort:
        body["sort"] = sort
    if search_after:
        body["search_after"] = search_after
        body.pop("from", None)
    if source:
        body["_source"] = source
    return _result(
        operation,
        client.request(
            "POST",
            f"/{path_target}/_search",
            query={"timeout": f"{timeout_ms}ms", "terminate_after": terminate_after},
            body=body,
        ),
    )


def snapshot(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    if operation == "repositories":
        return _result(operation, client.request("GET", "/_snapshot"))
    repository_name = str(_required(params, "repository"))
    repository = _segment(repository_name, "snapshot repository")
    if operation == "list":
        return _result(operation, client.request("GET", f"/_snapshot/{repository}/*", query={"verbose": "false"}))
    snapshot_name = str(_required(params, "snapshot"))
    snap = _segment(snapshot_name, "snapshot")
    base = f"/_snapshot/{repository}/{snap}"
    if operation == "status":
        return _result(operation, client.request("GET", f"{base}/_status"))
    if operation == "create":
        indices = _list(params, "indices")
        body = {
            "indices": ",".join(str(item) for item in indices),
            "include_global_state": False,
            "metadata": _object(params, "metadata"),
        }
        _targets(indices)
        _reject_scripts(body)
        return _result(operation, client.request("PUT", base, query={"wait_for_completion": "false"}, body=body))
    if operation == "delete":
        _confirm(params, operation, f"{repository_name}/{snapshot_name}")
        return _result(operation, client.request("DELETE", base))
    if operation == "restore":
        indices = _list(params, "indices")
        _targets(indices)
        rename_prefix = str(_required(params, "rename_prefix"))
        if not NAME_RE.fullmatch(rename_prefix) or not rename_prefix.endswith("-"):
            raise ActionError("rename_prefix must be a safe index prefix ending in '-'")
        _confirm(params, operation, f"{repository_name}/{snapshot_name}->{rename_prefix}*")
        resolve_method = "POST" if getattr(client, "major", 8) >= 9 else "GET"
        collision = client.request(
            resolve_method, f"/_resolve/index/{quote(rename_prefix, safe='')}*"
        )
        collision_data = collision.get("data", {})
        if isinstance(collision_data, dict) and any(
            collision_data.get(kind) for kind in ("indices", "aliases", "data_streams")
        ):
            raise ActionError("Restore rename prefix collides with an existing target")
        body = {
            "indices": ",".join(str(item) for item in indices),
            "include_global_state": False,
            "include_aliases": False,
            "rename_pattern": "^(.+)$",
            "rename_replacement": f"{rename_prefix}$1",
        }
        return _result(
            operation,
            client.request(
                "POST",
                f"{base}/_restore",
                query={"wait_for_completion": "false"},
                body=body,
            ),
        )
    raise ActionError("Unsupported snapshot operation")


def data_streams(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    if operation != "list":
        raise ActionError("Unsupported data stream operation")
    name = params.get("name")
    path = "/_data_stream" if not name else f"/_data_stream/{_segment(str(name), 'data stream', lower=True)}"
    return _result(operation, client.request("GET", path, query={"expand_wildcards": "open"}))


def ilm(params: dict[str, Any], client: ElasticsearchClient) -> dict[str, Any]:
    operation = _required(params, "operation")
    if operation == "status":
        return _result(operation, client.request("GET", "/_ilm/status"))
    if operation == "explain":
        name = str(_required(params, "index"))
        return _result(operation, client.request("GET", f"/{_index(name)}/_ilm/explain"))
    policy_name = str(_required(params, "policy"))
    policy = _segment(policy_name, "ILM policy")
    path = f"/_ilm/policy/{policy}"
    if operation == "policy_get":
        return _result(operation, client.request("GET", path))
    if operation == "policy_put":
        body = _object(params, "body")
        _reject_scripts(body)
        if not isinstance(body.get("policy"), dict) or not isinstance(body["policy"].get("phases"), dict):
            raise ActionError("ILM policy body requires policy.phases")
        _confirm(params, operation, policy_name)
        return _result(operation, client.request("PUT", path, body=body))
    if operation == "policy_delete":
        _confirm(params, operation, policy_name)
        return _result(operation, client.request("DELETE", path))
    raise ActionError("Unsupported ILM operation")


DISPATCH = {
    "cluster": cluster,
    "index": index,
    "aliases": aliases,
    "document": document,
    "search": search,
    "snapshot": snapshot,
    "data_streams": data_streams,
    "ilm": ilm,
}


def run(
    params: dict[str, Any], *, key_opener: Callable[..., Any] | None = None
) -> dict[str, Any]:
    action_ref = os.environ.get("ATTUNE_ACTION", "")
    domain = action_ref.rsplit(".", 1)[-1]
    handler = DISPATCH.get(domain)
    if handler is None:
        raise ActionError("Action reference is not a curated Elasticsearch action")
    credential = _attune_key(str(_required(params, "credential_key_ref")), key_opener)
    client = ElasticsearchClient(params, credential)
    client.verify_server()
    return handler(params, client)


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ActionError(f"Action parameters exceed {MAX_REQUEST_BYTES} bytes")
        params = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        if not isinstance(params, dict):
            raise ActionError("Action parameters must be a JSON object")
        print(json.dumps(run(params), separators=(",", ":"), ensure_ascii=True))
        return 0
    except (ActionError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:2000]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
