import copy
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

import requests
from fastapi import Body
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from pydantic import BaseModel
from pydantic import Field


OPA_URL = os.getenv("OPA_URL", "http://opa.opa.svc.cluster.local:8181").rstrip("/")
POLICY_SYNC_BACKEND = os.getenv("POLICY_SYNC_BACKEND", "opal").strip().lower()
OPAL_SERVER_URL = os.getenv("OPAL_SERVER_URL", "http://opal-server.opal.svc.cluster.local:7002").rstrip("/")
OPAL_SERVER_TOKEN = os.getenv("OPAL_SERVER_TOKEN", "").strip()
OPAL_MASTER_TOKEN = os.getenv("OPAL_MASTER_TOKEN", "").strip()
OPAL_DATA_TOPIC = os.getenv("OPAL_DATA_TOPIC", "tenant_policies").strip() or "tenant_policies"
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "20"))
VERIFY_TLS = os.getenv("OPA_VERIFY_TLS", "false").lower() == "true"
OPAL_VERIFY_TLS = os.getenv("OPAL_VERIFY_TLS", "false").lower() == "true"
AUDIT_MAX_EVENTS = max(100, int(os.getenv("AUDIT_MAX_EVENTS", "1000")))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "").strip()

_POLICY_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()
_OPAL_DATASOURCE_TOKEN: str | None = None
_AUDIT_EVENTS: list[dict[str, Any]] = []
_AUDIT_LOCK = threading.Lock()


app = FastAPI(
    title="PEP Proxy",
    version="0.2.0",
    description="FastAPI reference implementation for OPA policy data management, audit, replay, and non-gateway authorization.",
)


class PolicyPackageRequest(BaseModel):
    version: str | None = None
    policies: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DbAuthorizeRequest(BaseModel):
    tenant_id: str
    user: str | None = None
    roles: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    action: str
    resource: str
    resource_kind: str = "database"
    context: dict[str, Any] = Field(default_factory=dict)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _append_audit_file(event: dict[str, Any]) -> None:
    if not AUDIT_LOG_PATH:
        return
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _redact(value: Any) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump() if hasattr(value, "model_dump") else value.dict()
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            k_lower = str(k).lower()
            if any(token in k_lower for token in ("token", "secret", "password")):
                out[k] = "***redacted***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(x) for x in value]
    return value


def _actor_from_request(request: Request, tenant_hint: str | None = None) -> dict[str, Any]:
    client = request.client
    return {
        "user": request.headers.get("x-user") or "anonymous",
        "tenant_id": request.headers.get("x-tenant-id") or tenant_hint,
        "client_id": request.headers.get("x-client-id"),
        "roles": request.headers.get("x-roles"),
        "groups": request.headers.get("x-groups"),
        "request_id": request.headers.get("x-request-id"),
        "client_host": client.host if client else None,
    }


def _record_audit_event(
    *,
    request: Request,
    action: str,
    tenant_id: str | None,
    payload: Any = None,
    result: Any = None,
    replayable: bool = False,
    replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "action": action,
        "tenant_id": tenant_id,
        "actor": _actor_from_request(request, tenant_id),
        "request": {"method": request.method, "path": request.url.path, "query": dict(request.query_params)},
        "payload": _redact(payload),
        "result": _redact(result),
        "replayable": replayable,
        "replay": _redact(replay),
    }
    with _AUDIT_LOCK:
        _AUDIT_EVENTS.append(event)
        if len(_AUDIT_EVENTS) > AUDIT_MAX_EVENTS:
            del _AUDIT_EVENTS[0 : len(_AUDIT_EVENTS) - AUDIT_MAX_EVENTS]
    _append_audit_file(event)
    return event


def _next_policy_version() -> str:
    return datetime.now(timezone.utc).strftime("v%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]


def _normalize_policy_rule(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="Each policy entry must be an object")
    policy = copy.deepcopy(raw)
    if not policy.get("name"):
        raise HTTPException(status_code=400, detail="Policy 'name' is required")
    effect = str(policy.get("effect", "allow")).lower()
    if effect not in {"allow", "deny"}:
        raise HTTPException(status_code=400, detail=f"Invalid effect for policy {policy.get('name')}: {effect}")
    policy["effect"] = effect
    resource_kind = str(policy.get("resource_kind", "api")).lower()
    if resource_kind not in {"api", "database"}:
        raise HTTPException(status_code=400, detail=f"Invalid resource_kind for policy {policy.get('name')}: {resource_kind}")
    policy["resource_kind"] = resource_kind
    if "resources" not in policy or not isinstance(policy["resources"], list) or not policy["resources"]:
        raise HTTPException(status_code=400, detail=f"Policy {policy.get('name')} requires non-empty 'resources' list")
    if "subjects" not in policy or not isinstance(policy["subjects"], list) or not policy["subjects"]:
        raise HTTPException(status_code=400, detail=f"Policy {policy.get('name')} requires non-empty 'subjects' list")
    if "actions" not in policy or not isinstance(policy["actions"], list) or not policy["actions"]:
        raise HTTPException(status_code=400, detail=f"Policy {policy.get('name')} requires non-empty 'actions' list")
    if resource_kind == "database":
        allowed_actions = {"query", "write", "admin", "read", "update", "delete", "create"}
        if any(str(a).lower() not in allowed_actions for a in policy["actions"]):
            raise HTTPException(status_code=400, detail=f"Database policy {policy.get('name')} contains unsupported action")
    return policy


def _normalize_policy_package(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        policies = [_normalize_policy_rule(item) for item in payload]
        return {"version": _next_policy_version(), "updated_at": _now_iso(), "metadata": {}, "policies": policies}
    if isinstance(payload, dict):
        if "policies" in payload and isinstance(payload.get("policies"), list):
            version = str(payload.get("version") or _next_policy_version())
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            policies = [_normalize_policy_rule(item) for item in payload["policies"]]
            return {"version": version, "updated_at": _now_iso(), "metadata": metadata, "policies": policies}
    raise HTTPException(status_code=400, detail="Body must be a policy list or {version?, metadata?, policies:[...]} object")


def _extract_policy_list(package_or_legacy: Any) -> list[dict[str, Any]]:
    if isinstance(package_or_legacy, dict) and isinstance(package_or_legacy.get("policies"), list):
        return list(package_or_legacy["policies"])
    if isinstance(package_or_legacy, list):
        return list(package_or_legacy)
    return []


def _opa_request(
    method: str,
    path: str,
    *,
    expected: tuple[int, ...] = (200, 204),
    json: Any = None,
) -> requests.Response:
    url = f"{OPA_URL}{path}"
    resp = requests.request(
        method=method,
        url=url,
        json=json,
        headers={"Content-Type": "application/json"},
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )
    if resp.status_code not in expected:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Unexpected response from OPA",
                "method": method,
                "path": path,
                "status_code": resp.status_code,
                "body": resp.text,
            },
        )
    return resp


def _opal_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = _get_opal_publish_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_opal_publish_token() -> str:
    global _OPAL_DATASOURCE_TOKEN
    if OPAL_SERVER_TOKEN:
        return OPAL_SERVER_TOKEN
    if _OPAL_DATASOURCE_TOKEN:
        return _OPAL_DATASOURCE_TOKEN
    if not OPAL_MASTER_TOKEN:
        return ""

    resp = requests.post(
        f"{OPAL_SERVER_URL}/token",
        json={"type": "datasource"},
        headers={
            "Authorization": f"Bearer {OPAL_MASTER_TOKEN}",
            "Content-Type": "application/json",
        },
        timeout=REQUEST_TIMEOUT,
        verify=OPAL_VERIFY_TLS,
    )
    if resp.status_code != 200:
        # Some OPAL deployments run without security enabled and reject token minting.
        # In that mode, publish requests should proceed without Authorization headers.
        if "not configured with security" in resp.text.lower():
            return ""
        raise HTTPException(status_code=502, detail=f"Failed to obtain OPAL datasource token: {resp.text}")
    body = resp.json()
    token = body.get("token") or ""
    if not token:
        raise HTTPException(status_code=502, detail="OPAL /token response missing 'token' field")
    _OPAL_DATASOURCE_TOKEN = token
    return token


def _opal_request(method: str, path: str, *, expected: tuple[int, ...] = (200, 201, 204), json: Any = None) -> requests.Response:
    url = f"{OPAL_SERVER_URL}{path}"
    resp = requests.request(
        method=method,
        url=url,
        json=json,
        headers=_opal_headers(),
        timeout=REQUEST_TIMEOUT,
        verify=OPAL_VERIFY_TLS,
    )
    if resp.status_code not in expected:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Unexpected response from OPAL server",
                "method": method,
                "path": path,
                "status_code": resp.status_code,
                "body": resp.text,
            },
        )
    return resp


def _publish_opal_put(tenant_id: str, policy_package: dict[str, Any]) -> None:
    payload = {
        "reason": f"pep-proxy upsert tenant policies ({tenant_id})",
        "entries": [
            {
                "url": "",
                "topics": [OPAL_DATA_TOPIC],
                "dst_path": f"/tenant_policies/{tenant_id}",
                "save_method": "PUT",
                "data": policy_package,
            }
        ],
    }
    _opal_request("POST", "/data/config", expected=(200, 201), json=payload)


def _publish_opal_delete(tenant_id: str) -> None:
    payload = {
        "reason": f"pep-proxy delete tenant policies ({tenant_id})",
        "entries": [
            {
                "url": "",
                "topics": [OPAL_DATA_TOPIC],
                "dst_path": "/tenant_policies",
                "save_method": "PATCH",
                "data": [{"op": "remove", "path": f"/{tenant_id}"}],
            }
        ],
    }
    _opal_request("POST", "/data/config", expected=(200, 201), json=payload)


def _cache_set(tenant_id: str, policy_package: dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _POLICY_CACHE[tenant_id] = copy.deepcopy(policy_package)


def _cache_get_package(tenant_id: str) -> dict[str, Any]:
    with _CACHE_LOCK:
        return copy.deepcopy(_POLICY_CACHE.get(tenant_id) or {"version": "", "updated_at": "", "metadata": {}, "policies": []})


def _cache_get_policies(tenant_id: str) -> list[dict[str, Any]]:
    package = _cache_get_package(tenant_id)
    return _extract_policy_list(package)


def _cache_delete(tenant_id: str) -> None:
    with _CACHE_LOCK:
        _POLICY_CACHE.pop(tenant_id, None)


def _cache_snapshot() -> dict[str, dict[str, Any]]:
    with _CACHE_LOCK:
        return {tenant_id: copy.deepcopy(pkg) for tenant_id, pkg in _POLICY_CACHE.items()}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    resp = requests.get(f"{OPA_URL}/health", timeout=REQUEST_TIMEOUT, verify=VERIFY_TLS)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"OPA health check failed: {resp.text}")
    if POLICY_SYNC_BACKEND == "opal":
        # OPAL server health endpoint can vary across versions; try the common one first.
        opal_resp = requests.get(
            f"{OPAL_SERVER_URL}/healthcheck",
            timeout=REQUEST_TIMEOUT,
            verify=OPAL_VERIFY_TLS,
            headers={"Content-Type": "application/json"},
        )
        if opal_resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"OPAL server health check failed: {opal_resp.text}")
    return {"status": "ok", "sync_backend": POLICY_SYNC_BACKEND}


@app.put("/tenants/{tenant_id}/policies")
def upsert_tenant_policies(tenant_id: str, request: Request, policies: Any = Body(...)) -> dict[str, Any]:
    policy_package = _normalize_policy_package(policies)
    if POLICY_SYNC_BACKEND == "opal":
        _publish_opal_put(tenant_id, policy_package)
        _cache_set(tenant_id, policy_package)
    else:
        _opa_request("PUT", f"/v1/data/tenant_policies/{tenant_id}", expected=(204,), json=policy_package)
    result = {
        "tenant_id": tenant_id,
        "count": len(policy_package["policies"]),
        "status": "upserted",
        "policy_version": policy_package["version"],
    }
    _record_audit_event(
        request=request,
        action="upsert_tenant_policies",
        tenant_id=tenant_id,
        payload=policy_package,
        result=result,
        replayable=True,
        replay={"endpoint": f"/tenants/{tenant_id}/policies", "method": "PUT", "body": policy_package},
    )
    return result


@app.get("/tenants/{tenant_id}/policies")
def get_tenant_policies(tenant_id: str) -> list[dict[str, Any]]:
    if POLICY_SYNC_BACKEND == "opal":
        return _cache_get_policies(tenant_id)
    resp = requests.get(
        f"{OPA_URL}/v1/data/tenant_policies/{tenant_id}",
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )
    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Failed to query tenant policies: {resp.text}")
    body = resp.json()
    return _extract_policy_list(body.get("result"))


@app.get("/tenants/{tenant_id}/policy-package")
def get_tenant_policy_package(tenant_id: str) -> dict[str, Any]:
    if POLICY_SYNC_BACKEND == "opal":
        return _cache_get_package(tenant_id)
    resp = requests.get(
        f"{OPA_URL}/v1/data/tenant_policies/{tenant_id}",
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS,
    )
    if resp.status_code == 404:
        return {"version": "", "updated_at": "", "metadata": {}, "policies": []}
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Failed to query tenant policy package: {resp.text}")
    result = resp.json().get("result") or {}
    if isinstance(result, list):
        return {"version": "legacy-list", "updated_at": "", "metadata": {}, "policies": result}
    if isinstance(result, dict):
        return result
    return {"version": "", "updated_at": "", "metadata": {}, "policies": []}


@app.delete("/tenants/{tenant_id}/policies")
def delete_tenant_policies(tenant_id: str, request: Request) -> dict[str, str]:
    before = get_tenant_policy_package(tenant_id)
    if POLICY_SYNC_BACKEND == "opal":
        _publish_opal_delete(tenant_id)
        _cache_delete(tenant_id)
    else:
        _opa_request("DELETE", f"/v1/data/tenant_policies/{tenant_id}", expected=(204, 404))
    result = {"tenant_id": tenant_id, "status": "deleted"}
    _record_audit_event(
        request=request,
        action="delete_tenant_policies",
        tenant_id=tenant_id,
        payload={"before": before},
        result=result,
        replayable=True,
        replay={"endpoint": f"/tenants/{tenant_id}/policies", "method": "DELETE"},
    )
    return result


@app.get("/tenants")
def list_policy_tenants() -> list[str]:
    if POLICY_SYNC_BACKEND == "opal":
        return sorted(_cache_snapshot().keys())
    resp = _opa_request("GET", "/v1/data/tenant_policies", expected=(200,))
    result = resp.json().get("result") or {}
    if isinstance(result, dict):
        return sorted(result.keys())
    return []


@app.get("/opal/snapshots/tenant_policies")
def opal_tenant_policies_snapshot() -> dict[str, Any]:
    """Snapshot endpoint for OPAL data source bootstrap."""
    return _cache_snapshot()


@app.get("/audit/events")
def list_audit_events(
    tenant_id: str | None = None,
    action: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    with _AUDIT_LOCK:
        events = list(_AUDIT_EVENTS)
    if tenant_id:
        events = [e for e in events if e.get("tenant_id") == tenant_id]
    if action:
        events = [e for e in events if e.get("action") == action]
    return events[-limit:]


@app.get("/audit/events/{event_id}")
def get_audit_event(event_id: str) -> dict[str, Any]:
    with _AUDIT_LOCK:
        for event in _AUDIT_EVENTS:
            if event.get("id") == event_id:
                return event
    raise HTTPException(status_code=404, detail="Audit event not found")


@app.post("/audit/replay/{event_id}")
def replay_audit_event(event_id: str, request: Request) -> dict[str, Any]:
    event = get_audit_event(event_id)
    replay = event.get("replay")
    if not event.get("replayable") or not isinstance(replay, dict):
        raise HTTPException(status_code=400, detail="Audit event is not replayable")
    path = str(replay.get("endpoint") or "")
    method = str(replay.get("method") or "").upper()
    if not path or method not in {"PUT", "DELETE"}:
        raise HTTPException(status_code=400, detail="Unsupported replay event")
    if method == "PUT":
        if not path.startswith("/tenants/") or not path.endswith("/policies"):
            raise HTTPException(status_code=400, detail="Unsupported replay target")
        tenant_id = path.split("/")[2]
        body = replay.get("body") or {}
        policy_package = _normalize_policy_package(body)
        if POLICY_SYNC_BACKEND == "opal":
            _publish_opal_put(tenant_id, policy_package)
            _cache_set(tenant_id, policy_package)
        else:
            _opa_request("PUT", f"/v1/data/tenant_policies/{tenant_id}", expected=(204,), json=policy_package)
        result = {"replayed_event_id": event_id, "tenant_id": tenant_id, "status": "replayed", "policy_version": policy_package["version"]}
    else:
        if not path.startswith("/tenants/") or not path.endswith("/policies"):
            raise HTTPException(status_code=400, detail="Unsupported replay target")
        tenant_id = path.split("/")[2]
        if POLICY_SYNC_BACKEND == "opal":
            _publish_opal_delete(tenant_id)
            _cache_delete(tenant_id)
        else:
            _opa_request("DELETE", f"/v1/data/tenant_policies/{tenant_id}", expected=(204, 404))
        result = {"replayed_event_id": event_id, "tenant_id": tenant_id, "status": "replayed_delete"}
    _record_audit_event(
        request=request,
        action="replay_audit_event",
        tenant_id=result.get("tenant_id"),
        payload={"source_event_id": event_id},
        result=result,
    )
    return result


@app.post("/authorize/db")
def authorize_db(payload: DbAuthorizeRequest) -> dict[str, Any]:
    opa_input = {
        "tenant_id": payload.tenant_id,
        "subject": {
            "user": payload.user,
            "roles": payload.roles,
            "groups": payload.groups,
        },
        "request": {
            "action": payload.action,
            "resource": payload.resource,
            "resource_kind": payload.resource_kind,
            "context": payload.context,
        },
    }
    resp = _opa_request("POST", "/v1/data/envoy/authz/app_decision", expected=(200,), json={"input": opa_input})
    return resp.json()


@app.post("/simulate")
def simulate(payload: dict[str, Any]) -> dict[str, Any]:
    resp = _opa_request("POST", "/v1/data/envoy/authz/decision", expected=(200,), json=payload)
    return resp.json()
