import json
import os
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
from typing import Optional

import requests
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from pydantic import BaseModel
from pydantic import Field


KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak.keycloak.svc.cluster.local:8080").rstrip("/")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")
KEYCLOAK_VERIFY_TLS = os.getenv("KEYCLOAK_VERIFY_TLS", "false").lower() == "true"
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "20"))
AUDIT_MAX_EVENTS = max(100, int(os.getenv("AUDIT_MAX_EVENTS", "1000")))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "").strip()
ENABLE_JWT_PROVIDER_AUTOREG = os.getenv("ENABLE_JWT_PROVIDER_AUTOREG", "false").lower() == "true"
KEYCLOAK_PUBLIC_ISSUER_BASE_URL = os.getenv("KEYCLOAK_PUBLIC_ISSUER_BASE_URL", "").rstrip("/")
AGENTGATEWAY_POLICY_NAMESPACE = os.getenv("AGENTGATEWAY_POLICY_NAMESPACE", "agentgateway-system")
AGENTGATEWAY_POLICY_NAME = os.getenv("AGENTGATEWAY_POLICY_NAME", "jwt-auth-policy")
AGENTGATEWAY_IDB_POLICY_NAME = os.getenv("AGENTGATEWAY_IDB_POLICY_NAME", "idb-proxy-jwt-auth-policy")
AGENTGATEWAY_PEP_POLICY_NAME = os.getenv("AGENTGATEWAY_PEP_POLICY_NAME", "pep-proxy-jwt-auth-policy")
AGENTGATEWAY_KEYCLOAK_SERVICE_NAME = os.getenv("AGENTGATEWAY_KEYCLOAK_SERVICE_NAME", "keycloak")
AGENTGATEWAY_KEYCLOAK_SERVICE_NAMESPACE = os.getenv("AGENTGATEWAY_KEYCLOAK_SERVICE_NAMESPACE", "keycloak")
AGENTGATEWAY_KEYCLOAK_SERVICE_PORT = int(os.getenv("AGENTGATEWAY_KEYCLOAK_SERVICE_PORT", "8080"))
K8S_API_SERVER = (
    os.getenv("K8S_API_SERVER", "").strip()
    or (
        f"https://{os.getenv('KUBERNETES_SERVICE_HOST')}:{os.getenv('KUBERNETES_SERVICE_PORT_HTTPS', '443')}"
        if os.getenv("KUBERNETES_SERVICE_HOST")
        else ""
    )
)
K8S_SA_TOKEN_FILE = os.getenv("K8S_SA_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
K8S_CA_CERT_FILE = os.getenv("K8S_CA_CERT_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
K8S_VERIFY_TLS = os.getenv("K8S_VERIFY_TLS", "true").lower() == "true"

DEFAULT_CLIENT_CONF = {
    "enabled": True,
    "directAccessGrantsEnabled": True,
    "serviceAccountsEnabled": True,
    "authorizationServicesEnabled": True,
    "redirectUris": ["*"],
    "publicClient": False,
}

SPOOFABLE_TRUST_HEADERS = [
    "x-tenant-id",
    "x-user",
    "x-roles",
    "x-groups",
    "x-client-id",
    "x-authz-policy-version",
]

_AUDIT_EVENTS: list[dict[str, Any]] = []
_AUDIT_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _model_dump(model: BaseModel, *, exclude_none: bool = False) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_none=exclude_none)  # type: ignore[attr-defined]
    return model.dict(exclude_none=exclude_none)  # type: ignore[no-any-return]


def _redact(value: Any) -> Any:
    if isinstance(value, BaseModel):
        value = _model_dump(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key_lower = str(key).lower()
            if any(token in key_lower for token in ("password", "secret", "token")):
                out[key] = "***redacted***"
            elif "metadata_xml" in key_lower:
                out[key] = "***redacted_xml***"
            else:
                out[key] = _redact(item)
        return out
    if isinstance(value, list):
        return [_redact(x) for x in value]
    return value


def _append_audit_file(event: dict[str, Any]) -> None:
    if not AUDIT_LOG_PATH:
        return
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _actor_from_request(request: Request, tenant_hint: str | None = None) -> dict[str, Any]:
    client = request.client
    return {
        "user": request.headers.get("x-user") or request.headers.get("x-forwarded-user") or "anonymous",
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
    resource_type: str,
    resource_id: str | None,
    payload: Any = None,
    result: Any = None,
    status: str = "success",
    replayable: bool = False,
    replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "action": action,
        "status": status,
        "tenant_id": tenant_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
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


def _normalize_cert_pem(cert_text: str) -> str:
    compact = "".join((cert_text or "").split())
    if not compact:
        return ""
    chunks = [compact[i : i + 64] for i in range(0, len(compact), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(chunks) + "\n-----END CERTIFICATE-----"


def _pick_binding_url(elements: list[ET.Element]) -> tuple[str | None, str | None]:
    if not elements:
        return None, None
    for suffix in ("HTTP-Redirect", "HTTP-POST"):
        for el in elements:
            binding = el.attrib.get("Binding", "")
            if binding.endswith(suffix):
                return binding, el.attrib.get("Location")
    first = elements[0]
    return first.attrib.get("Binding"), first.attrib.get("Location")


def _parse_saml_metadata_xml(xml_text: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid SAML metadata XML: {exc}") from exc

    ns = {
        "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    entity = root
    if root.tag.endswith("EntitiesDescriptor"):
        found = root.find(".//md:EntityDescriptor", ns)
        if found is None:
            raise HTTPException(status_code=400, detail="SAML metadata missing EntityDescriptor")
        entity = found

    entity_id = entity.attrib.get("entityID")
    idp_descriptor = entity.find("md:IDPSSODescriptor", ns)
    if idp_descriptor is None:
        raise HTTPException(status_code=400, detail="SAML metadata missing IDPSSODescriptor")

    sso_binding, sso_url = _pick_binding_url(idp_descriptor.findall("md:SingleSignOnService", ns))
    slo_binding, slo_url = _pick_binding_url(idp_descriptor.findall("md:SingleLogoutService", ns))

    certs: list[str] = []
    for key_desc in idp_descriptor.findall("md:KeyDescriptor", ns):
        key_use = key_desc.attrib.get("use", "")
        if key_use and key_use not in ("signing",):
            continue
        for cert_el in key_desc.findall(".//ds:X509Certificate", ns):
            cert_pem = _normalize_cert_pem(cert_el.text or "")
            if cert_pem and cert_pem not in certs:
                certs.append(cert_pem)

    return {
        "entity_id": entity_id,
        "sso_binding": sso_binding,
        "sso_url": sso_url,
        "slo_binding": slo_binding,
        "slo_url": slo_url,
        "certificates": certs,
    }


app = FastAPI(
    title="IDB Proxy",
    version="0.1.0",
    description="FastAPI reference implementation for Keycloak bootstrap and tenant identity management.",
)


class TenantUser(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    groups: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)


class MasterBootstrapRequest(BaseModel):
    client_id: str = "master-gateway-client"
    super_admin_username: str = "superadmin"
    super_admin_password: str = "superadmin123"
    super_admin_email: str = "superadmin@gateway.local"


class TenantBootstrapRequest(BaseModel):
    display_name: str
    client_id: str
    tenant_admin: TenantUser
    users: list[TenantUser] = Field(default_factory=list)
    auto_register_jwt_provider: Optional[bool] = None


class RoleCreateRequest(BaseModel):
    role_name: str


class UserCreateRequest(TenantUser):
    assign_roles: list[str] = Field(default_factory=list)


class GroupCreateRequest(BaseModel):
    name: str
    parent_group_id: Optional[str] = None
    attributes: dict[str, list[str]] = Field(default_factory=dict)


class GroupUpdateRequest(BaseModel):
    name: Optional[str] = None
    attributes: Optional[dict[str, list[str]]] = None


class UserGroupMembershipRequest(BaseModel):
    group_ids: list[str] = Field(default_factory=list)
    group_names: list[str] = Field(default_factory=list)
    mode: str = "replace"  # replace | add | remove


class SamlIdPImportRequest(BaseModel):
    alias: str
    display_name: Optional[str] = None
    metadata_xml: Optional[str] = None
    metadata_url: Optional[str] = None
    enabled: bool = True
    store_token: bool = False
    trust_email: bool = True
    sync_mode: str = "IMPORT"
    first_broker_login_flow_alias: Optional[str] = "first broker login"
    post_broker_login_flow_alias: Optional[str] = None
    config_overrides: dict[str, Any] = Field(default_factory=dict)


class SamlIdPUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    enabled: Optional[bool] = None
    metadata_xml: Optional[str] = None
    metadata_url: Optional[str] = None
    trust_email: Optional[bool] = None
    store_token: Optional[bool] = None
    sync_mode: Optional[str] = None
    config_updates: dict[str, Any] = Field(default_factory=dict)
    config_remove_keys: list[str] = Field(default_factory=list)


class SamlIdPEnableRequest(BaseModel):
    enabled: bool


class SamlIdPCertRotateRequest(BaseModel):
    metadata_xml: Optional[str] = None
    metadata_url: Optional[str] = None
    signing_certificates: list[str] = Field(default_factory=list)
    update_endpoints: bool = False


class IdPMapperRequest(BaseModel):
    name: str
    identity_provider_mapper: str
    config: dict[str, Any] = Field(default_factory=dict)


class JwtProviderSyncRequest(BaseModel):
    issuer_base_url: Optional[str] = None
    enabled: Optional[bool] = None


class KeycloakClient:
    def __init__(self) -> None:
        self._token: Optional[str] = None
        self._token_expire_at = 0.0

    def _admin_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expire_at - 15:
            return self._token

        token_url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
        resp = requests.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KEYCLOAK_ADMIN_USER,
                "password": KEYCLOAK_ADMIN_PASSWORD,
            },
            timeout=REQUEST_TIMEOUT,
            verify=KEYCLOAK_VERIFY_TLS,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Failed to obtain Keycloak admin token: {resp.text}")

        body = resp.json()
        self._token = body.get("access_token")
        expires_in = int(body.get("expires_in", 60))
        self._token_expire_at = now + expires_in
        if not self._token:
            raise HTTPException(status_code=502, detail="Keycloak admin token missing access_token field")
        return self._token

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: tuple[int, ...] = (200, 201, 204),
        json: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        token = self._admin_token()
        url = f"{KEYCLOAK_URL}{path}"
        req_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if headers:
            req_headers.update(headers)
        resp = requests.request(
            method=method,
            url=url,
            headers=req_headers,
            json=json,
            params=params,
            timeout=REQUEST_TIMEOUT,
            verify=KEYCLOAK_VERIFY_TLS,
        )
        if resp.status_code not in expected:
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "Unexpected response from Keycloak",
                    "method": method,
                    "path": path,
                    "status_code": resp.status_code,
                    "body": resp.text,
                },
            )
        return resp

    def ensure_user_profile_attribute(self, realm: str, attr_name: str) -> None:
        """Register a custom attribute in Keycloak's Declarative User Profile (v24+).

        Keycloak 24+ enables Declarative User Profile by default. Custom user
        attributes that are not registered in the User Profile configuration
        are silently dropped during user creation/update.
        """
        resp = self.request("GET", f"/admin/realms/{realm}/users/profile", expected=(200,))
        profile = resp.json()
        existing_names = {a.get("name") for a in profile.get("attributes", [])}
        if attr_name in existing_names:
            return
        profile["attributes"].append(
            {
                "name": attr_name,
                "displayName": attr_name.capitalize(),
                "validations": {},
                "annotations": {},
                "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
                "multivalued": False,
            }
        )
        self.request("PUT", f"/admin/realms/{realm}/users/profile", json=profile, expected=(200,))

    def ensure_realm(self, realm: str, display_name: Optional[str] = None) -> None:
        exists = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{realm}",
            headers={"Authorization": f"Bearer {self._admin_token()}"},
            timeout=REQUEST_TIMEOUT,
            verify=KEYCLOAK_VERIFY_TLS,
        )
        if exists.status_code == 200:
            return
        if exists.status_code != 404:
            raise HTTPException(status_code=502, detail=f"Failed to read realm {realm}: {exists.text}")

        payload = {"realm": realm, "enabled": True}
        if display_name:
            payload["displayName"] = display_name
        self.request("POST", "/admin/realms", json=payload, expected=(201, 409))

    def get_client(self, realm: str, client_id: str) -> Optional[dict[str, Any]]:
        resp = self.request(
            "GET",
            f"/admin/realms/{realm}/clients",
            params={"clientId": client_id},
            expected=(200,),
        )
        items = resp.json()
        if not items:
            return None
        return items[0]

    def ensure_client(self, realm: str, client_id: str) -> tuple[str, str]:
        existing = self.get_client(realm, client_id)
        if existing is None:
            payload = {"clientId": client_id, **DEFAULT_CLIENT_CONF}
            self.request("POST", f"/admin/realms/{realm}/clients", json=payload, expected=(201, 409))
            existing = self.get_client(realm, client_id)
            if existing is None:
                raise HTTPException(status_code=502, detail=f"Failed to create client {client_id} in realm {realm}")

        client_uuid = existing["id"]
        update_payload = {"clientId": client_id, "id": client_uuid, **DEFAULT_CLIENT_CONF}
        self.request("PUT", f"/admin/realms/{realm}/clients/{client_uuid}", json=update_payload, expected=(204,))

        secret_resp = self.request("GET", f"/admin/realms/{realm}/clients/{client_uuid}/client-secret", expected=(200,))
        secret = secret_resp.json().get("value")
        if not secret:
            raise HTTPException(status_code=502, detail=f"Client {client_id} secret is empty")
        return client_uuid, secret

    def ensure_mapper(self, realm: str, client_uuid: str, mapper_name: str, payload: dict[str, Any]) -> None:
        resp = self.request(
            "GET",
            f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models",
            expected=(200,),
        )
        for mapper in resp.json():
            if mapper.get("name") == mapper_name:
                return
        self.request(
            "POST",
            f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models",
            json=payload,
            expected=(201, 409),
        )

    def _get_mapper(self, realm: str, client_uuid: str, mapper_name: str) -> Optional[dict[str, Any]]:
        resp = self.request(
            "GET",
            f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models",
            expected=(200,),
        )
        for mapper in resp.json():
            if mapper.get("name") == mapper_name:
                return mapper
        return None

    def upsert_mapper(self, realm: str, client_uuid: str, mapper_name: str, payload: dict[str, Any]) -> None:
        existing = self._get_mapper(realm, client_uuid, mapper_name)
        if existing is None:
            self.request(
                "POST",
                f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models",
                json=payload,
                expected=(201, 409),
            )
            return
        merged = {**existing, **payload}
        self.request(
            "PUT",
            f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models/{existing['id']}",
            json=merged,
            expected=(204,),
        )

    def ensure_role(self, realm: str, role_name: str) -> dict[str, Any]:
        get_resp = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{realm}/roles/{role_name}",
            headers={"Authorization": f"Bearer {self._admin_token()}"},
            timeout=REQUEST_TIMEOUT,
            verify=KEYCLOAK_VERIFY_TLS,
        )
        if get_resp.status_code == 200:
            return get_resp.json()
        if get_resp.status_code != 404:
            raise HTTPException(status_code=502, detail=f"Failed to read role {role_name}: {get_resp.text}")

        self.request("POST", f"/admin/realms/{realm}/roles", json={"name": role_name}, expected=(201, 409))
        return self.request("GET", f"/admin/realms/{realm}/roles/{role_name}", expected=(200,)).json()

    def delete_role(self, realm: str, role_name: str) -> None:
        self.request("DELETE", f"/admin/realms/{realm}/roles/{role_name}", expected=(204, 404))

    def get_user(self, realm: str, username: str) -> Optional[dict[str, Any]]:
        resp = self.request(
            "GET",
            f"/admin/realms/{realm}/users",
            params={"username": username},
            expected=(200,),
        )
        items = resp.json()
        if not items:
            return None
        for item in items:
            if item.get("username") == username:
                return item
        return items[0]

    def get_user_by_id(self, realm: str, user_id: str) -> dict[str, Any]:
        return self.request("GET", f"/admin/realms/{realm}/users/{user_id}", expected=(200,)).json()

    def ensure_user(self, realm: str, user: TenantUser) -> str:
        existing = self.get_user(realm, user.username)
        first_name = user.first_name or user.username
        last_name = user.last_name or "user"
        payload = {
            "username": user.username,
            "email": user.email,
            "enabled": True,
            "emailVerified": True,
            "firstName": first_name,
            "lastName": last_name,
            "requiredActions": [],
        }
        if existing is None:
            self.request("POST", f"/admin/realms/{realm}/users", json=payload, expected=(201, 409))
            existing = self.get_user(realm, user.username)
            if existing is None:
                raise HTTPException(status_code=502, detail=f"Failed to create user {user.username}")
        else:
            self.request("PUT", f"/admin/realms/{realm}/users/{existing['id']}", json=payload, expected=(204,))
        self.set_password(realm, existing["id"], user.password)
        return existing["id"]

    def set_password(self, realm: str, user_id: str, password: str) -> None:
        self.request(
            "PUT",
            f"/admin/realms/{realm}/users/{user_id}/reset-password",
            json={
                "type": "password",
                "value": password,
                "temporary": False,
            },
            expected=(204,),
        )

    def assign_roles(self, realm: str, user_id: str, role_names: list[str]) -> None:
        if not role_names:
            return
        existing_roles = self.request(
            "GET",
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            expected=(200,),
        ).json()
        existing_names = {x.get("name") for x in existing_roles}

        to_add: list[dict[str, Any]] = []
        for name in role_names:
            if name in existing_names:
                continue
            role_obj = self.ensure_role(realm, name)
            to_add.append(role_obj)
        if to_add:
            self.request(
                "POST",
                f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                json=to_add,
                expected=(204,),
            )

    def list_groups(self, realm: str) -> list[dict[str, Any]]:
        resp = self.request(
            "GET",
            f"/admin/realms/{realm}/groups",
            params={"briefRepresentation": "false", "max": "1000"},
            expected=(200,),
        )
        return resp.json()

    def get_group(self, realm: str, group_id: str) -> dict[str, Any]:
        return self.request(
            "GET",
            f"/admin/realms/{realm}/groups/{group_id}",
            params={"briefRepresentation": "false"},
            expected=(200,),
        ).json()

    def find_group_by_name(self, realm: str, name: str) -> Optional[dict[str, Any]]:
        stack = list(self.list_groups(realm))
        while stack:
            item = stack.pop()
            if item.get("name") == name:
                return item
            stack.extend(item.get("subGroups", []) or [])
        return None

    def ensure_group(
        self,
        realm: str,
        name: str,
        *,
        parent_group_id: str | None = None,
        attributes: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        existing = self.find_group_by_name(realm, name)
        if existing is None:
            payload: dict[str, Any] = {"name": name}
            if attributes is not None:
                payload["attributes"] = attributes
            if parent_group_id:
                self.request(
                    "POST",
                    f"/admin/realms/{realm}/groups/{parent_group_id}/children",
                    json=payload,
                    expected=(201, 204, 409),
                )
            else:
                self.request("POST", f"/admin/realms/{realm}/groups", json=payload, expected=(201, 204, 409))
            existing = self.find_group_by_name(realm, name)
        if existing is None:
            raise HTTPException(status_code=502, detail=f"Failed to create/find group {name}")
        if attributes is not None:
            current = self.get_group(realm, existing["id"])
            current["attributes"] = attributes
            self.request("PUT", f"/admin/realms/{realm}/groups/{existing['id']}", json=current, expected=(204,))
            existing = self.get_group(realm, existing["id"])
        return existing

    def update_group(self, realm: str, group_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        current = self.get_group(realm, group_id)
        current.update(patch)
        self.request("PUT", f"/admin/realms/{realm}/groups/{group_id}", json=current, expected=(204,))
        return self.get_group(realm, group_id)

    def delete_group(self, realm: str, group_id: str) -> None:
        self.request("DELETE", f"/admin/realms/{realm}/groups/{group_id}", expected=(204, 404))

    def list_user_groups(self, realm: str, user_id: str) -> list[dict[str, Any]]:
        return self.request("GET", f"/admin/realms/{realm}/users/{user_id}/groups", expected=(200,)).json()

    def add_user_to_group(self, realm: str, user_id: str, group_id: str) -> None:
        self.request("PUT", f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}", expected=(204,))

    def remove_user_from_group(self, realm: str, user_id: str, group_id: str) -> None:
        self.request("DELETE", f"/admin/realms/{realm}/users/{user_id}/groups/{group_id}", expected=(204, 404))

    def set_user_groups(self, realm: str, user_id: str, target_group_ids: list[str], mode: str = "replace") -> list[dict[str, Any]]:
        mode = mode.lower()
        if mode not in {"replace", "add", "remove"}:
            raise HTTPException(status_code=400, detail="mode must be one of replace/add/remove")
        current = self.list_user_groups(realm, user_id)
        current_ids = {g.get("id") for g in current if g.get("id")}
        target_ids = {gid for gid in target_group_ids if gid}
        if mode == "replace":
            for gid in sorted(current_ids - target_ids):
                self.remove_user_from_group(realm, user_id, gid)
            for gid in sorted(target_ids - current_ids):
                self.add_user_to_group(realm, user_id, gid)
        elif mode == "add":
            for gid in sorted(target_ids - current_ids):
                self.add_user_to_group(realm, user_id, gid)
        else:
            for gid in sorted(target_ids & current_ids):
                self.remove_user_from_group(realm, user_id, gid)
        return self.list_user_groups(realm, user_id)

    def list_identity_providers(self, realm: str) -> list[dict[str, Any]]:
        return self.request("GET", f"/admin/realms/{realm}/identity-provider/instances", expected=(200,)).json()

    def get_identity_provider(self, realm: str, alias: str) -> dict[str, Any]:
        return self.request("GET", f"/admin/realms/{realm}/identity-provider/instances/{alias}", expected=(200,)).json()

    def create_identity_provider(self, realm: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.request("POST", f"/admin/realms/{realm}/identity-provider/instances", json=payload, expected=(201, 204, 409))
        return self.get_identity_provider(realm, payload["alias"])

    def update_identity_provider(self, realm: str, alias: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.request("PUT", f"/admin/realms/{realm}/identity-provider/instances/{alias}", json=payload, expected=(204,))
        return self.get_identity_provider(realm, alias)

    def delete_identity_provider(self, realm: str, alias: str) -> None:
        self.request("DELETE", f"/admin/realms/{realm}/identity-provider/instances/{alias}", expected=(204, 404))

    def list_identity_provider_mappers(self, realm: str, alias: str) -> list[dict[str, Any]]:
        return self.request("GET", f"/admin/realms/{realm}/identity-provider/instances/{alias}/mappers", expected=(200,)).json()

    def create_identity_provider_mapper(self, realm: str, alias: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.request(
            "POST",
            f"/admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
            json=payload,
            expected=(201, 204, 409),
        )
        for mapper in self.list_identity_provider_mappers(realm, alias):
            if mapper.get("name") == payload.get("name"):
                return mapper
        return {"name": payload.get("name")}

    def update_identity_provider_mapper(self, realm: str, alias: str, mapper_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.request(
            "PUT",
            f"/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{mapper_id}",
            json=payload,
            expected=(204,),
        )
        for mapper in self.list_identity_provider_mappers(realm, alias):
            if mapper.get("id") == mapper_id:
                return mapper
        return {"id": mapper_id}

    def delete_identity_provider_mapper(self, realm: str, alias: str, mapper_id: str) -> None:
        self.request("DELETE", f"/admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{mapper_id}", expected=(204, 404))

    @staticmethod
    def effective_user_group_names(user: TenantUser) -> list[str]:
        return [g for g in (user.groups or []) if g]


kc = KeycloakClient()


class AgentGatewayPolicySyncClient:
    def __init__(self) -> None:
        self.enabled = ENABLE_JWT_PROVIDER_AUTOREG

    def _bearer_token(self) -> str:
        if not K8S_SA_TOKEN_FILE or not os.path.exists(K8S_SA_TOKEN_FILE):
            raise HTTPException(status_code=500, detail="Kubernetes service account token file not found")
        with open(K8S_SA_TOKEN_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()

    def _verify_arg(self) -> bool | str:
        if not K8S_VERIFY_TLS:
            return False
        if K8S_CA_CERT_FILE and os.path.exists(K8S_CA_CERT_FILE):
            return K8S_CA_CERT_FILE
        return True

    def _request(self, method: str, path: str, *, expected: tuple[int, ...] = (200,), json_body: Any = None) -> requests.Response:
        if not K8S_API_SERVER:
            raise HTTPException(status_code=500, detail="K8S_API_SERVER is not configured")
        resp = requests.request(
            method,
            f"{K8S_API_SERVER}{path}",
            headers={
                "Authorization": f"Bearer {self._bearer_token()}",
                "Content-Type": "application/json",
            },
            json=json_body,
            timeout=REQUEST_TIMEOUT,
            verify=self._verify_arg(),
        )
        if resp.status_code not in expected:
            raise HTTPException(
                status_code=502,
                detail={
                    "message": "Unexpected response from Kubernetes API",
                    "method": method,
                    "path": path,
                    "status_code": resp.status_code,
                    "body": resp.text,
                },
            )
        return resp

    def _upsert_provider_in_policy(self, policy_name: str, new_provider: dict[str, Any]) -> str:
        """Add or update a JWT provider in an AgentgatewayPolicy. Returns status string."""
        path = f"/apis/agentgateway.dev/v1alpha1/namespaces/{AGENTGATEWAY_POLICY_NAMESPACE}/agentgatewaypolicies/{policy_name}"
        resource = self._request("GET", path, expected=(200,)).json()
        providers = (
            resource.get("spec", {})
            .get("traffic", {})
            .get("jwtAuthentication", {})
            .get("providers", [])
        )
        if not isinstance(providers, list):
            raise HTTPException(status_code=500, detail=f"AgentgatewayPolicy {policy_name} jwt providers is not a list")
        changed = False
        status = "created"
        for i, provider in enumerate(providers):
            if provider.get("issuer") == new_provider["issuer"]:
                if provider != new_provider:
                    providers[i] = new_provider
                    changed = True
                    status = "updated"
                else:
                    status = "noop"
                break
        else:
            providers.append(new_provider)
            changed = True
        if changed:
            resource.setdefault("spec", {}).setdefault("traffic", {}).setdefault("jwtAuthentication", {})["providers"] = providers
            resource.pop("status", None)
            if isinstance(resource.get("metadata"), dict):
                resource["metadata"].pop("managedFields", None)
            self._request("PUT", path, expected=(200,), json_body=resource)
        return status

    def ensure_jwt_provider(self, tenant_id: str, *, issuer_base_url: str | None = None) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled", "tenant_id": tenant_id}
        base = (issuer_base_url or KEYCLOAK_PUBLIC_ISSUER_BASE_URL or KEYCLOAK_URL).rstrip("/")
        issuer = f"{base}/realms/{tenant_id}"
        jwks_path = f"/realms/{tenant_id}/protocol/openid-connect/certs"
        new_provider = {
            "issuer": issuer,
            "jwks": {
                "remote": {
                    "jwksPath": jwks_path,
                    "cacheDuration": "5m",
                    "backendRef": {
                        "group": "",
                        "kind": "Service",
                        "name": AGENTGATEWAY_KEYCLOAK_SERVICE_NAME,
                        "namespace": AGENTGATEWAY_KEYCLOAK_SERVICE_NAMESPACE,
                        "port": AGENTGATEWAY_KEYCLOAK_SERVICE_PORT,
                    },
                }
            },
        }
        # Update business JWT policy
        status = self._upsert_provider_in_policy(AGENTGATEWAY_POLICY_NAME, new_provider)
        # Sync the same provider to idb-proxy and pep-proxy JWT policies (skip if not deployed)
        mgmt_sync: dict[str, str] = {}
        for name in (AGENTGATEWAY_IDB_POLICY_NAME, AGENTGATEWAY_PEP_POLICY_NAME):
            try:
                mgmt_sync[name] = self._upsert_provider_in_policy(name, new_provider)
            except HTTPException:
                mgmt_sync[name] = "skipped"
        return {
            "status": status,
            "tenant_id": tenant_id,
            "issuer": issuer,
            "jwks_path": jwks_path,
            "mgmt_policies": mgmt_sync,
        }


agw_sync = AgentGatewayPolicySyncClient()


def _build_keycloak_saml_idp_config(
    metadata: dict[str, Any],
    *,
    store_token: bool,
    trust_email: bool,
    sync_mode: str,
    config_overrides: dict[str, Any] | None = None,
) -> dict[str, str]:
    sso_binding = str(metadata.get("sso_binding") or "").upper()
    config: dict[str, str] = {
        "entityId": str(metadata.get("entity_id") or ""),
        "singleSignOnServiceUrl": str(metadata.get("sso_url") or ""),
        "singleLogoutServiceUrl": str(metadata.get("slo_url") or ""),
        "postBindingResponse": "true" if sso_binding.endswith("HTTP-POST") else "false",
        "postBindingAuthnRequest": "true",
        "wantAuthnRequestsSigned": "false",
        "wantAssertionsSigned": "true",
        "validateSignature": "true" if metadata.get("certificates") else "false",
        "storeToken": "true" if store_token else "false",
        "trustEmail": "true" if trust_email else "false",
        "syncMode": sync_mode,
    }
    certs = metadata.get("certificates") or []
    if certs:
        config["signingCertificate"] = certs[0]
        config["signingCertificates"] = json.dumps(certs)
    for key, value in (config_overrides or {}).items():
        if value is not None:
            config[key] = str(value)
    return config


def _load_saml_metadata(req: SamlIdPImportRequest | SamlIdPUpdateRequest | SamlIdPCertRotateRequest) -> tuple[dict[str, Any], str]:
    metadata_xml = getattr(req, "metadata_xml", None)
    metadata_url = getattr(req, "metadata_url", None)
    if metadata_xml and metadata_url:
        raise HTTPException(status_code=400, detail="Provide only one of metadata_xml or metadata_url")
    if not metadata_xml and not metadata_url:
        raise HTTPException(status_code=400, detail="metadata_xml or metadata_url is required")
    source = "metadata_xml"
    if metadata_url:
        source = "metadata_url"
        resp = requests.get(metadata_url, timeout=REQUEST_TIMEOUT, verify=KEYCLOAK_VERIFY_TLS)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Failed to fetch metadata_url: {resp.status_code} {resp.text}")
        metadata_xml = resp.text
    return _parse_saml_metadata_xml(metadata_xml or ""), source


def _saml_idp_payload_from_import(req: SamlIdPImportRequest) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata, source = _load_saml_metadata(req)
    config = _build_keycloak_saml_idp_config(
        metadata,
        store_token=req.store_token,
        trust_email=req.trust_email,
        sync_mode=req.sync_mode,
        config_overrides=req.config_overrides,
    )
    payload: dict[str, Any] = {
        "alias": req.alias,
        "providerId": "saml",
        "enabled": req.enabled,
        "displayName": req.display_name or req.alias,
        "trustEmail": req.trust_email,
        "storeToken": req.store_token,
        "firstBrokerLoginFlowAlias": req.first_broker_login_flow_alias,
        "config": config,
    }
    if req.post_broker_login_flow_alias:
        payload["postBrokerLoginFlowAlias"] = req.post_broker_login_flow_alias
    summary = {
        "entity_id": metadata.get("entity_id"),
        "sso_url": metadata.get("sso_url"),
        "slo_url": metadata.get("slo_url"),
        "cert_count": len(metadata.get("certificates") or []),
        "source": source,
    }
    return payload, summary


def _update_saml_idp_from_metadata(
    existing: dict[str, Any],
    req: SamlIdPUpdateRequest | SamlIdPCertRotateRequest,
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata, source = _load_saml_metadata(req)
    config = dict(existing.get("config") or {})
    certs = metadata.get("certificates") or []
    if certs:
        config["signingCertificate"] = certs[0]
        config["signingCertificates"] = json.dumps(certs)
        config["validateSignature"] = "true"
    if isinstance(req, SamlIdPUpdateRequest) or getattr(req, "update_endpoints", False):
        if metadata.get("entity_id"):
            config["entityId"] = str(metadata["entity_id"])
        if metadata.get("sso_url"):
            config["singleSignOnServiceUrl"] = str(metadata["sso_url"])
        if metadata.get("slo_url"):
            config["singleLogoutServiceUrl"] = str(metadata["slo_url"])
    existing["config"] = config
    summary = {
        "entity_id": metadata.get("entity_id"),
        "sso_url": metadata.get("sso_url"),
        "slo_url": metadata.get("slo_url"),
        "cert_count": len(certs),
        "source": source,
    }
    return existing, summary


def _resolve_group_ids(tenant_id: str, req: UserGroupMembershipRequest) -> list[str]:
    ids = {gid for gid in req.group_ids if gid}
    for name in req.group_names:
        group = kc.find_group_by_name(tenant_id, name)
        if group is None:
            raise HTTPException(status_code=404, detail=f"Group not found: {name}")
        if group.get("id"):
            ids.add(group["id"])
    return sorted(ids)


def _ensure_user_groups_by_names(tenant_id: str, user_id: str, user: TenantUser) -> list[dict[str, Any]]:
    target_ids: list[str] = []
    for group_name in kc.effective_user_group_names(user):
        group = kc.ensure_group(tenant_id, group_name)
        if group.get("id"):
            target_ids.append(group["id"])
    return kc.set_user_groups(tenant_id, user_id, target_ids, mode="replace")

def ensure_default_mappers(realm: str, client_uuid: str, tenant_id_value: str) -> None:
    kc.upsert_mapper(
        realm,
        client_uuid,
        "tenant_id",
        {
            "name": "tenant_id",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {
                "claim.name": "tenant_id",
                "claim.value": tenant_id_value,
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
    )
    kc.upsert_mapper(
        realm,
        client_uuid,
        "realm-roles",
        {
            "name": "realm-roles",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "claim.name": "roles",
                "jsonType.label": "String",
                "multivalued": "true",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
    )
    kc.upsert_mapper(
        realm,
        client_uuid,
        "groups",
        {
            "name": "groups",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-group-membership-mapper",
            "config": {
                "claim.name": "groups",
                "jsonType.label": "String",
                "multivalued": "true",
                "full.path": "true",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
    )


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "jwt_provider_autoreg": ENABLE_JWT_PROVIDER_AUTOREG, "k8s_api_detected": bool(K8S_API_SERVER)}


@app.get("/audit/events")
def list_audit_events(
    tenant_id: Optional[str] = None,
    action: Optional[str] = None,
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


@app.post("/bootstrap/master")
def bootstrap_master(payload: MasterBootstrapRequest, request: Request) -> dict[str, Any]:
    realm = "master"
    kc.ensure_realm(realm)
    client_uuid, client_secret = kc.ensure_client(realm, payload.client_id)
    ensure_default_mappers(realm, client_uuid, "master")
    kc.ensure_role(realm, "super_admin")
    kc.ensure_group(realm, "admin")

    user_model = TenantUser(
        username=payload.super_admin_username,
        password=payload.super_admin_password,
        email=payload.super_admin_email,
        groups=["admin"],
        roles=["super_admin"],
    )
    user_id = kc.ensure_user(realm, user_model)
    kc.assign_roles(realm, user_id, ["super_admin"])
    _ensure_user_groups_by_names(realm, user_id, user_model)

    result = {
        "realm": realm,
        "client_id": payload.client_id,
        "client_uuid": client_uuid,
        "client_secret": client_secret,
        "super_admin_username": payload.super_admin_username,
    }
    _record_audit_event(
        request=request,
        action="bootstrap_master",
        tenant_id="master",
        resource_type="realm",
        resource_id="master",
        payload=payload,
        result={k: v for k, v in result.items() if k != "client_secret"},
        replayable=True,
        replay={"endpoint": "/bootstrap/master", "method": "POST", "body": payload},
    )
    return result


@app.post("/tenants/{tenant_id}/bootstrap")
def bootstrap_tenant(tenant_id: str, payload: TenantBootstrapRequest, request: Request) -> dict[str, Any]:
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")

    kc.ensure_realm(tenant_id, payload.display_name)
    client_uuid, client_secret = kc.ensure_client(tenant_id, payload.client_id)
    ensure_default_mappers(tenant_id, client_uuid, tenant_id)
    kc.ensure_group(tenant_id, "admin")
    kc.ensure_group(tenant_id, "users")

    role_set = {"tenant_admin", "analyst", "viewer"}
    role_set.update(payload.tenant_admin.roles or [])
    for user in payload.users:
        role_set.update(user.roles)
    for role_name in sorted(role_set):
        kc.ensure_role(tenant_id, role_name)

    admin_roles = sorted(set(["tenant_admin"] + payload.tenant_admin.roles))
    admin_id = kc.ensure_user(tenant_id, payload.tenant_admin)
    kc.assign_roles(tenant_id, admin_id, admin_roles)
    _ensure_user_groups_by_names(tenant_id, admin_id, payload.tenant_admin)

    created_users: list[dict[str, Any]] = []
    for user in payload.users:
        uid = kc.ensure_user(tenant_id, user)
        roles = sorted(set(user.roles))
        kc.assign_roles(tenant_id, uid, roles)
        memberships = _ensure_user_groups_by_names(tenant_id, uid, user)
        created_users.append(
            {
                "username": user.username,
                "roles": roles,
                "groups": [g.get("path") or g.get("name") for g in memberships],
            }
        )

    jwt_provider_sync = None
    auto_sync = ENABLE_JWT_PROVIDER_AUTOREG if payload.auto_register_jwt_provider is None else payload.auto_register_jwt_provider
    if auto_sync:
        try:
            jwt_provider_sync = agw_sync.ensure_jwt_provider(tenant_id)
        except HTTPException as exc:
            jwt_provider_sync = {"status": "error", "detail": exc.detail}

    result = {
        "tenant_id": tenant_id,
        "display_name": payload.display_name,
        "client_id": payload.client_id,
        "client_uuid": client_uuid,
        "client_secret": client_secret,
        "tenant_admin": payload.tenant_admin.username,
        "users": created_users,
        "jwt_provider_sync": jwt_provider_sync,
    }
    _record_audit_event(
        request=request,
        action="bootstrap_tenant",
        tenant_id=tenant_id,
        resource_type="realm",
        resource_id=tenant_id,
        payload=payload,
        result={k: v for k, v in result.items() if k != "client_secret"},
        replayable=True,
        replay={"endpoint": f"/tenants/{tenant_id}/bootstrap", "method": "POST", "body": payload},
    )
    return result


@app.get("/tenants/{tenant_id}/roles")
def list_roles(tenant_id: str) -> list[dict[str, Any]]:
    resp = kc.request("GET", f"/admin/realms/{tenant_id}/roles", expected=(200,))
    return resp.json()


@app.post("/tenants/{tenant_id}/roles")
def create_role(tenant_id: str, payload: RoleCreateRequest, request: Request) -> dict[str, str]:
    role_obj = kc.ensure_role(tenant_id, payload.role_name)
    result = {"tenant_id": tenant_id, "role_name": role_obj["name"]}
    _record_audit_event(
        request=request,
        action="create_role",
        tenant_id=tenant_id,
        resource_type="role",
        resource_id=role_obj["name"],
        payload=payload,
        result=result,
    )
    return result


@app.delete("/tenants/{tenant_id}/roles/{role_name}")
def delete_role(tenant_id: str, role_name: str, request: Request) -> dict[str, str]:
    kc.delete_role(tenant_id, role_name)
    result = {"tenant_id": tenant_id, "role_name": role_name, "status": "deleted"}
    _record_audit_event(
        request=request,
        action="delete_role",
        tenant_id=tenant_id,
        resource_type="role",
        resource_id=role_name,
        result=result,
    )
    return result


@app.get("/tenants/{tenant_id}/users")
def list_users(tenant_id: str) -> list[dict[str, Any]]:
    resp = kc.request("GET", f"/admin/realms/{tenant_id}/users", expected=(200,))
    return resp.json()


@app.post("/tenants/{tenant_id}/users")
def create_user(tenant_id: str, payload: UserCreateRequest, request: Request) -> dict[str, Any]:
    uid = kc.ensure_user(
        tenant_id,
        TenantUser(
            username=payload.username,
            password=payload.password,
            email=payload.email,
            first_name=payload.first_name,
            last_name=payload.last_name,
            groups=payload.groups,
            roles=[],
        ),
    )
    roles = sorted(set(payload.assign_roles + payload.roles))
    kc.assign_roles(tenant_id, uid, roles)
    memberships = _ensure_user_groups_by_names(tenant_id, uid, payload)
    result = {
        "tenant_id": tenant_id,
        "user_id": uid,
        "username": payload.username,
        "roles": roles,
        "groups": [g.get("path") or g.get("name") for g in memberships],
    }
    _record_audit_event(
        request=request,
        action="create_user",
        tenant_id=tenant_id,
        resource_type="user",
        resource_id=uid,
        payload=payload,
        result=result,
    )
    return result


@app.post("/tenants/{tenant_id}/jwt-providers/sync")
def sync_jwt_provider(tenant_id: str, payload: JwtProviderSyncRequest, request: Request) -> dict[str, Any]:
    if payload.enabled is not None:
        agw_sync.enabled = payload.enabled
    result = agw_sync.ensure_jwt_provider(tenant_id, issuer_base_url=payload.issuer_base_url)
    _record_audit_event(
        request=request,
        action="sync_jwt_provider",
        tenant_id=tenant_id,
        resource_type="agentgateway_jwt_provider",
        resource_id=tenant_id,
        payload=payload,
        result=result,
        replayable=True,
        replay={"endpoint": f"/tenants/{tenant_id}/jwt-providers/sync", "method": "POST", "body": payload},
    )
    return result


@app.get("/tenants/{tenant_id}/groups")
def list_groups(tenant_id: str) -> list[dict[str, Any]]:
    return kc.list_groups(tenant_id)


@app.post("/tenants/{tenant_id}/groups")
def create_group(tenant_id: str, payload: GroupCreateRequest, request: Request) -> dict[str, Any]:
    group = kc.ensure_group(
        tenant_id,
        payload.name,
        parent_group_id=payload.parent_group_id,
        attributes=payload.attributes or None,
    )
    _record_audit_event(
        request=request,
        action="create_group",
        tenant_id=tenant_id,
        resource_type="group",
        resource_id=group.get("id"),
        payload=payload,
        result={"name": group.get("name"), "path": group.get("path")},
    )
    return group


@app.get("/tenants/{tenant_id}/groups/{group_id}")
def get_group(tenant_id: str, group_id: str) -> dict[str, Any]:
    return kc.get_group(tenant_id, group_id)


@app.put("/tenants/{tenant_id}/groups/{group_id}")
def update_group(tenant_id: str, group_id: str, payload: GroupUpdateRequest, request: Request) -> dict[str, Any]:
    patch: dict[str, Any] = {}
    if payload.name is not None:
        patch["name"] = payload.name
    if payload.attributes is not None:
        patch["attributes"] = payload.attributes
    updated = kc.update_group(tenant_id, group_id, patch)
    _record_audit_event(
        request=request,
        action="update_group",
        tenant_id=tenant_id,
        resource_type="group",
        resource_id=group_id,
        payload=payload,
        result={"name": updated.get("name"), "path": updated.get("path")},
    )
    return updated


@app.delete("/tenants/{tenant_id}/groups/{group_id}")
def delete_group(tenant_id: str, group_id: str, request: Request) -> dict[str, str]:
    kc.delete_group(tenant_id, group_id)
    result = {"tenant_id": tenant_id, "group_id": group_id, "status": "deleted"}
    _record_audit_event(
        request=request,
        action="delete_group",
        tenant_id=tenant_id,
        resource_type="group",
        resource_id=group_id,
        result=result,
    )
    return result


@app.get("/tenants/{tenant_id}/users/{username}/groups")
def list_user_groups(tenant_id: str, username: str) -> list[dict[str, Any]]:
    user = kc.get_user(tenant_id, username)
    if user is None:
        raise HTTPException(status_code=404, detail=f"User not found: {username}")
    return kc.list_user_groups(tenant_id, user["id"])


@app.put("/tenants/{tenant_id}/users/{username}/groups")
def update_user_groups(tenant_id: str, username: str, payload: UserGroupMembershipRequest, request: Request) -> dict[str, Any]:
    user = kc.get_user(tenant_id, username)
    if user is None:
        raise HTTPException(status_code=404, detail=f"User not found: {username}")
    group_ids = _resolve_group_ids(tenant_id, payload)
    groups = kc.set_user_groups(tenant_id, user["id"], group_ids, mode=payload.mode)
    result = {
        "tenant_id": tenant_id,
        "user_id": user["id"],
        "username": username,
        "mode": payload.mode,
        "groups": [g.get("path") or g.get("name") for g in groups],
    }
    _record_audit_event(
        request=request,
        action="update_user_groups",
        tenant_id=tenant_id,
        resource_type="user_group_membership",
        resource_id=user["id"],
        payload=payload,
        result=result,
    )
    return result


def _ensure_saml_idp(tenant_id: str, alias: str) -> dict[str, Any]:
    idp = kc.get_identity_provider(tenant_id, alias)
    if idp.get("providerId") != "saml":
        raise HTTPException(status_code=400, detail=f"Identity provider '{alias}' is not SAML")
    return idp


@app.get("/tenants/{tenant_id}/saml/idps")
def list_saml_idps(tenant_id: str) -> list[dict[str, Any]]:
    return [p for p in kc.list_identity_providers(tenant_id) if p.get("providerId") == "saml"]


@app.post("/tenants/{tenant_id}/saml/idps")
def create_saml_idp(tenant_id: str, payload: SamlIdPImportRequest, request: Request) -> dict[str, Any]:
    create_payload, meta_summary = _saml_idp_payload_from_import(payload)
    idp = kc.create_identity_provider(tenant_id, create_payload)
    _record_audit_event(
        request=request,
        action="create_saml_idp",
        tenant_id=tenant_id,
        resource_type="saml_idp",
        resource_id=payload.alias,
        payload=payload,
        result={"alias": idp.get("alias"), "enabled": idp.get("enabled"), "metadata": meta_summary},
        replayable=True,
        replay={"endpoint": f"/tenants/{tenant_id}/saml/idps", "method": "POST", "body": payload},
    )
    return idp


@app.get("/tenants/{tenant_id}/saml/idps/{alias}")
def get_saml_idp(tenant_id: str, alias: str) -> dict[str, Any]:
    return _ensure_saml_idp(tenant_id, alias)


@app.put("/tenants/{tenant_id}/saml/idps/{alias}")
def update_saml_idp(tenant_id: str, alias: str, payload: SamlIdPUpdateRequest, request: Request) -> dict[str, Any]:
    idp = _ensure_saml_idp(tenant_id, alias)
    meta_summary = None
    if payload.metadata_xml or payload.metadata_url:
        idp, meta_summary = _update_saml_idp_from_metadata(idp, payload)
    if payload.display_name is not None:
        idp["displayName"] = payload.display_name
    if payload.enabled is not None:
        idp["enabled"] = payload.enabled
    if payload.trust_email is not None:
        idp["trustEmail"] = payload.trust_email
        idp.setdefault("config", {})["trustEmail"] = "true" if payload.trust_email else "false"
    if payload.store_token is not None:
        idp["storeToken"] = payload.store_token
        idp.setdefault("config", {})["storeToken"] = "true" if payload.store_token else "false"
    if payload.sync_mode:
        idp.setdefault("config", {})["syncMode"] = payload.sync_mode
    for k, v in payload.config_updates.items():
        if v is not None:
            idp.setdefault("config", {})[k] = str(v)
    for key in payload.config_remove_keys:
        idp.setdefault("config", {}).pop(key, None)
    updated = kc.update_identity_provider(tenant_id, alias, idp)
    _record_audit_event(
        request=request,
        action="update_saml_idp",
        tenant_id=tenant_id,
        resource_type="saml_idp",
        resource_id=alias,
        payload=payload,
        result={"alias": alias, "enabled": updated.get("enabled"), "metadata": meta_summary},
        replayable=True,
        replay={"endpoint": f"/tenants/{tenant_id}/saml/idps/{alias}", "method": "PUT", "body": payload},
    )
    return updated


@app.put("/tenants/{tenant_id}/saml/idps/{alias}/enabled")
def set_saml_idp_enabled(tenant_id: str, alias: str, payload: SamlIdPEnableRequest, request: Request) -> dict[str, Any]:
    idp = _ensure_saml_idp(tenant_id, alias)
    idp["enabled"] = payload.enabled
    updated = kc.update_identity_provider(tenant_id, alias, idp)
    result = {"tenant_id": tenant_id, "alias": alias, "enabled": updated.get("enabled")}
    _record_audit_event(
        request=request,
        action="set_saml_idp_enabled",
        tenant_id=tenant_id,
        resource_type="saml_idp",
        resource_id=alias,
        payload=payload,
        result=result,
    )
    return result


@app.post("/tenants/{tenant_id}/saml/idps/{alias}/certificates/rotate")
def rotate_saml_idp_certificates(tenant_id: str, alias: str, payload: SamlIdPCertRotateRequest, request: Request) -> dict[str, Any]:
    idp = _ensure_saml_idp(tenant_id, alias)
    if payload.metadata_xml or payload.metadata_url:
        idp, meta_summary = _update_saml_idp_from_metadata(idp, payload)
    elif payload.signing_certificates:
        certs = [_normalize_cert_pem(c) for c in payload.signing_certificates if c.strip()]
        certs = [c for c in certs if c]
        if not certs:
            raise HTTPException(status_code=400, detail="No valid signing_certificates provided")
        idp.setdefault("config", {})["signingCertificate"] = certs[0]
        idp.setdefault("config", {})["signingCertificates"] = json.dumps(certs)
        idp.setdefault("config", {})["validateSignature"] = "true"
        meta_summary = {"cert_count": len(certs), "source": "signing_certificates"}
    else:
        raise HTTPException(status_code=400, detail="Provide metadata_xml, metadata_url, or signing_certificates")
    updated = kc.update_identity_provider(tenant_id, alias, idp)
    result = {"tenant_id": tenant_id, "alias": alias, "enabled": updated.get("enabled"), "metadata": meta_summary}
    _record_audit_event(
        request=request,
        action="rotate_saml_idp_certificates",
        tenant_id=tenant_id,
        resource_type="saml_idp_certificate",
        resource_id=alias,
        payload=payload,
        result=result,
    )
    return result


@app.delete("/tenants/{tenant_id}/saml/idps/{alias}")
def delete_saml_idp(tenant_id: str, alias: str, request: Request) -> dict[str, str]:
    kc.delete_identity_provider(tenant_id, alias)
    result = {"tenant_id": tenant_id, "alias": alias, "status": "deleted"}
    _record_audit_event(
        request=request,
        action="delete_saml_idp",
        tenant_id=tenant_id,
        resource_type="saml_idp",
        resource_id=alias,
        result=result,
    )
    return result


@app.get("/tenants/{tenant_id}/saml/idps/{alias}/mappers")
def list_saml_idp_mappers(tenant_id: str, alias: str) -> list[dict[str, Any]]:
    _ensure_saml_idp(tenant_id, alias)
    return kc.list_identity_provider_mappers(tenant_id, alias)


@app.post("/tenants/{tenant_id}/saml/idps/{alias}/mappers")
def create_saml_idp_mapper(tenant_id: str, alias: str, payload: IdPMapperRequest, request: Request) -> dict[str, Any]:
    _ensure_saml_idp(tenant_id, alias)
    mapper = kc.create_identity_provider_mapper(
        tenant_id,
        alias,
        {
            "name": payload.name,
            "identityProviderAlias": alias,
            "identityProviderMapper": payload.identity_provider_mapper,
            "config": {k: str(v) for k, v in payload.config.items()},
        },
    )
    _record_audit_event(
        request=request,
        action="create_saml_idp_mapper",
        tenant_id=tenant_id,
        resource_type="saml_idp_mapper",
        resource_id=mapper.get("id") or payload.name,
        payload=payload,
        result=mapper,
    )
    return mapper


@app.put("/tenants/{tenant_id}/saml/idps/{alias}/mappers/{mapper_id}")
def update_saml_idp_mapper(
    tenant_id: str,
    alias: str,
    mapper_id: str,
    payload: IdPMapperRequest,
    request: Request,
) -> dict[str, Any]:
    _ensure_saml_idp(tenant_id, alias)
    mapper = kc.update_identity_provider_mapper(
        tenant_id,
        alias,
        mapper_id,
        {
            "id": mapper_id,
            "name": payload.name,
            "identityProviderAlias": alias,
            "identityProviderMapper": payload.identity_provider_mapper,
            "config": {k: str(v) for k, v in payload.config.items()},
        },
    )
    _record_audit_event(
        request=request,
        action="update_saml_idp_mapper",
        tenant_id=tenant_id,
        resource_type="saml_idp_mapper",
        resource_id=mapper_id,
        payload=payload,
        result=mapper,
    )
    return mapper


@app.delete("/tenants/{tenant_id}/saml/idps/{alias}/mappers/{mapper_id}")
def delete_saml_idp_mapper(tenant_id: str, alias: str, mapper_id: str, request: Request) -> dict[str, str]:
    _ensure_saml_idp(tenant_id, alias)
    kc.delete_identity_provider_mapper(tenant_id, alias, mapper_id)
    result = {"tenant_id": tenant_id, "alias": alias, "mapper_id": mapper_id, "status": "deleted"}
    _record_audit_event(
        request=request,
        action="delete_saml_idp_mapper",
        tenant_id=tenant_id,
        resource_type="saml_idp_mapper",
        resource_id=mapper_id,
        result=result,
    )
    return result
