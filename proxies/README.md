# IDB / PEP Proxy FastAPI Reference

This folder contains a minimal reference implementation for:

- `idb-proxy`: Keycloak bootstrap and identity admin facade
- `pep-proxy`: policy management facade (default backend: OPAL realtime sync -> OPA)

## Folder Layout

- `idb-proxy/app/main.py`
- `idb-proxy/requirements.txt`
- `idb-proxy/Dockerfile`
- `pep-proxy/app/main.py`
- `pep-proxy/requirements.txt`
- `pep-proxy/Dockerfile`
- `k8s/proxy-system.yaml`
- `k8s/proxy-gateway-routes.yaml`
- `k8s/opal-system.yaml`

## Build Images

```bash
docker build -t ghcr.io/your-org/idb-proxy-fastapi:0.1.0 proxies/idb-proxy
docker build -t ghcr.io/your-org/pep-proxy-fastapi:0.1.0 proxies/pep-proxy
docker push ghcr.io/your-org/idb-proxy-fastapi:0.1.0
docker push ghcr.io/your-org/pep-proxy-fastapi:0.1.0
```

If you use different tags, update them in `proxies/k8s/proxy-system.yaml`.

## Deploy to Kubernetes

```bash
kubectl apply -f proxies/k8s/opal-system.yaml
kubectl apply -f proxies/k8s/proxy-system.yaml
kubectl apply -f proxies/k8s/proxy-gateway-routes.yaml
```

Notes:

- `pep-proxy` now keeps the same external API, but by default publishes policy updates to OPAL (`/data/config`) for realtime propagation to OPA.
- `POLICY_SYNC_BACKEND=opa` can be used as a compatibility fallback to write OPA Data API directly.

## IDB Proxy API (summary)

- `GET /healthz`
- `POST /bootstrap/master`
- `POST /tenants/{tenant_id}/bootstrap`
- `GET /tenants/{tenant_id}/roles`
- `POST /tenants/{tenant_id}/roles`
- `GET /tenants/{tenant_id}/users`
- `POST /tenants/{tenant_id}/users`

## PEP Proxy API (summary)

- `GET /healthz`
- `PUT /tenants/{tenant_id}/policies`
- `GET /tenants/{tenant_id}/policies`
- `DELETE /tenants/{tenant_id}/policies`
- `GET /tenants`
- `POST /simulate`
- `GET /opal/snapshots/tenant_policies` (OPAL bootstrap snapshot datasource)
