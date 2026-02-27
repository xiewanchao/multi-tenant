# AgentGateway 多租户身份与策略控制教程（基于当前项目）

本教程对应当前仓库中的 `manifests/tutorial`、`proxies/*`、`scripts/tutorial-curl-extended-tests.sh`。
目标是跑通一条完整链路：

- Keycloak 负责认证与 token/JWKS
- AgentGateway 负责入口路由与 JWT/AuthZ 串联
- OPA 负责细粒度授权（含管理面与业务面）
- IDB Proxy 负责租户身份管理
- PEP Proxy 负责策略管理、审计、回放与 DB 授权模拟

## 1. 架构与流量路径

```text
Client
  |
  v
AgentGateway (Gateway + HTTPRoute)
  |
  +-- /realms/* ------------------> Keycloak (OIDC/JWKS/token)
  |
  +-- /api/v1/admin/* -----------> 业务后端 (tutorial 默认 httpbin)
  |      1) JWT Auth (AgentgatewayPolicy)
  |      2) OPA ext_authz (AgentgatewayPolicy -> OPA gRPC)
  |
  +-- /api/v1/tenants/* ---------> 业务后端 (tutorial 默认 httpbin)
  |      1) JWT Auth
  |      2) OPA ext_authz
  |
  +-- /proxy/idb/* --------------> idb-proxy (管理面)
  |      1) mgmt JWT Auth
  |      2) mgmt OPA ext_authz
  |
  +-- /proxy/pep/* --------------> pep-proxy (管理面)
         1) mgmt JWT Auth
         2) mgmt OPA ext_authz
```

## 2. 目录与文件职责

### 2.1 Gateway 与业务路由

- `manifests/tutorial/00-gateway.yaml`
- `manifests/tutorial/10-baseline-routes.yaml`
- `manifests/tutorial/11-httpbin-networkpolicy.yaml`（可选硬化）

### 2.2 Keycloak 与 JWT

- `manifests/tutorial/30-keycloak-oidc-route.yaml`
- `manifests/tutorial/31-jwt-auth-policy.template.yaml`
- `manifests/tutorial/61-jwt-auth-policy-add-globex.template.yaml`（新增租户 realm 示例）

### 2.3 OPA 与业务授权

- `manifests/tutorial/40-opa-policy-configmap.yaml`
- `manifests/tutorial/41-opa-deployment-service.yaml`
- `manifests/tutorial/52-opa-referencegrant.yaml`
- `manifests/tutorial/53-opa-ext-auth-policy.yaml`

### 2.4 管理面代理与管理面策略

- `manifests/tutorial/20-idb-proxy-deployment.yaml`
- `manifests/tutorial/21-idb-proxy-gateway-routes.yaml`
- `manifests/tutorial/22-idb-proxy-jwt-sync-rbac.yaml`（JWT provider 自动注册可选）
- `manifests/tutorial/50-pep-proxy-deployment.yaml`
- `manifests/tutorial/51-pep-proxy-gateway-routes.yaml`
- `manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml`
- `manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml`

## 3. 前置条件

至少满足：

1. Kubernetes 集群可用
2. AgentGateway CRD 与 controller 已安装（`AgentgatewayPolicy` 可创建）
3. Gateway API CRD 已安装（`GatewayClass/Gateway/HTTPRoute/ReferenceGrant` 可创建）
4. 命名空间已准备：`agentgateway-system`、`keycloak`、`proxy-system`、`opa`（`opal` 若启用）
5. Keycloak 已运行并暴露 `keycloak.keycloak.svc.cluster.local:8080`
6. 业务后端可用（教程默认 `httpbin.httpbin.svc.cluster.local:8000`）
7. `idb-proxy-fastapi:local`、`pep-proxy-fastapi:local` 镜像可拉取（或替换为你自己的镜像）

## 4. 部署顺序（manifests/tutorial）

### 4.1 部署 Gateway 与基线路由

```bash
kubectl apply -f manifests/tutorial/00-gateway.yaml
kubectl apply -f manifests/tutorial/10-baseline-routes.yaml
```

可选网络硬化：

```bash
kubectl apply -f manifests/tutorial/11-httpbin-networkpolicy.yaml
```

### 4.2 部署 IDB Proxy 与路由

```bash
kubectl apply -f manifests/tutorial/20-idb-proxy-deployment.yaml
kubectl apply -f manifests/tutorial/21-idb-proxy-gateway-routes.yaml
```

如果你要启用租户创建后自动同步 JWT provider：

```bash
kubectl apply -f manifests/tutorial/22-idb-proxy-jwt-sync-rbac.yaml
```

并把 `20-idb-proxy-deployment.yaml` 里的 `ENABLE_JWT_PROVIDER_AUTOREG` 改为 `"true"`。

### 4.3 部署 Keycloak OIDC 路由

```bash
kubectl apply -f manifests/tutorial/30-keycloak-oidc-route.yaml
```

### 4.4 渲染并部署业务 JWT 策略

先设置 issuer/JWKS 路径变量：

```bash
export MASTER_ISSUER="http://www.example.com/realms/master"
export MASTER_JWKS_PATH="/realms/master/protocol/openid-connect/certs"
export ACME_ISSUER="http://www.example.com/realms/acme"
export ACME_JWKS_PATH="/realms/acme/protocol/openid-connect/certs"
```

渲染并应用：

```bash
envsubst < manifests/tutorial/31-jwt-auth-policy.template.yaml | kubectl apply -f -
```

如果没有 `envsubst`，手工替换模板中的 `${...}` 后再 `kubectl apply -f`。

### 4.5 部署 OPA 与业务授权策略

```bash
kubectl apply -f manifests/tutorial/40-opa-policy-configmap.yaml
kubectl apply -f manifests/tutorial/41-opa-deployment-service.yaml
kubectl apply -f manifests/tutorial/52-opa-referencegrant.yaml
kubectl apply -f manifests/tutorial/53-opa-ext-auth-policy.yaml
```

### 4.6 部署 PEP Proxy 与路由

```bash
kubectl apply -f manifests/tutorial/50-pep-proxy-deployment.yaml
kubectl apply -f manifests/tutorial/51-pep-proxy-gateway-routes.yaml
```

### 4.7 管理面策略先不要部署（关键）

在首次初始化（`/proxy/idb/bootstrap/*`）之前，不要先应用：

- `manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml`
- `manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml`

原因：管理面 JWT 是 `Strict`，先启用会把 bootstrap 请求拦成 `401`。

## 5. 部署后检查

```bash
kubectl get gateway -n agentgateway-system
kubectl get httproute -n agentgateway-system
kubectl get referencegrant -A
kubectl get agentgatewaypolicy -n agentgateway-system
kubectl get deploy -n proxy-system
kubectl get deploy -n opa
```

重点检查（此时还不包含 mgmt 策略）：

1. `agentgateway-proxy` 已 Programmed
2. 路由存在：`admin-api-route`、`tenant-api-route`、`keycloak-oidc-route`、`idb-proxy-route`、`pep-proxy-route`
3. 策略存在：`jwt-auth-policy`、`opa-ext-auth-policy`

## 6. 基础联调（最小可用）

先把网关端口转发到本地：

```bash
kubectl -n agentgateway-system port-forward deployment/agentgateway-proxy 8080:80
```

### 6.1 OIDC 免认证路径

```bash
curl -i "http://127.0.0.1:8080/realms/master/.well-known/openid-configuration" \
  -H "Host: www.example.com"
```

### 6.2 业务 API 无 token（预期 401）

```bash
curl -i "http://127.0.0.1:8080/api/v1/admin/tenants" \
  -H "Host: www.example.com"
```

### 6.3 管理面 API 无 token（初始化阶段预期 200）

```bash
curl -i "http://127.0.0.1:8080/proxy/idb/healthz" \
  -H "Host: www.example.com"
```

## 7. 使用 IDB Proxy 初始化主 realm 与租户

> 下列接口路径都走网关：`/proxy/idb/*`。
> 确保此时还未应用 `54/55` 管理面策略，否则会返回 `401`。

### 7.1 初始化 master realm

```bash
curl -sS -X POST "http://127.0.0.1:8080/proxy/idb/bootstrap/master" \
  -H "Host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "master-gateway-client",
    "super_admin_username": "superadmin",
    "super_admin_password": "superadmin123",
    "super_admin_email": "superadmin@gateway.local"
  }'
```

### 7.2 初始化租户 realm（acme）

```bash
curl -sS -X POST "http://127.0.0.1:8080/proxy/idb/tenants/acme/bootstrap" \
  -H "Host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Acme Corp",
    "client_id": "acme-frontend",
    "tenant_admin": {
      "username": "alice",
      "password": "alice123",
      "email": "alice@acme.local",
      "groups": ["admin"],
      "roles": ["tenant_admin"]
    },
    "users": [
      {
        "username": "bob",
        "password": "bob123",
        "email": "bob@acme.local",
        "groups": ["users"],
        "roles": ["viewer"]
      }
    ]
  }'
```

## 8. 获取 token 并验证 401/403/200

### 8.1 获取 acme 租户管理员 token

先从 `7.2` 的响应里拿到 `client_secret`，再请求 token：

```bash
curl -sS -X POST "http://127.0.0.1:8080/realms/acme/protocol/openid-connect/token" \
  -H "Host: www.example.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=acme-frontend&client_secret=<7.2返回的client_secret>&username=alice&password=alice123"
```

### 8.2 调业务 API（带 token）

```bash
TOKEN="<把上一步 access_token 填进来>"
curl -i "http://127.0.0.1:8080/api/v1/tenants/acme/apps/myapp" \
  -H "Host: www.example.com" \
  -H "Authorization: Bearer ${TOKEN}"
```

你会看到：

1. JWT 不合法或缺失 -> `401`
2. JWT 合法但 OPA 不允许 -> `403`
3. JWT 合法且 OPA 允许 -> `200`

## 9. 启用管理面 JWT + OPA 策略（初始化后）

初始化完成后再启用管理面策略：

```bash
envsubst < manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml | kubectl apply -f -
kubectl apply -f manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml
```

验证（此时无 token 应返回 `401`）：

```bash
curl -i "http://127.0.0.1:8080/proxy/idb/healthz" \
  -H "Host: www.example.com"
```

## 10. PEP Proxy 动态策略（含 DB 授权）

> 下列接口路径走网关：`/proxy/pep/*`。

### 10.1 写入租户策略包

```bash
curl -sS -X PUT "http://127.0.0.1:8080/proxy/pep/tenants/acme/policies" \
  -H "Host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "demo-v1",
    "metadata": {"source": "tutorial"},
    "policies": [
      {
        "name": "allow-db-query-by-group",
        "effect": "allow",
        "resource_kind": "database",
        "subjects": ["group:finance"],
        "resources": ["db1.sales.*"],
        "actions": ["query"]
      }
    ]
  }'
```

### 10.2 调用 DB 授权检查

```bash
curl -sS -X POST "http://127.0.0.1:8080/proxy/pep/authorize/db" \
  -H "Host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme",
    "user": "alice",
    "roles": ["analyst"],
    "groups": ["finance"],
    "action": "query",
    "resource_kind": "database",
    "resource": "db1.sales.orders"
  }'
```

## 11. 扩展接口（当前项目已实现）

### 11.1 IDB Proxy 扩展

- Group 管理：
  - `GET/POST /tenants/{tenant_id}/groups`
  - `GET/PUT/DELETE /tenants/{tenant_id}/groups/{group_id}`
  - `GET/PUT /tenants/{tenant_id}/users/{username}/groups`
- SAML IdP：
  - `GET/POST /tenants/{tenant_id}/saml/idps`
  - `GET/PUT/DELETE /tenants/{tenant_id}/saml/idps/{alias}`
  - `PUT /tenants/{tenant_id}/saml/idps/{alias}/enabled`
  - `POST /tenants/{tenant_id}/saml/idps/{alias}/certificates/rotate`
  - `GET/POST/PUT/DELETE /tenants/{tenant_id}/saml/idps/{alias}/mappers...`
- JWT Provider 手动同步：
  - `POST /tenants/{tenant_id}/jwt-providers/sync`

### 11.2 PEP Proxy 扩展

- 审计查询：
  - `GET /audit/events`
  - `GET /audit/events/{event_id}`
- 审计回放：
  - `POST /audit/replay/{event_id}`
- 策略快照：
  - `GET /opal/snapshots/tenant_policies`
- 模拟授权：
  - `POST /simulate`

## 12. 一键扩展测试脚本

仓库提供了扩展联调脚本：

- `scripts/tutorial-curl-extended-tests.sh`

运行前准备：

1. `kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80`
2. 本机安装 `jq`
3. 基础教程步骤已完成（含租户初始化）

执行：

```bash
bash scripts/tutorial-curl-extended-tests.sh
```

可覆盖：Group、SAML、DB 授权、审计回放完整链路。

## 13. 常见问题与排查

1. `AgentgatewayPolicy` 创建失败
   - 检查 CRD 和 controller 是否已安装
2. `HTTPRoute` 不生效
   - 检查 Host 头是否与 `www.example.com` 一致
   - 检查 `Gateway` 状态是否 Programmed
3. OPA ext_authz 不通
   - 检查 `52-opa-referencegrant.yaml` 是否已应用
   - 检查 `opa` Service 的 gRPC 端口 `9191`
4. 管理面接口返回 401
   - 说明 mgmt JWT 策略生效，需使用合法 token
5. 管理面接口返回 403
   - 说明 JWT 已通过但 OPA 管理面规则拒绝（角色/租户不匹配）

## 14. Helm 版本部署参考

如果你走 umbrella chart，请参考：

- `docs/helm-umbrella-deploy.md`
- `charts/agentgateway-multi-tenant/values.yaml`
- `charts/agentgateway-multi-tenant/values-prod.example.yaml`

核心思路一致，只是把教程中的分散 manifests 统一参数化为 Helm values。

## 15. AgentGateway 挂载 OPA Sidecar + OPAL Client（新增）

如果你要把 OPA/OPAL 能力内聚到 `agentgateway-proxy` Pod（而不是单独依赖 `opa.opa`），按下面执行：

```bash
bash scripts/tutorial-enable-agentgateway-sidecar-opal.sh
```

脚本会做这些事：

1. 部署 OPAL Server（`manifests/tutorial/42-opal-server.yaml`）
2. 创建 Sidecar 暴露 Service（`manifests/tutorial/56-agentgateway-sidecar-opa-service.yaml`）
3. 给 `agentgateway-proxy` 打补丁，注入：
   - `opa-sidecar`（gRPC 9191 + HTTP 8181）
   - `opal-client-sidecar`（同步 `tenant_policies` 数据）
4. 将 ext_authz backend 切到 `agentgateway-opa-sidecar.agentgateway-system:9191`

快速检查：

```bash
kubectl -n agentgateway-system get deploy agentgateway-proxy -o jsonpath='{.spec.template.spec.containers[*].name}'
kubectl -n agentgateway-system get svc agentgateway-opa-sidecar
kubectl -n opal get deploy
```

## 16. OPA Rego 动态更新验证（无重启）

执行：

```bash
bash scripts/tutorial-test-sidecar-opal-dynamic.sh
```

该脚本会验证完整闭环：

1. 基线请求：`200`
2. 动态下发 Rego 模块后：`403`
3. 删除动态模块后恢复：`200`

期望输出：

```text
PASS sidecar+dynamic-rego: baseline=200, updated=403, restored=200
```
