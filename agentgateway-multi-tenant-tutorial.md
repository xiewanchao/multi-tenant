# AgentGateway 多租户身份与策略控制 �?完整部署教程

## 架构概览

```
[Client / Admin / User]
        �?
        �?
   [AgentGateway-Proxy] (Envoy, port 80)
     �?
     �? 路由分两区：
     �?
     ├─── 免认证专区（Keycloak OIDC 端点�?
     �?     不经�?JWT 认证 / OPA 授权
     �?     /realms/*  �?[Keycloak]  (token 签发、JWKS、OIDC discovery)
     �?
     ├─── 业务鉴权区（业务 API�?
     �?     �?JWT 认证 (AuthN) �?attach �?admin-api-route / tenant-api-route
     �?        AgentGateway �?Keycloak JWKS 公钥验签
     �?        支持�?realm（master + 各租�?realm�?
     �?        �?�?token / token 无效 �?401 Unauthorized
     �?     �?外部授权 (AuthZ) �?attach �?admin-api-route / tenant-api-route
     �?        AgentGateway �?OPA (gRPC ext_authz)
     �?        OPA �?tenant_id 做多租户隔离 RBAC
     �?        �?无权�?�?403 Forbidden
     �?     �?两层都通过后路�?
     �?     ├── /api/v1/admin/*            �?[Admin Service]        超级管理员操�?
     �?     └── /api/v1/tenants/*/apps/*   �?[App Service]
     �?
     └─── 管理面鉴权区（IDB / PEP Proxy�?
            �?JWT 认证 (AuthN) �?attach �?idb-proxy-route / pep-proxy-route
            �?外部授权 (AuthZ) �?独立 OPA 策略（管理面路径分级�?
               super_admin（master realm）→ 可访问所有管理面路径
               tenant_admin �?仅可访问 /tenants/{own_tenant_id}/*
               普通用�?�?403
            ├── /proxy/idb/*               �?[IDB Proxy]   ──────�? [Keycloak Admin API]
            └── /proxy/pep/*               �?[PEP Proxy]   ──────�? [OPAL Server]
                                                                       �?
                                                                       ├── realtime push �?[OPAL Client]
                                                                       �?                   └── sync data �?[OPA Data API]
                                                                       └── policy check     �?[OPA] (ext_authz)
```

> **关键设计决策**�?
> 1. Keycloak 挂在 Gateway 后面统一入口，但�?OIDC 端点（token 签发、JWKS 公钥、OpenID Discovery）必须作�?免认证专�?独立路由。JWT 认证�?OPA 授权策略通过 `targetRefs` 精确绑定到业�?HTTPRoute，而非 Gateway 整体，从而避�?鸡生�?问题 —�?客户端必须先能无 token 调用 Keycloak 拿到 token，才能用 token 调用业务 API�?
> 2. **Namespace 统一原则**：所�?HTTPRoute �?AgentgatewayPolicy 统一放在 `agentgateway-system` namespace。因�?`AgentgatewayPolicy` �?`targetRefs` 不支持跨 namespace 引用（CRD �?`namespace` 字段），Policy 只能绑定�?namespace �?HTTPRoute。后�?Service（keycloak、httpbin、opa）通过 ReferenceGrant �?namespace 引用�?

**三层角色模型**�?

| 角色 | 说明 | JWT 来源 | 可访问路�?|
|---|---|---|---|
| 超级管理�?| 全局治理、创建租�?| master realm | `/api/v1/admin/*` |
| 租户管理�?| 管理本租户身份与策略 | 租户 realm | `/api/v1/tenants/{own_tenant}/*` 管理 API |
| 普通用�?| 业务操作 | 租户 realm | `/api/v1/tenants/{own_tenant}/apps/*` |

**双层安全模型**（仅作用于业务路由，不影�?Keycloak 免认证专区）�?

| 层级 | 组件 | 职责 | 失败响应 | 绑定目标 |
|---|---|---|---|---|
| �?1 层：认证 (AuthN) | Keycloak + JWT | 验证"你是�? �?token 签名、过期、issuer | 401 Unauthorized | 业务 HTTPRoute |
| �?2 层：授权 (AuthZ) | OPA ext_authz | 决定"你能做什�? �?多租户隔�?RBAC | 403 Forbidden | 业务 HTTPRoute |

> **为什么绑定到 HTTPRoute 而非 Gateway�?* 如果�?JWT/OPA 策略绑定�?Gateway 整体，所有经�?Gateway 的流量（包括 Keycloak �?token 端点）都会要�?JWT —�?但客户端还没�?token！通过将策略精确绑定到业务 HTTPRoute，Keycloak �?OIDC 路由可以免认证通行�?

**渐进式部署思路**：本教程采用渐进式方式构建，每一步完成后都可以用 curl 验证�?

| 阶段 | 部署内容 | 验证效果 |
|---|---|---|
| 第一部分 | httpbin + 业务路由 | curl �?httpbin 200 OK（无任何认证�?|
| 第二部分 | Keycloak + IDB Proxy（身份配置面�?| 通过 `/proxy/idb/*` 完成 Keycloak 初始�?|
| 第三部分 | Keycloak OIDC 路由 + JWT 策略 | �?token �?401，有 token �?200 |
| 第四部分 | OPA 策略引擎 + ext_authz + 管理面策�?| 正确角色 �?200，错误角�?�?403；管理面路由同样�?JWT + OPA 保护 |
| 第五部分 | 端到端完整测�?| 15 个场景全面覆盖（含管理面鉴权�?|

---



## 建议阅读顺序（推荐）

为降低首次部署的排障成本，建议按“核心主�?�?排障 �?可选扩展”的顺序阅读�?

1. 核心主线（必做）：第一部分 �?第二部分 �?第三部分 �?第四部分 �?第五部分
2. 常用排障（强烈建议）：第八部分《调试与运维�?
3. 可选扩展：第六部分《动态策略管理》→ 第七部分《添加更多租户�?
4. 清理资源：第九部�?

> **核心主线成功标准**�?
> - �?token 访问业务 API �?`401`
> - 有效 token 但角色不�?�?`403`
> - 正确角色访问正确租户资源 �?`200`

---

## 前提条件

> **清单组织说明**：本教程中的内联 YAML 已全部拆分到 `manifests/tutorial/*.yaml`，后续命令会直接引用这些文件�?
>
> **模板渲染说明**：涉�?`${MASTER_ISSUER}`、`${ACME_ISSUER}` 等变量的策略文件使用 `*.template.yaml`，需通过 `envsubst` 渲染后再 `kubectl apply`�?

### 路径 A：已有环境（推荐�?

确保已完成：

1. �?有一�?Kubernetes 集群（Kind 即可�?
2. �?安装�?AgentGateway 控制�?
3. �?创建�?agentgateway-proxy Gateway

### 路径 B：从零安装（可选，若你尚未准备环境�?

如果还没完成�?

```bash
# 创建 Kind 集群
kind create cluster

# 1. 安装 Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml

# 2. 安装 AgentGateway CRDs
helm upgrade -i agentgateway-crds oci://ghcr.io/kgateway-dev/charts/agentgateway-crds \
--create-namespace --namespace agentgateway-system \
--version v2.2.0-main \
--set controller.image.pullPolicy=Always

# 3. 安装 AgentGateway 控制�?
helm upgrade -i agentgateway oci://ghcr.io/kgateway-dev/charts/agentgateway \
  --namespace agentgateway-system \
  --version v2.2.0-main \
  --set controller.image.pullPolicy=IfNotPresent \
  --set controller.extraEnv.KGW_ENABLE_GATEWAY_API_EXPERIMENTAL_FEATURES=true

# 4. 创建 Gateway
kubectl apply -f manifests/tutorial/00-gateway.yaml
```

验证 Gateway 就绪�?

```bash
kubectl get gateway -n agentgateway-system
# 应看�?agentgateway-proxy 状态为 Accepted/Programmed
```

---

# 第一部分：部�?httpbin 和业务路由（建立基线�?

> **目标**：先搭建最基本�?Gateway �?httpbin 通路，确认流量可以正常转发。此时没有任何认证和授权，所有请求都应该返回 200 OK�?

## �?1 步：部署 httpbin 模拟后端

httpbin 用于模拟业务 App Service。在后续步骤中，我们会逐步在路由上叠加 JWT 认证�?OPA 授权�?

```bash
kubectl apply -f https://raw.githubusercontent.com/kgateway-dev/kgateway/refs/heads/main/examples/httpbin.yaml

kubectl -n httpbin rollout status deploy/httpbin
```

## �?2 步：创建业务路由

创建两条 HTTPRoute，将业务 API 路由�?httpbin。所�?HTTPRoute 统一放在 `agentgateway-system` namespace，通过 ReferenceGrant �?namespace 引用 httpbin Service�?

```bash
kubectl apply -f manifests/tutorial/10-baseline-routes.yaml
```

> **说明**：在此教程中，所有业务路由都指向 httpbin 作为模拟后端。由�?httpbin 不识�?`/api/v1/*` 路径，路由中使用�?`URLRewrite` 将请求路径重写到 httpbin �?`/anything/*` 端点（该端点对任意路径和方法返回 200 并回显请求信息）。生产环境中应替换为实际的后端服务并移除 URL rewrite�?

验证路由�?

```bash
kubectl get httproute -n agentgateway-system
kubectl get referencegrant -n httpbin
```

## �?3 步：验证基线 �?裸流量通路

启动 port-forward 并测试：

```bash
kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80 &
```

> **Windows 用户注意**：建议在单独�?PowerShell 标签页中执行 port-forward。如果使�?Git Bash (MINGW64) 且配置了 HTTP 代理，需要先 `unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy`，否则请求可能不会走本地 port-forward�?

```bash
# 测试管理 API 路由 �?应该返回 200（无任何认证�?
echo "=== Baseline Test 1: Admin API route �?200 (no auth) ==="
curl -s http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" | jq '{url, origin}'

# 测试租户 API 路由 �?应该返回 200（无任何认证�?
echo "=== Baseline Test 2: Tenant API route �?200 (no auth) ==="
curl -s http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" | jq '{url, origin}'
```

预期：两个请求都返回 200，body 中包�?httpbin 回显的请求信息，例如�?

```json
{
  "url": "http://www.example.com/anything/api/v1/admin/tenants",
  "origin": "10.244.0.1"
}
```

> httpbin 本身不认�?`/api/v1/admin/tenants` 路径，路由中配置�?URL Rewrite（`ReplacePrefixMatch`）将请求转发�?httpbin �?`/anything/*` 端点。该端点接受任意路径和方法，回显所有请求头�?body，非常适合用来验证流量通路�?

> **说明**：httpbin �?GET 请求只识别特定路径（�?`/get`、`/anything/*`），对不认识的路径返�?404。但 POST 请求会被 httpbin 正常处理并回显。如果看�?`404 Not Found (go-httpbin does not handle the path ...)`，说�?Gateway �?httpbin 通路正常，只�?httpbin 不处理该 GET 路径�?

> �?**检查点**：如果这里返�?404 或连接失败，请检�?Gateway、HTTPRoute �?httpbin 的部署状态后再继续。后续步骤会在这个基线之上逐层叠加安全策略�?

---

# 第二部分：部�?Keycloak + IDB Proxy（身份配置面�?

## �?4 步：部署 Keycloak

### 4.1 创建 namespace 并部�?

```bash
kubectl create namespace keycloak

kubectl -n keycloak apply -f https://raw.githubusercontent.com/solo-io/gloo-mesh-use-cases/main/policy-demo/oidc/keycloak.yaml

kubectl -n keycloak rollout status deploy/keycloak
```

### 4.2 获取 Keycloak 访问地址

Keycloak 将通过 Gateway 对外暴露（免认证专区路由将在�?8 步配置），但�?Keycloak 初始配置阶段，我们先使用 port-forward 直连�?

**Kind 集群（初始配置阶段，使用 port-forward 直连�?*�?

```bash
kubectl port-forward -n keycloak svc/keycloak 9080:8080 &
export KEYCLOAK_URL=http://localhost:9080
echo "Keycloak URL: $KEYCLOAK_URL"
```

> **说明**：完成第 8 步的 Keycloak 免认证路由配置后，外部客户端将通过 Gateway（`http://<gateway-ip>/realms/...`）访�?Keycloak �?OIDC 端点，而无需单独�?port-forward�?

**LoadBalancer 正常工作�?*�?

```bash
export ENDPOINT_KEYCLOAK=$(kubectl -n keycloak get service keycloak \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}'):8080
export KEYCLOAK_URL=http://${ENDPOINT_KEYCLOAK}
echo "Keycloak URL: $KEYCLOAK_URL"
```

### 4.3 获取 master realm admin token

```bash
export KEYCLOAK_TOKEN=$(curl -s \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" | jq -r .access_token)

echo "Admin token: ${KEYCLOAK_TOKEN:0:20}..."
```

> 如果返回空，检�?Keycloak 是否已就绪以�?URL 是否正确�?
> 说明：后续主流程通过 IDB Proxy 完成配置，这�?`KEYCLOAK_TOKEN` 主要用于排障和手工检查�?

---

## �?5 步：部署 IDB Proxy（FastAPI 身份配置面）

为避免直接使用大�?`curl` �?Keycloak Admin API �?OPAL/OPA 接口，本教程将配置动作下沉到两个独立 FastAPI 服务�?

1. `IDB Proxy`：负�?Keycloak 管理动作（realm/client/user/role/bootstrap�?
2. `PEP Proxy`：负责策略数据管理（policy upsert/query/delete/simulate）；在本教程中它通过 OPAL 实时下发数据�?OPA，建议放�?OPA/OPAL 部分部署（健康检查依�?OPA，实时推送依�?OPAL�?

> **Keycloak 24+ 兼容性说�?*：Keycloak 24 及以上版本默认启�?声明式用户配置文�?（Declarative User Profile），未在 User Profile 中注册的自定义用户属性会在创�?更新用户时被静默忽略。IDB Proxy �?bootstrap 流程已自动处理此问题 —�?在创建用户时会自动将用户加入指定�?Keycloak Group，并通过 Group Membership Mapper �?`groups` claim 映射�?JWT，无需手动注册自定义用户属性�?

### 5.1 部署 IDB Proxy 服务

> 下方镜像请替换为你的 FastAPI 实现镜像。生产环境建议将 admin 凭据放入 Secret，这里为教程演示简化配置�?

```bash
kubectl create namespace proxy-system --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f manifests/tutorial/20-idb-proxy-deployment.yaml
```

### 5.2 �?IDB Proxy 接入 Gateway

```bash
kubectl apply -f manifests/tutorial/21-idb-proxy-gateway-routes.yaml

kubectl get deploy,svc -n proxy-system
kubectl get httproute -n agentgateway-system
```

> 说明：本教程�?`idb-proxy-route` 作为身份配置面入口，默认不绑�?JWT/OPA，便于首�?bootstrap。`pep-proxy` 将在 OPA 部分部署并接�?Gateway。生产环境应至少配合内网访问控制。完成初始化后，教程会在�?12.3 步为 idb-proxy-route �?pep-proxy-route 部署独立�?JWT + OPA 策略�?

### 5.3 通过 IDB Proxy 初始�?master realm（超级管理员�?

> 如果之前 `kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80` 已停止，请先重新启动�?

```bash
MASTER_BOOTSTRAP=$(curl -s -X POST http://127.0.0.1:8080/proxy/idb/bootstrap/master \
  -H "host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "master-gateway-client",
    "super_admin_username": "superadmin",
    "super_admin_password": "superadmin123"
  }')

echo "$MASTER_BOOTSTRAP" | jq .

export MASTER_CLIENT_ID=$(echo "$MASTER_BOOTSTRAP" | jq -r '.client_id')
export MASTER_CLIENT_SECRET=$(echo "$MASTER_BOOTSTRAP" | jq -r '.client_secret')
export MASTER_CLIENT_UUID=$(echo "$MASTER_BOOTSTRAP" | jq -r '.client_uuid')
```

预期返回包含如下字段�?

```json
{
  "realm": "master",
  "client_id": "master-gateway-client",
  "client_secret": "...",
  "client_uuid": "...",
  "super_admin_username": "superadmin"
}
```

---

## �?6 步：通过 IDB Proxy 创建租户 Realm（以 acme 为例�?

每个租户对应一个独�?Keycloak realm。这里通过 IDB Proxy 一次性完�?realm、client、claims mapper、角色、用户初始化�?

### 6.1 创建 acme 租户

```bash
export TENANT_ID="acme"

TENANT_BOOTSTRAP=$(curl -s -X POST http://127.0.0.1:8080/proxy/idb/tenants/${TENANT_ID}/bootstrap \
  -H "host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "ACME Corp",
    "client_id": "acme-gateway-client",
    "tenant_admin": {
      "username": "alice",
      "password": "password",
      "email": "alice@acme.com",
      "groups": ["admin"]
    },
    "users": [
      {
        "username": "bob",
        "password": "password",
        "email": "bob@acme.com",
        "groups": ["users"],
        "roles": ["analyst"]
      },
      {
        "username": "charlie",
        "password": "password",
        "email": "charlie@acme.com",
        "groups": ["users"],
        "roles": ["viewer"]
      }
    ]
  }')

echo "$TENANT_BOOTSTRAP" | jq .

export ACME_CLIENT_ID=$(echo "$TENANT_BOOTSTRAP" | jq -r '.client_id')
export ACME_CLIENT_SECRET=$(echo "$TENANT_BOOTSTRAP" | jq -r '.client_secret')
export ACME_CLIENT_UUID=$(echo "$TENANT_BOOTSTRAP" | jq -r '.client_uuid')
```

`TENANT_BOOTSTRAP` 建议至少返回：`tenant_id`、`client_id`、`client_secret`、`client_uuid`，便于后�?JWT 测试直接复用�?

### 6.2 验证 Keycloak 配置

```bash
echo "========================================="
echo "Keycloak Admin Console: $KEYCLOAK_URL"
echo "  用户�? admin / 密码: admin"
echo "========================================="
echo ""
echo "已创�?Realm:"
echo "  - master (超级管理�?"
echo "  - ${TENANT_ID} (租户)"
echo ""
echo "用户总览:"
echo "  [master] superadmin / superadmin123  �?role: super_admin"
echo "  [${TENANT_ID}] alice / password      �?role: tenant_admin"
echo "  [${TENANT_ID}] bob / password        �?role: analyst"
echo "  [${TENANT_ID}] charlie / password    �?role: viewer"
```

---

# 第三部分：配�?JWT 认证（多 Realm 支持�?

> **目标**：为业务路由叠加 JWT 认证层。完成后，无 token 的请求会被拦截返�?401，有�?token 的请求正常通过。Keycloak �?OIDC 端点作为"免认证专�?不受影响�?

## �?7 步：获取 JWKS 信息

```bash
# Master realm
export MASTER_ISSUER=$KEYCLOAK_URL/realms/master
export MASTER_JWKS_PATH=/realms/master/protocol/openid-connect/certs

# 租户 realm
export ACME_ISSUER=$KEYCLOAK_URL/realms/${TENANT_ID}
export ACME_JWKS_PATH=/realms/${TENANT_ID}/protocol/openid-connect/certs

echo "Master Issuer: $MASTER_ISSUER"
echo "Master JWKS: $MASTER_JWKS_PATH"
echo "Acme Issuer: $ACME_ISSUER"
echo "Acme JWKS: $ACME_JWKS_PATH"
```

验证两个 JWKS 端点�?

```bash
echo "--- Master JWKS ---"
curl -s $KEYCLOAK_URL$MASTER_JWKS_PATH | jq '.keys[0].kid'

echo "--- Acme JWKS ---"
curl -s $KEYCLOAK_URL$ACME_JWKS_PATH | jq '.keys[0].kid'
```

两者应返回不同�?key ID（每�?realm 有独立的密钥对）�?
## �?8 步：配置 Keycloak 免认证路�?& �?Provider JWT 认证策略

### 8.1 创建 Keycloak 免认证路由（�?namespace 引用�?

Keycloak 部署�?`keycloak` namespace，而所�?HTTPRoute 统一放在 `agentgateway-system`（与 Policy �?namespace）。需要创�?ReferenceGrant 允许�?namespace 引用后端 Service�?

```bash
kubectl apply -f manifests/tutorial/30-keycloak-oidc-route.yaml
```

> **安全说明**：此路由仅暴�?`/realms/*` 路径，Keycloak �?Admin API（`/admin/*`）不在此路由中，因此不会被外部直接访问。Keycloak Admin API 的访问应通过内部 IDB Proxy 转发，或使用独立�?port-forward�?

验证路由�?

```bash
kubectl get httproute keycloak-oidc-route -n agentgateway-system
kubectl get referencegrant -n keycloak
```

### 8.2 创建�?Provider JWT 认证策略（绑定到业务路由�?

> **关键变更**：JWT 策略�?`targetRefs` 指向具体的业�?HTTPRoute（`admin-api-route` �?`tenant-api-route`），而不�?Gateway 整体。这�?Keycloak 的免认证路由不受影响�?

```bash
envsubst < manifests/tutorial/31-jwt-auth-policy.template.yaml | kubectl apply -f -
```

> **说明**：每新增一个租�?realm，需要在此策略中添加对应�?provider。生产环境建议通过 K8s Operator 自动化管理�?
>
> **注意事项**：`targetRefs` 不支�?`namespace` 字段（CRD 限制），因此 Policy �?HTTPRoute 必须在同一�?namespace（`agentgateway-system`）。由�?JWT 策略绑定�?HTTPRoute，路由已在第 2 步创建完成，策略创建后会自动关联�?

验证策略�?

```bash
kubectl get AgentgatewayPolicy jwt-auth-policy -n agentgateway-system -o json | jq '.status'
```

## �?9 步：验证 JWT 认证

> **此时的行为变�?*：在第一部分，业�?API 没有任何认证，所有请求都返回 200。现�?JWT 策略已绑定到业务路由，未携带有效 token 的请求会被拦截返�?401�?

### 9.1 验证 Keycloak 免认证路�?

先确�?Keycloak �?OIDC 端点可通过 Gateway �?token 访问（免认证专区）：

```bash
# OIDC Discovery 端点 �?200（不需要任�?token�?
echo "=== Keycloak OIDC Discovery (no token required) ==="
curl -i http://127.0.0.1:8080/realms/master/.well-known/openid-configuration \
  -H "host: www.example.com"
```

预期：`HTTP/1.1 200 OK`，返�?OIDC Discovery JSON�?

```bash
# JWKS 公钥端点 �?200（不需要任�?token�?
echo "=== Keycloak JWKS (no token required) ==="
curl -i http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs \
  -H "host: www.example.com"
```

预期：`HTTP/1.1 200 OK`，返�?JWKS 公钥 JSON�?

> 以上两个请求走的�?`keycloak-oidc-route`，该路由未绑定任�?JWT/OPA 策略，因此无需 token 即可通过�?

### 9.2 验证业务 API 已需�?token �?401

```bash
# 同样的请求，第一部分返回 200，现在应该返�?401
echo "=== No token �?401 (JWT enforced) ==="
curl -i http://127.0.0.1:8080/api/v1/admin/tenants -H "host: www.example.com"
```

预期：`HTTP/1.1 401 Unauthorized`

> 对比第一部分的基线测试：同样的请求从 200 变成�?401，说�?JWT 策略已生效�?

### 9.3 获取各用�?token 并验�?

> **通过 Gateway 获取 token**：如�?Keycloak 免认证路由已配置，也可以通过 Gateway 地址获取 token（将 `$KEYCLOAK_URL` 替换�?`http://127.0.0.1:8080`，并添加 host header）。这里继续使用直连地址以保持配置阶段的简洁性�?

```bash
# 超级管理�?token（来�?master realm�?
ACCESS_TOKEN_SUPERADMIN=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${MASTER_CLIENT_ID}" \
  -d "client_secret=${MASTER_CLIENT_SECRET}" \
  -d "username=superadmin" \
  -d "password=superadmin123" \
  | jq -r '.access_token')

# 租户管理�?token（来�?acme realm�?
ACCESS_TOKEN_ALICE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=alice" \
  -d "password=password" \
  | jq -r '.access_token')

# 普通用�?token（来�?acme realm�?
ACCESS_TOKEN_BOB=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=bob" \
  -d "password=password" \
  | jq -r '.access_token')

echo "SuperAdmin token: ${ACCESS_TOKEN_SUPERADMIN:0:20}..."
echo "Alice token: ${ACCESS_TOKEN_ALICE:0:20}..."
echo "Bob token: ${ACCESS_TOKEN_BOB:0:20}..."
```

> 可以�?https://jwt.io 解码 token，确认包�?`tenant_id`、`roles` �?claims�?

### 9.4 验证 token 中的 claims

```bash
# 解码 Alice �?token（查�?payload 部分�?
echo $ACCESS_TOKEN_ALICE | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{tenant_id, roles, preferred_username, groups}'
```

预期输出类似�?

```json
{
  "tenant_id": "acme",
  "roles": ["tenant_admin", "default-roles-acme"],
  "preferred_username": "alice",
  "groups": ["/admin"]
}
```

### 9.5 �?token 访问业务 API �?200

```bash
# 超级管理员访问管�?API �?200 �?
echo "=== SuperAdmin with token �?200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'

# Alice 访问租户 API �?200 �?
echo "=== Alice with token �?200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "test"}'

# Bob 也可以访问（JWT 层只验证 token 有效性，不做角色检查）�?200 �?
echo "=== Bob with token �?200 (JWT only checks token validity) ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：三个请求都返回 `HTTP/1.1 200 OK`（httpbin 回显请求内容）�?

> ⚠️ **注意**：此�?Bob（普通用户）也能 POST 管理 API！这是因�?JWT 层只验证 token 签名的有效性，不做角色和权限检查。这正是第四部分 OPA 授权层要解决的问题�?

> �?**检查点**：JWT 层已工作。无 token �?401，有�?token �?200（不区分角色）。接下来部署 OPA 来添加细粒度的角色权限控制�?


---

# 第四部分：部�?OPA（多租户授权引擎�?

> 如果你已按前文“第 5 步（前置推荐）”提前完�?OPA 部署，这一部分的部署类命令可跳过；保留后续策略说明与验证步骤即可�?

> **目标**：为业务路由叠加 OPA 授权层。完成后，即�?token 有效，没有正确角色的请求也会被拦截返�?403�?

## �?10 步：编写多租�?OPA 策略

此策略实现了设计文档中的完整授权模型：超级管理员、租户管理员、普通用户三�?RBAC，加上动态策略数据驱动的业务鉴权�?

```bash
kubectl create namespace opa

kubectl apply -f manifests/tutorial/40-opa-policy-configmap.yaml
```

**策略逻辑说明**�?

```
请求进来
  �?AgentGateway JWT 层验签（�?8 步配置）
     �?通过后，Envoy �?JWT payload 写入 metadataContext
  �?Envoy 将请�?+ metadataContext 通过 gRPC 发给 OPA
  �?OPA 提取 tenant_id、roles、groups、username
  �?OPA 从路径提�?path_tenant_id
  �?租户隔离检查：token.tenant_id == path.tenant_id
  �?按角色路由到对应规则�?
     - super_admin �?可创�?查看租户
     - tenant_admin �?可管理本租户身份/策略
     - 普通用�?�?走动态策略匹�?�?回退到静态权限表
  �?返回 allow = true / false
```

---

## �?11 步：部署 OPA 服务

```bash
kubectl apply -f manifests/tutorial/41-opa-deployment-service.yaml
```

验证 OPA 部署�?

```bash
kubectl get pods -n opa -l app=opa
kubectl get svc -n opa opa
```

### 11.1 部署 OPAL（实时策略同步：PEP Proxy �?OPAL �?OPA�?

> 本教程使�?`OPAL Server + OPAL Client` 做“数据变更发布与实时分发”。`PEP Proxy` 不再直接�?OPA Data API，而是调用 OPAL `/data/config`；再�?`OPAL Client` 将更新同步到 OPA�?

```bash
kubectl apply -f proxies/k8s/opal-system.yaml

kubectl -n opal rollout status deploy/postgres
kubectl -n opal rollout status deploy/opal-server
kubectl -n opal rollout status deploy/opal-client
kubectl get pods -n opal
kubectl get svc -n opal opal-server
```

> **说明**�?
> - `proxies/k8s/opal-system.yaml` 内置了演示用 token（`THIS_IS_A_DEV_SECRET_CHANGE_ME`），请在生产环境替换�?
> - `opal-client` �?standalone 模式工作，目�?OPA �?`http://opa.opa.svc.cluster.local:8181/v1`�?
> - `OPAL_DATA_CONFIG_SOURCES` 已指�?`pep-proxy` 的快照接�?`/opal/snapshots/tenant_policies`，用于客户端重连/重启后的数据补齐�?

---

## �?12 步：配置�?namespace 引用�?OPA 外部授权策略

### 12.0 部署 PEP Proxy（放�?OPA + OPAL 部分，确保可直接 Ready�?

`pep-proxy` �?`/healthz` 会访�?OPA `/health`，在 OPAL 模式下还会检�?OPAL Server `/healthcheck`。因此把 `pep-proxy` 放在 OPA + OPAL 部分部署，避免依赖未就绪导致 `pep-proxy` readiness/liveness 失败�?

```bash
kubectl apply -f manifests/tutorial/50-pep-proxy-deployment.yaml

kubectl -n proxy-system rollout status deploy/pep-proxy
```

### 12.0.1 �?PEP Proxy 接入 Gateway

```bash
kubectl apply -f manifests/tutorial/51-pep-proxy-gateway-routes.yaml
```

### 12.1 创建 ReferenceGrant

```bash
kubectl apply -f manifests/tutorial/52-opa-referencegrant.yaml
```

### 12.2 创建 OPA 外部授权策略（绑定到业务路由�?

> **关键变更**：与 JWT 策略一致，OPA 授权策略也绑定到具体的业�?HTTPRoute，确�?Keycloak 免认证路由不�?OPA 鉴权影响�?

```bash
kubectl apply -f manifests/tutorial/53-opa-ext-auth-policy.yaml
```

### 12.3 为管理面路由部署独立 JWT + OPA 策略

> **关键设计**：`idb-proxy-route` �?`pep-proxy-route` 现在也有独立�?JWT 认证�?OPA 授权策略。OPA 规则按管理面路径分级：`super_admin`（master realm）可访问所有管理面路径；`tenant_admin` 仅可访问 `/tenants/{own_tenant_id}/*`�?

```bash
envsubst < manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml | kubectl apply -f -
kubectl apply -f manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml
```

验证�?

```bash
kubectl get AgentgatewayPolicy -n agentgateway-system
```

应看�?6 个策略：

```
NAME                            AGE
jwt-auth-policy                 Xm
opa-ext-auth-policy             Xs
idb-proxy-jwt-auth-policy       Xs
idb-proxy-opa-ext-auth-policy   Xs
pep-proxy-jwt-auth-policy       Xs
pep-proxy-opa-ext-auth-policy   Xs
```

验证所有资源：

```bash
kubectl get AgentgatewayPolicy -n agentgateway-system
kubectl get ReferenceGrant -n opa
kubectl get ReferenceGrant -n keycloak
kubectl get ReferenceGrant -n proxy-system
kubectl get httproute -n agentgateway-system
```

应看到：

```
NAME                            AGE
jwt-auth-policy                 Xm
opa-ext-auth-policy             Xs
idb-proxy-jwt-auth-policy       Xs
idb-proxy-opa-ext-auth-policy   Xs
pep-proxy-jwt-auth-policy       Xs
pep-proxy-opa-ext-auth-policy   Xs

NAME                        AGE
allow-agentgateway-to-opa   Xs

NAME                          AGE
allow-routes-to-keycloak      Xs
allow-routes-to-idb-proxy     Xs
allow-routes-to-pep-proxy     Xs

NAME                  HOSTNAMES             AGE
keycloak-oidc-route   ["www.example.com"]   Xm
admin-api-route       ["www.example.com"]   Xs
tenant-api-route      ["www.example.com"]   Xs
idb-proxy-route       ["www.example.com"]   Xs
pep-proxy-route       ["www.example.com"]   Xs
```


## �?13 步：验证 OPA 授权

> **此时的行为变�?*：第三部分中，Bob 拿着有效 token 可以 POST 管理 API�?00）。现�?OPA 授权层已叠加，只有正确角色的用户才能通过�?

```bash
# 重新获取 tokens（可能已过期�?
ACCESS_TOKEN_SUPERADMIN=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${MASTER_CLIENT_ID}" \
  -d "client_secret=${MASTER_CLIENT_SECRET}" \
  -d "username=superadmin" \
  -d "password=superadmin123" | jq -r '.access_token')

ACCESS_TOKEN_ALICE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=alice" \
  -d "password=password" | jq -r '.access_token')

ACCESS_TOKEN_BOB=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=bob" \
  -d "password=password" | jq -r '.access_token')
```

### 13.1 超级管理员创建租�?�?200 �?

```bash
echo "=== SuperAdmin POST /admin/tenants �?200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：`HTTP/1.1 200 OK`

### 13.2 普通用户访问管�?API �?403 �?

```bash
# 同样的请求，第三部分�?Bob 拿着 token 返回 200，现在应该返�?403
echo "=== Bob POST /admin/tenants �?403 (OPA enforced) ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：`HTTP/1.1 403 Forbidden`

> 对比第三部分：同样的请求（Bob + 有效 token + POST /admin/tenants）从 200 变成�?403，说�?OPA 授权层已生效�?

### 13.3 租户管理员管理本租户 �?200 �?

```bash
echo "=== Alice POST /tenants/acme/roles �?200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "test"}'
```

预期：`HTTP/1.1 200 OK`（Alice �?acme �?tenant_admin�?

### 13.4 跨租户访�?�?403 �?

```bash
echo "=== Alice GET /tenants/other-corp/roles �?403 (cross-tenant) ==="
curl -i http://127.0.0.1:8080/api/v1/tenants/other-corp/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

预期：`HTTP/1.1 403 Forbidden`（Alice �?tenant_id=acme，不匹配 other-corp�?

### 13.5 管理面鉴权验证：�?token 访问 IDB Proxy �?401

```bash
echo "=== No token �?IDB Proxy �?401 ==="
curl -i http://127.0.0.1:8080/proxy/idb/healthz \
  -H "host: www.example.com"
```

预期：`HTTP/1.1 401 Unauthorized`（之前无策略时返�?200，现�?JWT 策略已生效）

### 13.6 管理面鉴权验证：super_admin 访问全部管理�?�?200 �?

```bash
echo "=== SuperAdmin �?IDB Proxy bootstrap �?200 ==="
curl -i http://127.0.0.1:8080/proxy/idb/healthz \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}"
```

预期：`HTTP/1.1 200 OK`

### 13.7 管理面鉴权验证：tenant_admin 访问本租�?�?200 �?

```bash
echo "=== Alice �?IDB Proxy /tenants/acme/groups �?200 ==="
curl -i http://127.0.0.1:8080/proxy/idb/tenants/acme/groups \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

预期：`HTTP/1.1 200 OK`（Alice �?acme �?tenant_admin，OPA 允许访问 `/tenants/acme/*`�?

### 13.8 管理面鉴权验证：tenant_admin 跨租�?�?403 �?

```bash
echo "=== Alice �?IDB Proxy /tenants/other/groups �?403 ==="
curl -i http://127.0.0.1:8080/proxy/idb/tenants/other/groups \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

预期：`HTTP/1.1 403 Forbidden`（Alice �?tenant_id=acme，不匹配 other�?

### 13.9 管理面鉴权验证：普通用户访问管理面 �?403 �?

```bash
echo "=== Bob �?IDB Proxy /tenants/acme/groups �?403 ==="
curl -i http://127.0.0.1:8080/proxy/idb/tenants/acme/groups \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}"
```

预期：`HTTP/1.1 403 Forbidden`（Bob 没有 tenant_admin �?super_admin 角色�?

> �?**检查点**：双层安全模型完整工作。无 token �?401（JWT），�?token 但角色不�?�?403（OPA），token 有效且角色正�?�?200。管理面路由同样�?JWT + OPA 保护�?

### 行为变化总结

| 请求场景 | 第一部分（无安全层） | 第三部分（仅 JWT�?| 第四部分（JWT + OPA�?|
|---|---|---|---|
| �?token �?/api/v1/admin/tenants | 200 �?| 401 �?| 401 �?|
| Bob (token) �?POST /api/v1/admin/tenants | �?| 200 �?| **403** �?|
| SuperAdmin (token) �?POST /api/v1/admin/tenants | �?| 200 �?| 200 �?|
| Alice (token) �?/tenants/other-corp/roles | �?| 200 �?| **403** �?|

> **管理面行为变�?*：在�?12.3 步之前，`/proxy/idb/*` �?`/proxy/pep/*` 无需任何认证即可访问。部署管理面策略后，�?token �?401，super_admin �?200，tenant_admin 仅本租户 �?200，普通用�?�?403�?


---

# 第五部分：端到端完整验证

## �?14 步：完整测试场景

确保 port-forward 仍在运行�?

```bash
# 如果之前�?port-forward 断开了，重新建立
kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80 &
```

### 14.1 重新获取 tokens（防止过期）

```bash
# 超级管理�?
ACCESS_TOKEN_SUPERADMIN=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${MASTER_CLIENT_ID}" \
  -d "client_secret=${MASTER_CLIENT_SECRET}" \
  -d "username=superadmin" \
  -d "password=superadmin123" | jq -r '.access_token')

# 租户管理�?Alice
ACCESS_TOKEN_ALICE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=alice" \
  -d "password=password" | jq -r '.access_token')

# 普通用�?Bob
ACCESS_TOKEN_BOB=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=bob" \
  -d "password=password" | jq -r '.access_token')

echo "Tokens acquired:"
echo "  SuperAdmin: ${ACCESS_TOKEN_SUPERADMIN:0:20}..."
echo "  Alice:      ${ACCESS_TOKEN_ALICE:0:20}..."
echo "  Bob:        ${ACCESS_TOKEN_BOB:0:20}..."
```

### 14.2 测试 0：Keycloak 免认证端�?�?200（无需 token�?

```bash
echo "=== Test 0a: Keycloak OIDC Discovery �?200 (no token) ==="
curl -i http://127.0.0.1:8080/realms/master/.well-known/openid-configuration \
  -H "host: www.example.com"

echo ""
echo "=== Test 0b: Keycloak Token Endpoint �?可用 (no token) ==="
curl -s -X POST http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  -H "host: www.example.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${MASTER_CLIENT_ID}" \
  -d "client_secret=${MASTER_CLIENT_SECRET}" \
  -d "username=superadmin" \
  -d "password=superadmin123" | jq '{access_token: .access_token[:20], token_type, expires_in}'
```

预期�?
- Test 0a：`HTTP/1.1 200 OK`，返�?OIDC Discovery JSON
- Test 0b：成功获�?token（通过 Gateway 代理�?Keycloak�?

> 这两个测试验证了 Keycloak 免认证专区的正确�?—�?请求�?`keycloak-oidc-route`，不经过 JWT/OPA 鉴权链�?

### 14.3 测试 1：无 token 访问业务 API �?401（JWT 层拦截）

```bash
echo "=== Test 1: No token �?401 ==="
curl -i http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com"
```

预期：`HTTP/1.1 401 Unauthorized`

### 14.4 测试 2：伪�?token �?401（JWT 层拦截）

```bash
echo "=== Test 2: Fake token �?401 ==="
curl -i http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer fake.invalid.token"
```

预期：`HTTP/1.1 401 Unauthorized`

### 14.5 测试 3：超级管理员创建租户 �?200 �?

```bash
echo "=== Test 3: SuperAdmin POST /admin/tenants �?200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：`HTTP/1.1 200 OK`（httpbin 返回请求内容�?

### 14.6 测试 4：普通用户访问管�?API �?403 �?

```bash
echo "=== Test 4: Bob POST /admin/tenants �?403 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：`HTTP/1.1 403 Forbidden`（Bob 没有 super_admin 角色�?

### 14.7 测试 5：租户管理员管理本租户角�?�?200 �?

```bash
echo "=== Test 5: Alice GET /tenants/acme/roles �?200 ==="
curl -i http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

预期：`HTTP/1.1 200 OK`（Alice �?acme �?tenant_admin�?

### 14.8 测试 6：租户管理员管理本租户策�?�?200 �?

```bash
echo "=== Test 6: Alice POST /tenants/acme/policies �?200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
  -H "Content-Type: application/json" \
  -d '{"name": "order-read", "effect": "allow", "subjects": ["role:analyst"], "resources": ["db:orders"], "actions": ["read"]}'
```

预期：`HTTP/1.1 200 OK`

### 14.9 测试 7：普通用户不能管理策�?�?403 �?

```bash
echo "=== Test 7: Bob POST /tenants/acme/policies �?403 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"name": "sneaky-policy"}'
```

预期：`HTTP/1.1 403 Forbidden`（Bob 没有 tenant_admin 角色�?

### 14.10 测试 8：租户管理员不能跨租�?�?403 �?

```bash
echo "=== Test 8: Alice GET /tenants/other-corp/roles �?403 (cross-tenant) ==="
curl -i http://127.0.0.1:8080/api/v1/tenants/other-corp/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

预期：`HTTP/1.1 403 Forbidden`（Alice �?tenant_id=acme，不匹配 other-corp�?

### 14.11 测试 9：普通用户访问业�?API（静态回退�?�?200 �?

```bash
echo "=== Test 9: Bob GET /tenants/acme/apps/order-service/orders �?200 ==="
curl -i http://127.0.0.1:8080/api/v1/tenants/acme/apps/order-service/orders \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}"
```

预期：`HTTP/1.1 200 OK`（Bob 属于 users 组，静态权限允�?GET�?

> **排障提示**：如果此测试返回 403 而非 200，请检�?Bob �?JWT 是否包含 `groups` claim。解�?token 查看：`echo $ACCESS_TOKEN_BOB | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.groups'`。如�?`groups` �?null 或缺失，说明 Keycloak 中未正确配置 Group Membership Mapper。请确保使用最新版本的 IDB Proxy（已包含 groups mapper 自动配置），并重新运�?bootstrap�?

### 14.12 测试 10：普通用�?POST 业务 API（静态回退�?�?403 �?

```bash
echo "=== Test 10: Bob POST /tenants/acme/apps/order-service/orders �?403 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/apps/order-service/orders \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"order": "test"}'
```

预期：`HTTP/1.1 403 Forbidden`（users 组静态权限不允许 POST�?

### 测试结果汇�?

| # | 场景 | 用户 | 路径 | Method | 路由 | JWT �?| OPA �?| 结果 |
|---|---|---|---|---|---|---|---|---|
| 0a | Keycloak OIDC Discovery | �?| /realms/master/.well-known/... | GET | keycloak-oidc-route | ⏭️ 跳过 | ⏭️ 跳过 | **200** |
| 0b | 通过 Gateway 获取 token | �?| /realms/master/.../token | POST | keycloak-oidc-route | ⏭️ 跳过 | ⏭️ 跳过 | **200** |
| 1 | �?token 访问业务 API | �?| /api/v1/admin/tenants | POST | admin-api-route | �?401 | �?| **401** |
| 2 | 伪�?token | �?| /api/v1/admin/tenants | POST | admin-api-route | �?401 | �?| **401** |
| 3 | 超级管理员创建租�?| superadmin | /api/v1/admin/tenants | POST | admin-api-route | �?| �?super_admin | **200** |
| 4 | 普通用户访问管�?API | bob | /api/v1/admin/tenants | POST | admin-api-route | �?| �?no super_admin | **403** |
| 5 | 租户管理员查看角�?| alice | /api/v1/tenants/acme/roles | GET | tenant-api-route | �?| �?tenant_admin + match | **200** |
| 6 | 租户管理员添加策�?| alice | /api/v1/tenants/acme/policies | POST | tenant-api-route | �?| �?tenant_admin + match | **200** |
| 7 | 普通用户管理策�?| bob | /api/v1/tenants/acme/policies | POST | tenant-api-route | �?| �?no tenant_admin | **403** |
| 8 | 跨租户访�?| alice | /api/v1/tenants/other-corp/roles | GET | tenant-api-route | �?| �?tenant mismatch | **403** |
| 9 | 业务 API GET | bob | /api/v1/tenants/acme/apps/.../orders | GET | tenant-api-route | �?| �?groups �?users + GET | **200** |
| 10 | 业务 API POST | bob | /api/v1/tenants/acme/apps/.../orders | POST | tenant-api-route | �?| �?groups �?users, no POST | **403** |
| 11 | 管理面无 token | �?| /proxy/idb/healthz | GET | idb-proxy-route | �?401 | �?| **401** |
| 12 | super_admin 访问管理�?| superadmin | /proxy/idb/healthz | GET | idb-proxy-route | �?| �?super_admin | **200** |
| 13 | tenant_admin 本租户管理面 | alice | /proxy/idb/tenants/acme/groups | GET | idb-proxy-route | �?| �?tenant_admin + match | **200** |
| 14 | tenant_admin 跨租户管理面 | alice | /proxy/idb/tenants/other/groups | GET | idb-proxy-route | �?| �?tenant mismatch | **403** |
| 15 | 普通用户访问管理面 | bob | /proxy/idb/tenants/acme/groups | GET | idb-proxy-route | �?| �?no admin role | **403** |

---

> **到这里（第五部分结束）你已经完成核心主线�?*  
> 建议先阅读第八部分《调试与运维》作为排障手册，再回到下面两个可选扩展章节�?

---

# 第六部分（可选扩展）：动态策略管理（通过 PEP Proxy + OPAL 实时更新�?

## �?15 步：通过 PEP Proxy 推送租户策略（�?OPAL 实时同步�?OPA�?

从这一节开始，不再直连 OPA Data API。所有策略写入与读取都经�?`PEP Proxy (FastAPI)`，并通过 gateway 入口访问�?
在本版本中，`PEP Proxy` 的写操作会触�?OPAL `/data/config`，再�?`OPAL Client` 实时写入 OPA 数据路径 `/tenant_policies/*`�?
接口约定：`PUT /tenants/{tenant_id}/policies`（覆盖写入）、`GET /tenants/{tenant_id}/policies`（读取）、`DELETE /tenants/{tenant_id}/policies`（删除）、`POST /simulate`（透传 OPA 决策模拟）�?

### 15.1 �?acme 租户推送策略数�?

```bash
# 推送策略：analyst 角色可以 read orders
curl -s -X PUT http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "name": "order-read-policy",
      "effect": "allow",
      "subjects": ["role:analyst"],
      "resources": ["/api/v1/tenants/acme/apps/order-service/**"],
      "actions": ["read"]
    },
    {
      "name": "report-export-policy",
      "effect": "allow",
      "subjects": ["role:analyst", "role:tenant_admin"],
      "resources": ["/api/v1/tenants/acme/apps/report-service/**"],
      "actions": ["read", "create"]
    },
    {
      "name": "viewer-read-policy",
      "effect": "allow",
      "subjects": ["role:viewer"],
      "resources": ["/api/v1/tenants/acme/apps/*/orders"],
      "actions": ["read"]
    }
  ]' | jq .
```

### 15.2 验证策略数据已加�?

```bash
curl -s http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" | jq '.[].name'

# （可选）观察 OPAL 实时同步链路日志
kubectl logs -n opal deploy/opal-server --tail=50
kubectl logs -n opal deploy/opal-client --tail=50
```

预期输出�?

```
"order-read-policy"
"report-export-policy"
"viewer-read-policy"
```

并且�?`opal-client` 日志中应能看到数据更�?保存�?OPA 的记录（不同版本日志字段略有差异）�?

### 15.3 验证动态策略生�?

```bash
# 重新获取 tokens（可能已过期�?
ACCESS_TOKEN_BOB=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=bob" \
  -d "password=password" | jq -r '.access_token')

# Bob (analyst) 读取订单 �?200 ✅（动态策�?order-read-policy 允许�?
echo "=== Bob GET orders (dynamic policy) ==="
curl -i http://127.0.0.1:8080/api/v1/tenants/acme/apps/order-service/orders \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}"

# Bob (analyst) 导出报表 �?200 ✅（动态策�?report-export-policy 允许�?
echo "=== Bob POST report export (dynamic policy) ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/apps/report-service/reports \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"format": "csv"}'
```

### 15.4 模拟 OPA 决策（通过 PEP Proxy�?

```bash
# 模拟 Bob (analyst, tenant=acme) 访问订单
curl -s -X POST http://127.0.0.1:8080/proxy/pep/simulate \
  -H "host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "attributes": {
        "request": {
          "http": {
            "method": "GET",
            "path": "/api/v1/tenants/acme/apps/order-service/orders"
          }
        },
        "metadataContext": {
          "filterMetadata": {
            "envoy.filters.http.jwt_authn": {
              "jwt_payload": {
                "preferred_username": "bob",
                "tenant_id": "acme",
                "roles": ["analyst", "default-roles-acme"],
                "groups": ["/users"],
                "iss": "http://keycloak:8080/realms/acme"
              }
            }
          }
        }
      }
    }
  }' | jq .
```

预期：`{"result": true}`

```bash
# 模拟 Bob 跨租户访问（应被拒绝�?
curl -s -X POST http://127.0.0.1:8080/proxy/pep/simulate \
  -H "host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "attributes": {
        "request": {
          "http": {
            "method": "GET",
            "path": "/api/v1/tenants/other-corp/apps/order-service/orders"
          }
        },
        "metadataContext": {
          "filterMetadata": {
            "envoy.filters.http.jwt_authn": {
              "jwt_payload": {
                "preferred_username": "bob",
                "tenant_id": "acme",
                "roles": ["analyst"],
                "groups": ["/users"]
              }
            }
          }
        }
      }
    }
  }' | jq .
```

预期：`{"result": false}`（tenant_id 不匹配）

---

# 第七部分（可选扩展）：添加更多租�?

## �?16 步：创建第二个租户（globex�?

重复�?6 步的流程，使用不�?tenant_id，通过 IDB Proxy 快速完成初始化�?

### 16.1 创建 globex 租户并导�?JWT Provider 所需变量

```bash
export NEW_TENANT_ID="globex"

GLOBEX_BOOTSTRAP=$(curl -s -X POST http://127.0.0.1:8080/proxy/idb/tenants/${NEW_TENANT_ID}/bootstrap \
  -H "host: www.example.com" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Globex Corporation",
    "client_id": "globex-gateway-client",
    "tenant_admin": {
      "username": "gina",
      "password": "password",
      "email": "gina@globex.com",
      "groups": ["admin"]
    }
  }')

echo "$GLOBEX_BOOTSTRAP" | jq .

export GLOBEX_CLIENT_ID=$(echo "$GLOBEX_BOOTSTRAP" | jq -r '.client_id')
export GLOBEX_CLIENT_SECRET=$(echo "$GLOBEX_BOOTSTRAP" | jq -r '.client_secret')
export GLOBEX_CLIENT_UUID=$(echo "$GLOBEX_BOOTSTRAP" | jq -r '.client_uuid')
export GLOBEX_ISSUER=$KEYCLOAK_URL/realms/${NEW_TENANT_ID}
export GLOBEX_JWKS_PATH=/realms/${NEW_TENANT_ID}/protocol/openid-connect/certs
```

### 16.2 更新 JWT 策略（添�?globex realm provider�?

```bash
envsubst < manifests/tutorial/61-jwt-auth-policy-add-globex.template.yaml | kubectl apply -f -

echo "Tenant '${NEW_TENANT_ID}' created and JWT policy updated."
```

> **验证租户隔离**：使�?globex 租户�?token 尝试访问 acme 的资源，应该返回 403�?

---

# 第八部分：调试与运维（建议在第五部分后阅读）

## 查看 OPA 决策日志

```bash
kubectl logs -n opa -l app=opa -f
```

每次授权请求都会输出完整�?input �?result�?

新增版本中，授权通过时还会在上游请求头中注入 `x-authz-policy-version`（由 OPA 根据租户策略包版本生成），便于将业务日志与策略版本关联排查�?

## 查看 OPAL 同步链路日志（实时更新排障）

```bash
kubectl logs -n opal deploy/opal-server -f
kubectl logs -n opal deploy/opal-client -f
```

排查重点�?

- `opal-server` 是否收到 `/data/config` 更新事件
- `opal-client` 是否成功消费 `tenant_policies` topic
- `opal-client` 是否成功写入 `http://opa.opa.svc.cluster.local:8181/v1`

## 查看 OPA 中已加载的策略数�?

```bash
# 通过 PEP Proxy 查看 acme 租户策略
curl -s http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" | jq .

# 查看完整策略包（包含 version / metadata / policies�?
curl -s http://127.0.0.1:8080/proxy/pep/tenants/acme/policy-package \
  -H "host: www.example.com" | jq .

# 通过 PEP Proxy 查看所有租户策�?
curl -s http://127.0.0.1:8080/proxy/pep/tenants \
  -H "host: www.example.com" | jq .
```

## 查看 IDB / PEP 审计事件（新增）

```bash
# 查看 IDB Proxy 审计事件（身份面操作：tenant/group/saml 等）
curl -s "http://127.0.0.1:8080/proxy/idb/audit/events?limit=20" \
  -H "host: www.example.com" | jq .

# 查看 PEP Proxy 审计事件（策略变�?/ 回放�?
curl -s "http://127.0.0.1:8080/proxy/pep/audit/events?limit=20" \
  -H "host: www.example.com" | jq .
```

> 如果你使用了扩展测试脚本 `scripts/tutorial-curl-extended-tests.sh`，可以在这里查看 `upsert_tenant_policies`、`delete_tenant_policies`、`replay_audit_event` 等事件记录�?

## 更新 OPA 策略（Rego 逻辑�?

```bash
# 编辑策略
kubectl edit configmap opa-policy -n opa

# 重启 OPA Pod 使新策略生效
kubectl rollout restart deployment opa -n opa
```

> 注意：重�?OPA 会清除内存中的动态策略数据。若使用 OPAL，同步数据通常会在下一次策略发布或 OPAL Client 重连/重同步后恢复；生产环境建议为策略数据设计持久化来源（如数据库 + OPAL datasource）�?

## 删除租户策略数据

```bash
# 删除 acme 租户的所有策略（通过 PEP Proxy�?
curl -X DELETE http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com"
```

## 查看 AgentGateway 策略状�?

```bash
kubectl get AgentgatewayPolicy -n agentgateway-system
kubectl get AgentgatewayPolicy jwt-auth-policy -n agentgateway-system -o yaml
kubectl get AgentgatewayPolicy opa-ext-auth-policy -n agentgateway-system -o yaml
```

> 若启用了 JWT provider 自动注册，可�?`jwt-auth-policy` 中检查新增租�?realm �?`issuer` �?`jwksPath` 是否已自动写入�?

## Token 过期处理

Keycloak 签发�?access_token 默认有效期较短（通常 5 分钟）。在实际应用中使�?refresh_token�?

```bash
# 首次登录获取 refresh_token
TOKENS=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=alice" \
  -d "password=password")

ACCESS_TOKEN=$(echo $TOKENS | jq -r '.access_token')
REFRESH_TOKEN=$(echo $TOKENS | jq -r '.refresh_token')

# �?refresh_token 刷新
NEW_ACCESS_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "refresh_token=${REFRESH_TOKEN}" | jq -r '.access_token')
```

---

# 第九部分：清理资�?

```bash
# 删除 OPA 相关资源
kubectl delete AgentgatewayPolicy opa-ext-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy idb-proxy-jwt-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy idb-proxy-opa-ext-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy pep-proxy-jwt-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy pep-proxy-opa-ext-auth-policy -n agentgateway-system
kubectl delete ns opa
kubectl delete ns opal

# 删除 JWT 策略
kubectl delete AgentgatewayPolicy jwt-auth-policy -n agentgateway-system

# 删除所�?HTTPRoute（都�?agentgateway-system�?
kubectl delete httproute keycloak-oidc-route -n agentgateway-system
kubectl delete httproute admin-api-route -n agentgateway-system
kubectl delete httproute tenant-api-route -n agentgateway-system
kubectl delete httproute idb-proxy-route -n agentgateway-system
kubectl delete httproute pep-proxy-route -n agentgateway-system

# 删除 ReferenceGrant
kubectl delete referencegrant allow-routes-to-keycloak -n keycloak
kubectl delete referencegrant allow-routes-to-httpbin -n httpbin
kubectl delete referencegrant allow-routes-to-idb-proxy -n proxy-system
kubectl delete referencegrant allow-routes-to-pep-proxy -n proxy-system

# 删除 Keycloak
kubectl delete ns keycloak

# 删除 httpbin
kubectl delete -f https://raw.githubusercontent.com/kgateway-dev/kgateway/refs/heads/main/examples/httpbin.yaml

# 删除 IDB Proxy / PEP Proxy
kubectl delete ns proxy-system
```

---

# 第十部分（增补）：扩展功能验证（SAML / Groups / DB Authorize / Audit Replay�?

> **增补说明�?026-02�?*：本教程后续已扩�?`IDB Proxy` / `PEP Proxy` / `OPA` 能力，新增了 SAML IdP 管理、真�?Group 管理、数据库资源授权检查、审计与策略回放能力。本节给出推荐验证流程与脚本�?

## 10.1 新增接口能力（概览）

### IDB Proxy（`/proxy/idb/*`�?

- Group CRUD：`/tenants/{tenant_id}/groups`
- 用户入组/移组：`/tenants/{tenant_id}/users/{username}/groups`
- SAML IdP 管理：`/tenants/{tenant_id}/saml/idps`
- SAML IdP 启停：`/tenants/{tenant_id}/saml/idps/{alias}/enabled`
- SAML 证书轮换：`/tenants/{tenant_id}/saml/idps/{alias}/certificates/rotate`
- SAML Mapper 管理：`/tenants/{tenant_id}/saml/idps/{alias}/mappers`
- JWT Provider 自动注册（可选）：`/tenants/{tenant_id}/jwt-providers/sync`
- 审计查询：`/audit/events`、`/audit/events/{event_id}`

### PEP Proxy（`/proxy/pep/*`�?

- 策略包（带版�?元数据）查询：`/tenants/{tenant_id}/policy-package`
- 数据库资源授权检查：`/authorize/db`
- 审计查询/回放：`/audit/events`、`/audit/replay/{event_id}`

## 10.2 OPA/网关行为增补

- OPA ext_authz 决策路径改为 `envoy/authz/decision`（不再是仅布�?`allow`�?
- OPA 会向后端注入可信头（并移除同名来路头）：
  - `x-tenant-id`
  - `x-user`
  - `x-roles`
  - `x-groups`
  - `x-client-id`
  - `x-authz-policy-version`
- OPA 支持 `tenant_policies` 的“策略包格式”：
  - `version`
  - `metadata`
  - `policies[]`
- OPA 保持兼容旧格式（直接�?`policies[]` 数组�?

## 10.3 启用 JWT Provider 自动注册（可选）

如果你希望“创建租户后自动把新 realm 注册�?`jwt-auth-policy`”，需要给 `idb-proxy` 额外 RBAC 权限�?

```bash
kubectl apply -f manifests/tutorial/22-idb-proxy-jwt-sync-rbac.yaml
```

并在 `manifests/tutorial/20-idb-proxy-deployment.yaml` 中启用：

- `ENABLE_JWT_PROVIDER_AUTOREG=true`
- `KEYCLOAK_PUBLIC_ISSUER_BASE_URL`（建议设置为外部访问 Keycloak �?base URL，例�?`http://www.example.com`�?

> 说明：`manifests/tutorial/20-idb-proxy-deployment.yaml` 已包�?`serviceAccountName: idb-proxy` 示例；`22-idb-proxy-jwt-sync-rbac.yaml` 负责补齐访问 `AgentgatewayPolicy` 的权限�?

> 若不启用自动注册，也可以使用 `POST /proxy/idb/tenants/{tenant_id}/jwt-providers/sync` 手动触发�?

## 10.4 扩展 curl 测试脚本（推荐）

已新增脚本：`scripts/tutorial-curl-extended-tests.sh`

覆盖内容�?

- Group 创建与用户入�?
- SAML IdP 创建/更新/启停/证书轮换
- 数据库资源策略下发与 `/authorize/db`
- PEP 审计事件查询与回放（策略恢复�?

使用示例�?

```bash
# 前提：另一个终端已启动 port-forward
kubectl -n agentgateway-system port-forward deployment/agentgateway-proxy 8080:80

# 运行脚本（默�?tenant=acme, user=alice�?
bash scripts/tutorial-curl-extended-tests.sh

# 自定义参数（示例�?
GATEWAY_URL=http://127.0.0.1:8080 \
HOST_HEADER=www.example.com \
TENANT_ID=acme \
TENANT_USER=alice \
GROUP_NAME=finance \
SAML_ALIAS=corp-saml-demo \
CLEANUP_SAML=true \
bash scripts/tutorial-curl-extended-tests.sh
```

> 说明：脚本中�?SAML metadata 使用内置最小示�?XML（无证书，便于演�?API 流程）。生产环境请替换为真�?IdP metadata，并开启签名校验与证书管理�?

> Windows 用户说明：脚本为 Bash 脚本，建议使�?`Git Bash` / `WSL` 运行；若仅使�?PowerShell，可参考脚本中�?curl 调用逐条执行�?

## 10.5 后端“仅信任网关来源流量”示例（可选加固）

本教程新增了一个可选示�?`NetworkPolicy`�?

```bash
kubectl apply -f manifests/tutorial/11-httpbin-networkpolicy.yaml
```

用途：限制示例后端 `httpbin` 仅接受来�?`agentgateway-system`（以及同 namespace）的流量，从网络层帮助你落实“后端只信任网关注入 metadata 头”的约束�
