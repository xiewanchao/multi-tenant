# AgentGateway 多租户身份与策略控制平台

基于 **AgentGateway (Envoy) + Keycloak + OPA + OPAL** 的多租户身份认证与细粒度授权方案，提供从网关入口到策略引擎的完整安全链路。

## 特性

- **统一网关入口**：AgentGateway (Envoy-based) 作为唯一入口，路由、认证、授权一体化
- **多租户隔离**：每个租户独立 Keycloak Realm，OPA 按 `tenant_id` 强制隔离
- **三级 RBAC**：超级管理员 / 租户管理员 / 普通用户，角色与路径精确匹配
- **动态策略**：通过 OPAL 实时同步租户策略数据到 OPA，无需重启
- **管理面独立鉴权**：IDB Proxy / PEP Proxy 的管理接口有独立的 JWT + OPA 策略
- **渐进式部署**：教程按阶段叠加安全层，每步可独立验证

## 架构概览

```
[Client / Admin / User]
        │
        ▼
   [AgentGateway-Proxy] (Envoy, port 80)
     │
     │  路由分三区：
     │
     ├─── 免认证专区（Keycloak OIDC 端点）
     │      不经过 JWT 认证 / OPA 授权
     │      /realms/*  → [Keycloak]  (token 签发、JWKS、OIDC discovery)
     │
     ├─── 业务鉴权区（所有业务 API）
     │      │
     │      │  ① JWT 认证 (AuthN) — 仅 attach 到业务路由
     │      │     AgentGateway 用 Keycloak JWKS 公钥验签
     │      │     支持多 realm（master + 各租户 realm）
     │      │     → 无 token / token 无效 → 401 Unauthorized
     │      │
     │      │  ② 外部授权 (AuthZ) — 仅 attach 到业务路由
     │      │     AgentGateway → OPA (gRPC ext_authz)
     │      │     OPA 按 tenant_id 做多租户隔离 RBAC
     │      │     → 无权限 → 403 Forbidden
     │      │
     │      ├── /api/v1/admin/*            → [Admin Service]
     │      └── /api/v1/tenants/*/apps/*   → [App Service]
     │
     └─── 管理面鉴权区（独立 JWT + OPA 策略）
            │
            │  ① mgmt JWT 认证 — attach 到管理面路由
            │  ② mgmt OPA 授权 — attach 到管理面路由
            │
            ├── /proxy/idb/*  → [IDB Proxy] ──→ [Keycloak Admin API]
            └── /proxy/pep/*  → [PEP Proxy] ──→ [OPAL Server] ──→ [OPA]
```

> **关键设计决策**：
> 1. Keycloak 挂在 Gateway 后面统一入口，但其 OIDC 端点（token 签发、JWKS 公钥、OpenID Discovery）必须作为"免认证专区"独立路由。JWT 认证和 OPA 授权策略通过 `targetRefs` 精确绑定到业务 HTTPRoute，而非 Gateway 整体，从而避免"鸡生蛋"问题 —— 客户端必须先能无 token 调用 Keycloak 拿到 token，才能用 token 调用业务 API。
> 2. **Namespace 统一原则**：所有 HTTPRoute 和 AgentgatewayPolicy 统一放在 `agentgateway-system` namespace。因为 `AgentgatewayPolicy` 的 `targetRefs` 不支持跨 namespace 引用（CRD 无 `namespace` 字段），Policy 只能绑定同 namespace 的 HTTPRoute。后端 Service（keycloak、httpbin、opa）通过 ReferenceGrant 跨 namespace 引用。
> 3. **管理面独立策略**：IDB Proxy 和 PEP Proxy 的管理接口有独立的 JWT 和 OPA 策略（`54-mgmt-jwt-auth-policy` / `55-mgmt-opa-ext-auth-policy`），与业务面策略分离。初始化阶段（bootstrap）需要先不启用管理面策略，待 Keycloak 配置完成后再应用。

**三层角色模型**：

| 角色 | 说明 | JWT 来源 | 可访问路径 |
|---|---|---|---|
| 超级管理员 | 全局治理、创建租户 | master realm | `/api/v1/admin/*`、`/proxy/idb/*`、`/proxy/pep/*` |
| 租户管理员 | 管理本租户身份与策略 | 租户 realm | `/api/v1/tenants/{own_tenant}/*`、`/proxy/idb/tenants/{own_tenant}/*`、`/proxy/pep/tenants/{own_tenant}/*` |
| 普通用户 | 业务操作 | 租户 realm | `/api/v1/tenants/{own_tenant}/apps/*` |

**双层安全模型**（业务面 + 管理面各有独立策略）：

| 层级 | 组件 | 职责 | 失败响应 | 绑定目标 |
|---|---|---|---|---|
| 第 1 层：认证 (AuthN) | Keycloak + JWT | 验证"你是谁" — token 签名、过期、issuer | 401 Unauthorized | 业务/管理面 HTTPRoute |
| 第 2 层：授权 (AuthZ) | OPA ext_authz | 决定"你能做什么" — 多租户隔离 RBAC | 403 Forbidden | 业务/管理面 HTTPRoute |

> **为什么绑定到 HTTPRoute 而非 Gateway？** 如果将 JWT/OPA 策略绑定到 Gateway 整体，所有经过 Gateway 的流量（包括 Keycloak 的 token 端点）都会要求 JWT —— 但客户端还没有 token！通过将策略精确绑定到业务 HTTPRoute，Keycloak 的 OIDC 路由可以免认证通行。

## 项目结构

```
.
├── README.md                              ← 本文件（完整部署教程）
├── agentgateway-multi-tenant-tutorial.md  ← 精简版教程（快速参考）
├── auth-chain-example.md                  ← 认证链路完整示例
│
├── manifests/tutorial/                    ← 分步部署 YAML（按编号顺序）
│   ├── 00-gateway.yaml                    ← Gateway 定义
│   ├── 10-baseline-routes.yaml            ← 业务路由 + ReferenceGrant
│   ├── 11-httpbin-networkpolicy.yaml      ← 可选网络硬化
│   ├── 20-idb-proxy-deployment.yaml       ← IDB Proxy Deployment + Service
│   ├── 21-idb-proxy-gateway-routes.yaml   ← IDB Proxy HTTPRoute
│   ├── 22-idb-proxy-jwt-sync-rbac.yaml    ← JWT Provider 自动注册 RBAC
│   ├── 30-keycloak-oidc-route.yaml        ← Keycloak 免认证路由
│   ├── 31-jwt-auth-policy.template.yaml   ← 业务面 JWT 策略（需 envsubst）
│   ├── 40-opa-policy-configmap.yaml       ← OPA Rego 策略 ConfigMap
│   ├── 41-opa-deployment-service.yaml     ← OPA Deployment + Service
│   ├── 42-opal-server.yaml               ← OPAL Server（sidecar 模式用）
│   ├── 50-pep-proxy-deployment.yaml       ← PEP Proxy Deployment + Service
│   ├── 51-pep-proxy-gateway-routes.yaml   ← PEP Proxy HTTPRoute
│   ├── 52-opa-referencegrant.yaml         ← OPA 跨 NS 引用授权
│   ├── 53-opa-ext-auth-policy.yaml        ← 业务面 OPA ext_authz 策略
│   ├── 54-mgmt-jwt-auth-policy.template.yaml  ← 管理面 JWT 策略（需 envsubst）
│   ├── 55-mgmt-opa-ext-auth-policy.yaml   ← 管理面 OPA ext_authz 策略
│   ├── 56-agentgateway-sidecar-opa-service.yaml ← Sidecar OPA Service
│   └── 61-jwt-auth-policy-add-globex.template.yaml ← 新增租户 JWT Provider
│
├── proxies/                               ← FastAPI 代理服务
│   ├── idb-proxy/                         ← 身份管理代理（Keycloak facade）
│   │   ├── app/main.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── pep-proxy/                         ← 策略管理代理（OPAL/OPA facade）
│   │   ├── app/main.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── k8s/                               ← 合并版 K8s 部署清单
│   │   ├── opal-system.yaml
│   │   ├── proxy-system.yaml
│   │   └── proxy-gateway-routes.yaml
│   └── README.md
│
├── charts/agentgateway-multi-tenant/      ← Helm Umbrella Chart
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── values-prod.example.yaml
│   ├── templates/namespaces.yaml
│   └── charts/
│       ├── keycloak-idb-proxy/            ← 子 chart：Keycloak + IDB Proxy
│       ├── agentgateway/                  ← 子 chart：Gateway + 路由 + JWT
│       └── opa-opal-pep-proxy/            ← 子 chart：OPA + OPAL + PEP Proxy
│
├── scripts/                               ← 辅助脚本
│   ├── tutorial-curl-extended-tests.sh    ← 扩展功能联调脚本
│   ├── tutorial-step14-full-tests.sh      ← 第 14 步（14.2+）完整测试汇总
│   ├── tutorial-test-step15-dynamic-policy.sh ← 第 15 步动态策略测试汇总
│   ├── tutorial-enable-agentgateway-sidecar-opal.sh ← Sidecar OPA 启用脚本（Linux）
│   └── tutorial-test-sidecar-opal-dynamic.sh   ← 动态 Rego 验证脚本（Linux）
│
└── docs/                                  ← 补充文档
    ├── helm-umbrella-deploy.md            ← Helm 部署指南
    └── values-prod-example-fields-zh.md   ← 生产配置字段说明
```

## 部署方式

本项目提供三种部署方式，核心组件和思路一致：

| 方式 | 适用场景 | 入口 |
|---|---|---|
| **分步 Manifest（本教程）** | 学习理解、开发调试 | `manifests/tutorial/00~61-*.yaml` |
| **合并 Manifest** | 快速部署、CI/CD | `proxies/k8s/*.yaml` |
| **Helm Umbrella Chart** | 生产环境、参数化部署 | `charts/agentgateway-multi-tenant/` |

Helm 部署详见 [`docs/helm-umbrella-deploy.md`](docs/helm-umbrella-deploy.md)。

## 渐进式部署思路

本教程采用渐进式方式构建，每一步完成后都可以用 curl 验证：

| 阶段 | 部署内容 | 验证效果 |
|---|---|---|
| 第一部分 | httpbin + 业务路由 | curl → httpbin 200 OK（无任何认证） |
| 第二部分 | Keycloak + IDB Proxy（身份配置面） | 通过 `/proxy/idb/*` 完成 Keycloak 初始化 |
| 第三部分 | Keycloak OIDC 路由 + JWT 策略 | 无 token → 401，有 token → 200 |
| 第四部分 | OPA 策略引擎 + ext_authz | 正确角色 → 200，错误角色 → 403 |
| 第五·五部分 | 启用管理面 JWT + OPA 策略 | 管理面接口也需要 token 和正确角色 |
| 第五部分 | 端到端完整测试 | 10 个场景全面覆盖 |
| 第六部分 | 动态策略管理（PEP Proxy + OPAL） | 运行时推送策略，OPA 实时生效 |
| 第七部分 | 添加更多租户 | 多租户隔离验证 |
| 第八部分 | 调试与运维 | 日志、排障、token 管理 |
| 第九部分 | 清理资源 | 完整卸载 |
| 第十部分 | 扩展功能（SAML / Groups / DB Authorize / Audit） | 高级能力验证 |
| 第十一部分 | Sidecar OPA + OPAL 到 AgentGateway（可选） | 低延迟 ext_authz |
| 第十二部分 | OPA Rego 动态更新验证（可选） | 无重启更新 Rego 策略 |

**建议阅读顺序**：

1. 核心主线（必做）：第一部分 → 第二部分 → 第三部分 → 第四部分 → 第五·五部分 → 第五部分
2. 管理面加固（强烈建议）：第五·五部分（先于完整测试执行）
3. 常用排障（强烈建议）：第八部分《调试与运维》
4. 可选扩展：第六部分《动态策略管理》→ 第七部分《添加更多租户》→ 第十部分《扩展功能》
5. 高级选项：第十一部分《Sidecar OPA》→ 第十二部分《动态 Rego》
6. 清理资源：第九部分

> **核心主线成功标准**：
> - 无 token 访问业务 API → `401`
> - 有效 token 但角色不符 → `403`
> - 正确角色访问正确租户资源 → `200`

---

## 前提条件

> **清单组织说明**：本教程中的内联 YAML 已全部拆分到 `manifests/tutorial/*.yaml`，后续命令会直接引用这些文件。
>
> **模板渲染说明**：涉及 `${MASTER_ISSUER}`、`${ACME_ISSUER}` 等变量的策略文件使用 `*.template.yaml`，需通过 `envsubst` 渲染后再 `kubectl apply`。

### 路径 A：已有环境（推荐）

确保已完成：

1. ✅ 有一个 Kubernetes 集群（Kind 即可）
2. ✅ 安装了 AgentGateway 控制面
3. ✅ 创建了 agentgateway-proxy Gateway

### 路径 B：从零安装（可选，若你尚未准备环境）

如果还没完成：

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

# 3. 安装 AgentGateway 控制面
helm upgrade -i agentgateway oci://ghcr.io/kgateway-dev/charts/agentgateway \
  --namespace agentgateway-system \
  --version v2.2.0-main \
  --set controller.image.pullPolicy=IfNotPresent \
  --set controller.extraEnv.KGW_ENABLE_GATEWAY_API_EXPERIMENTAL_FEATURES=true

# 4. 创建 Gateway
kubectl apply -f manifests/tutorial/00-gateway.yaml
```

验证 Gateway 就绪：

```bash
kubectl get gateway -n agentgateway-system
# 应看到 agentgateway-proxy 状态为 Accepted/Programmed
```

---

# 第一部分：部署 httpbin 和业务路由（建立基线）

> **目标**：先搭建最基本的 Gateway → httpbin 通路，确认流量可以正常转发。此时没有任何认证和授权，所有请求都应该返回 200 OK。

## 第 1 步：部署 httpbin 模拟后端

httpbin 用于模拟业务 App Service。在后续步骤中，我们会逐步在路由上叠加 JWT 认证和 OPA 授权。

```bash
kubectl apply -f https://raw.githubusercontent.com/kgateway-dev/kgateway/refs/heads/main/examples/httpbin.yaml

kubectl -n httpbin rollout status deploy/httpbin
```

## 第 2 步：创建业务路由

创建两条 HTTPRoute，将业务 API 路由到 httpbin。所有 HTTPRoute 统一放在 `agentgateway-system` namespace，通过 ReferenceGrant 跨 namespace 引用 httpbin Service。

```bash
kubectl apply -f manifests/tutorial/10-baseline-routes.yaml
```

> **说明**：在此教程中，所有业务路由都指向 httpbin 作为模拟后端。由于 httpbin 不识别 `/api/v1/*` 路径，路由中使用了 `URLRewrite` 将请求路径重写到 httpbin 的 `/anything/*` 端点（该端点对任意路径和方法返回 200 并回显请求信息）。生产环境中应替换为实际的后端服务并移除 URL rewrite。

验证路由：

```bash
kubectl get httproute -n agentgateway-system
kubectl get referencegrant -n httpbin
```

## 第 3 步：验证基线 — 裸流量通路

启动 port-forward 并测试：

```bash
kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80 &
```

> **Windows 用户注意**：建议在单独的 PowerShell 标签页中执行 port-forward。如果使用 Git Bash (MINGW64) 且配置了 HTTP 代理，需要先 `unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy`，否则请求可能不会走本地 port-forward。

```bash
# 测试管理 API 路由 — 应该返回 200（无任何认证）
echo "=== Baseline Test 1: Admin API route → 200 (no auth) ==="
curl -s http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" | jq '{url, origin}'

# 测试租户 API 路由 — 应该返回 200（无任何认证）
echo "=== Baseline Test 2: Tenant API route → 200 (no auth) ==="
curl -s http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" | jq '{url, origin}'
```

预期：两个请求都返回 200，body 中包含 httpbin 回显的请求信息。

> httpbin 本身不认识 `/api/v1/admin/tenants` 路径，路由中配置了 URL Rewrite（`ReplacePrefixMatch`）将请求转发到 httpbin 的 `/anything/*` 端点。该端点接受任意路径和方法，回显所有请求头和 body，非常适合用来验证流量通路。

> ✅ **检查点**：如果这里返回 404 或连接失败，请检查 Gateway、HTTPRoute 和 httpbin 的部署状态后再继续。后续步骤会在这个基线之上逐层叠加安全策略。

---

# 第二部分：部署 Keycloak + IDB Proxy（身份配置面）

## 第 4 步：部署 Keycloak

### 4.1 创建 namespace 并部署

```bash
kubectl create namespace keycloak

kubectl -n keycloak apply -f https://raw.githubusercontent.com/solo-io/gloo-mesh-use-cases/main/policy-demo/oidc/keycloak.yaml

kubectl -n keycloak rollout status deploy/keycloak
```

### 4.2 获取 Keycloak 访问地址

Keycloak 将通过 Gateway 对外暴露（免认证专区路由将在第 8 步配置），但在 Keycloak 初始配置阶段，我们先使用 port-forward 直连：

**Kind 集群（初始配置阶段，使用 port-forward 直连）**：

```bash
kubectl port-forward -n keycloak svc/keycloak 9080:8080 &
export KEYCLOAK_URL=http://localhost:9080
echo "Keycloak URL: $KEYCLOAK_URL"
```

> **说明**：完成第 8 步的 Keycloak 免认证路由配置后，外部客户端将通过 Gateway（`http://<gateway-ip>/realms/...`）访问 Keycloak 的 OIDC 端点，而无需单独的 port-forward。

**LoadBalancer 正常工作时**：

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

> 如果返回空，检查 Keycloak 是否已就绪以及 URL 是否正确。
> 说明：后续主流程通过 IDB Proxy 完成配置，这个 `KEYCLOAK_TOKEN` 主要用于排障和手工检查。

---

## 第 5 步：部署 IDB Proxy（FastAPI 身份配置面）

为避免直接使用大量 `curl` 调 Keycloak Admin API 与 OPAL/OPA 接口，本教程将配置动作下沉到两个独立 FastAPI 服务：

1. `IDB Proxy`：负责 Keycloak 管理动作（realm/client/user/role/bootstrap）
2. `PEP Proxy`：负责策略数据管理（policy upsert/query/delete/simulate）；在本教程中它通过 OPAL 实时下发数据到 OPA，建议放在 OPA/OPAL 部分部署（健康检查依赖 OPA，实时推送依赖 OPAL）

> **Keycloak 24+ 兼容性说明**：Keycloak 24 及以上版本默认启用"声明式用户配置文件"（Declarative User Profile），未在 User Profile 中注册的自定义用户属性会在创建/更新用户时被静默忽略。IDB Proxy 的 bootstrap 流程已自动处理此问题 —— 在创建用户之前，会先通过 Keycloak Admin API 将 `group` 属性注册到目标 realm 的 User Profile 配置中，确保 `group` 属性能正确保存并映射到 JWT claims。

### 5.1 部署 IDB Proxy 服务

> 下方镜像请替换为你的 FastAPI 实现镜像。生产环境建议将 admin 凭据放入 Secret，这里为教程演示简化配置。

```bash
kubectl create namespace proxy-system --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f manifests/tutorial/20-idb-proxy-deployment.yaml
```

### 5.2 将 IDB Proxy 接入 Gateway

```bash
kubectl apply -f manifests/tutorial/21-idb-proxy-gateway-routes.yaml

kubectl get deploy,svc -n proxy-system
kubectl get httproute -n agentgateway-system
```

> 说明：本教程将 `idb-proxy-route` 作为身份配置面入口，默认不绑定 JWT/OPA，便于首轮 bootstrap。`pep-proxy` 将在 OPA 部分部署并接入 Gateway。生产环境应至少配合内网访问控制（NetworkPolicy / mTLS / IP allowlist），并在初始化完成后按需纳入鉴权策略（见第五·五部分）。

### 5.3 通过 IDB Proxy 初始化 master realm（超级管理员）

> 如果之前 `kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80` 已停止，请先重新启动。

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

预期返回包含如下字段：

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

## 第 6 步：通过 IDB Proxy 创建租户 Realm（以 acme 为例）

每个租户对应一个独立 Keycloak realm。这里通过 IDB Proxy 一次性完成 realm、client、claims mapper、角色、用户初始化。

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
      "group": "admin"
    },
    "users": [
      {
        "username": "bob",
        "password": "password",
        "email": "bob@acme.com",
        "group": "users",
        "roles": ["analyst"]
      },
      {
        "username": "charlie",
        "password": "password",
        "email": "charlie@acme.com",
        "group": "users",
        "roles": ["viewer"]
      }
    ]
  }')

echo "$TENANT_BOOTSTRAP" | jq .

export ACME_CLIENT_ID=$(echo "$TENANT_BOOTSTRAP" | jq -r '.client_id')
export ACME_CLIENT_SECRET=$(echo "$TENANT_BOOTSTRAP" | jq -r '.client_secret')
export ACME_CLIENT_UUID=$(echo "$TENANT_BOOTSTRAP" | jq -r '.client_uuid')
```

`TENANT_BOOTSTRAP` 建议至少返回：`tenant_id`、`client_id`、`client_secret`、`client_uuid`，便于后续 JWT 测试直接复用。

### 6.2 验证 Keycloak 配置

```bash
echo "========================================="
echo "Keycloak Admin Console: $KEYCLOAK_URL"
echo "  用户名: admin / 密码: admin"
echo "========================================="
echo ""
echo "已创建 Realm:"
echo "  - master (超级管理员)"
echo "  - ${TENANT_ID} (租户)"
echo ""
echo "用户总览:"
echo "  [master] superadmin / superadmin123  → role: super_admin"
echo "  [${TENANT_ID}] alice / password      → role: tenant_admin"
echo "  [${TENANT_ID}] bob / password        → role: analyst"
echo "  [${TENANT_ID}] charlie / password    → role: viewer"
```

---

# 第三部分：配置 JWT 认证（多 Realm 支持）

> **目标**：为业务路由叠加 JWT 认证层。完成后，无 token 的请求会被拦截返回 401，有效 token 的请求正常通过。Keycloak 的 OIDC 端点作为"免认证专区"不受影响。

## 第 7 步：获取 JWKS 信息

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

验证两个 JWKS 端点：

```bash
echo "--- Master JWKS ---"
curl -s $KEYCLOAK_URL$MASTER_JWKS_PATH | jq '.keys[0].kid'

echo "--- Acme JWKS ---"
curl -s $KEYCLOAK_URL$ACME_JWKS_PATH | jq '.keys[0].kid'
```

两者应返回不同的 key ID（每个 realm 有独立的密钥对）。

## 第 8 步：配置 Keycloak 免认证路由 & 多 Provider JWT 认证策略

### 8.1 创建 Keycloak 免认证路由（跨 namespace 引用）

Keycloak 部署在 `keycloak` namespace，而所有 HTTPRoute 统一放在 `agentgateway-system`（与 Policy 同 namespace）。需要创建 ReferenceGrant 允许跨 namespace 引用后端 Service：

```bash
kubectl apply -f manifests/tutorial/30-keycloak-oidc-route.yaml
```

> **安全说明**：此路由仅暴露 `/realms/*` 路径，Keycloak 的 Admin API（`/admin/*`）不在此路由中，因此不会被外部直接访问。Keycloak Admin API 的访问应通过内部 IDB Proxy 转发，或使用独立的 port-forward。

验证路由：

```bash
kubectl get httproute keycloak-oidc-route -n agentgateway-system
kubectl get referencegrant -n keycloak
```

### 8.2 创建多 Provider JWT 认证策略（绑定到业务路由）

> **关键变更**：JWT 策略的 `targetRefs` 指向具体的业务 HTTPRoute（`admin-api-route` 和 `tenant-api-route`），而不是 Gateway 整体。这样 Keycloak 的免认证路由不受影响。

```bash
envsubst < manifests/tutorial/31-jwt-auth-policy.template.yaml | kubectl apply -f -
```

> **说明**：每新增一个租户 realm，需要在此策略中添加对应的 provider。生产环境建议通过 K8s Operator 自动化管理。
>
> **注意事项**：`targetRefs` 不支持 `namespace` 字段（CRD 限制），因此 Policy 和 HTTPRoute 必须在同一个 namespace（`agentgateway-system`）。由于 JWT 策略绑定到 HTTPRoute，路由已在第 2 步创建完成，策略创建后会自动关联。

验证策略：

```bash
kubectl get AgentgatewayPolicy jwt-auth-policy -n agentgateway-system -o json | jq '.status'
```

## 第 9 步：验证 JWT 认证

> **此时的行为变化**：在第一部分，业务 API 没有任何认证，所有请求都返回 200。现在 JWT 策略已绑定到业务路由，未携带有效 token 的请求会被拦截返回 401。

### 9.1 验证 Keycloak 免认证路由

先确认 Keycloak 的 OIDC 端点可通过 Gateway 无 token 访问（免认证专区）：

```bash
# OIDC Discovery 端点 → 200（不需要任何 token）
echo "=== Keycloak OIDC Discovery (no token required) ==="
curl -i http://127.0.0.1:8080/realms/master/.well-known/openid-configuration \
  -H "host: www.example.com"

# JWKS 公钥端点 → 200（不需要任何 token）
echo "=== Keycloak JWKS (no token required) ==="
curl -i http://127.0.0.1:8080/realms/master/protocol/openid-connect/certs \
  -H "host: www.example.com"
```

预期：`HTTP/1.1 200 OK`。

> 以上两个请求走的是 `keycloak-oidc-route`，该路由未绑定任何 JWT/OPA 策略，因此无需 token 即可通过。

### 9.2 验证业务 API 已需要 token → 401

```bash
# 同样的请求，第一部分返回 200，现在应该返回 401
echo "=== No token → 401 (JWT enforced) ==="
curl -i http://127.0.0.1:8080/api/v1/admin/tenants -H "host: www.example.com"
```

预期：`HTTP/1.1 401 Unauthorized`

> 对比第一部分的基线测试：同样的请求从 200 变成了 401，说明 JWT 策略已生效。

### 9.3 获取各用户 token 并验证

> **通过 Gateway 获取 token**：如果 Keycloak 免认证路由已配置，也可以通过 Gateway 地址获取 token（将 `$KEYCLOAK_URL` 替换为 `http://127.0.0.1:8080`，并添加 host header）。这里继续使用直连地址以保持配置阶段的简洁性。

```bash
# 超级管理员 token（来自 master realm）
ACCESS_TOKEN_SUPERADMIN=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${MASTER_CLIENT_ID}" \
  -d "client_secret=${MASTER_CLIENT_SECRET}" \
  -d "username=superadmin" \
  -d "password=superadmin123" \
  | jq -r '.access_token')

# 租户管理员 token（来自 acme realm）
ACCESS_TOKEN_ALICE=$(curl -s -X POST \
  "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "username=alice" \
  -d "password=password" \
  | jq -r '.access_token')

# 普通用户 token（来自 acme realm）
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

> 可以用 https://jwt.io 解码 token，确认包含 `tenant_id`、`roles` 等 claims。

### 9.4 验证 token 中的 claims

```bash
# 解码 Alice 的 token（查看 payload 部分）
echo $ACCESS_TOKEN_ALICE | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{tenant_id, roles, preferred_username, group}'
```

预期输出类似：

```json
{
  "tenant_id": "acme",
  "roles": ["tenant_admin", "default-roles-acme"],
  "preferred_username": "alice",
  "group": "admin"
}
```

### 9.5 带 token 访问业务 API → 200

```bash
# 超级管理员访问管理 API → 200 ✅
echo "=== SuperAdmin with token → 200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'

# Alice 访问租户 API → 200 ✅
echo "=== Alice with token → 200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "test"}'

# Bob 也可以访问（JWT 层只验证 token 有效性，不做角色检查）→ 200 ✅
echo "=== Bob with token → 200 (JWT only checks token validity) ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：三个请求都返回 `HTTP/1.1 200 OK`（httpbin 回显请求内容）。

> ⚠️ **注意**：此时 Bob（普通用户）也能 POST 管理 API！这是因为 JWT 层只验证 token 签名的有效性，不做角色和权限检查。这正是第四部分 OPA 授权层要解决的问题。

> ✅ **检查点**：JWT 层已工作。无 token → 401，有效 token → 200（不区分角色）。接下来部署 OPA 来添加细粒度的角色权限控制。

---

# 第四部分：部署 OPA（多租户授权引擎）

> **目标**：为业务路由叠加 OPA 授权层。完成后，即使 token 有效，没有正确角色的请求也会被拦截返回 403。

## 第 10 步：编写多租户 OPA 策略

此策略实现了设计文档中的完整授权模型：超级管理员、租户管理员、普通用户三级 RBAC，加上动态策略数据驱动的业务鉴权。

```bash
kubectl create namespace opa

kubectl apply -f manifests/tutorial/40-opa-policy-configmap.yaml
```

**策略逻辑说明**：

```
请求进来
  ① AgentGateway JWT 层验签（第 8 步配置）
     → 通过后，Envoy 将 JWT payload 写入 metadataContext
  ② Envoy 将请求 + metadataContext 通过 gRPC 发给 OPA
  ③ OPA 提取 tenant_id、roles、group、username
  ④ OPA 从路径提取 path_tenant_id
  ⑤ 租户隔离检查：token.tenant_id == path.tenant_id
  ⑥ 按角色路由到对应规则：
     - super_admin → 可创建/查看租户
     - tenant_admin → 可管理本租户身份/策略
     - 普通用户 → 走动态策略匹配 → 回退到静态权限表
  ⑦ 返回 allow = true / false
```

---

## 第 11 步：部署 OPA 服务

```bash
kubectl apply -f manifests/tutorial/41-opa-deployment-service.yaml
```

验证 OPA 部署：

```bash
kubectl get pods -n opa -l app=opa
kubectl get svc -n opa opa
```

### 11.1 部署 OPAL（实时策略同步：PEP Proxy → OPAL → OPA）

> 本教程使用 `OPAL Server + OPAL Client` 做"数据变更发布与实时分发"。`PEP Proxy` 不再直接写 OPA Data API，而是调用 OPAL `/data/config`；再由 `OPAL Client` 将更新同步到 OPA。

```bash
kubectl apply -f proxies/k8s/opal-system.yaml

kubectl -n opal rollout status deploy/postgres
kubectl -n opal rollout status deploy/opal-server
kubectl -n opal rollout status deploy/opal-client
kubectl get pods -n opal
kubectl get svc -n opal opal-server
```

> **说明**：
> - `proxies/k8s/opal-system.yaml` 内置了演示用 token（`THIS_IS_A_DEV_SECRET_CHANGE_ME`），请在生产环境替换。
> - `opal-client` 以 standalone 模式工作，目标 OPA 为 `http://opa.opa.svc.cluster.local:8181/v1`。
> - `OPAL_DATA_CONFIG_SOURCES` 已指向 `pep-proxy` 的快照接口 `/opal/snapshots/tenant_policies`，用于客户端重连/重启后的数据补齐。

---

## 第 12 步：配置跨 namespace 引用和 OPA 外部授权策略

### 12.0 部署 PEP Proxy（放在 OPA + OPAL 部分，确保可直接 Ready）

`pep-proxy` 的 `/healthz` 会访问 OPA `/health`，在 OPAL 模式下还会检查 OPAL Server `/healthcheck`。因此把 `pep-proxy` 放在 OPA + OPAL 部分部署，避免依赖未就绪导致 `pep-proxy` readiness/liveness 失败。

```bash
kubectl apply -f manifests/tutorial/50-pep-proxy-deployment.yaml

kubectl -n proxy-system rollout status deploy/pep-proxy
```

### 12.0.1 将 PEP Proxy 接入 Gateway

```bash
kubectl apply -f manifests/tutorial/51-pep-proxy-gateway-routes.yaml
```

### 12.1 创建 ReferenceGrant

```bash
kubectl apply -f manifests/tutorial/52-opa-referencegrant.yaml
```

### 12.2 创建 OPA 外部授权策略（绑定到业务路由）

> **关键变更**：与 JWT 策略一致，OPA 授权策略也绑定到具体的业务 HTTPRoute，确保 Keycloak 免认证路由不受 OPA 鉴权影响。

```bash
kubectl apply -f manifests/tutorial/53-opa-ext-auth-policy.yaml
```

验证：

```bash
kubectl get AgentgatewayPolicy -n agentgateway-system
kubectl get ReferenceGrant -n opa
kubectl get ReferenceGrant -n keycloak
kubectl get ReferenceGrant -n proxy-system
kubectl get httproute -n agentgateway-system
```

应看到：

```
NAME                  AGE
jwt-auth-policy       Xm
opa-ext-auth-policy   Xs

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

> ⚠️ **重要**：此时业务面的 JWT + OPA 策略已启用，但管理面的 JWT + OPA 策略尚未应用。管理面接口（`/proxy/idb/*`、`/proxy/pep/*`）仍可无 token 访问。这是故意的 —— 等完成端到端验证后，在第五·五部分再启用管理面策略。

## 第 13 步：验证 OPA 授权

> **此时的行为变化**：第三部分中，Bob 拿着有效 token 可以 POST 管理 API（200）。现在 OPA 授权层已叠加，只有正确角色的用户才能通过。

```bash
# 重新获取 tokens（可能已过期）
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

### 13.1 超级管理员创建租户 → 200 ✅

```bash
echo "=== SuperAdmin POST /admin/tenants → 200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：`HTTP/1.1 200 OK`

### 13.2 普通用户访问管理 API → 403 ❌

```bash
echo "=== Bob POST /admin/tenants → 403 (OPA enforced) ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/admin/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "newcorp"}'
```

预期：`HTTP/1.1 403 Forbidden`

> 对比第三部分：同样的请求（Bob + 有效 token + POST /admin/tenants）从 200 变成了 403，说明 OPA 授权层已生效。

### 13.3 租户管理员管理本租户 → 200 ✅

```bash
echo "=== Alice POST /tenants/acme/roles → 200 ==="
curl -i -X POST http://127.0.0.1:8080/api/v1/tenants/acme/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "test"}'
```

预期：`HTTP/1.1 200 OK`（Alice 是 acme 的 tenant_admin）

### 13.4 跨租户访问 → 403 ❌

```bash
echo "=== Alice GET /tenants/other-corp/roles → 403 (cross-tenant) ==="
curl -i http://127.0.0.1:8080/api/v1/tenants/other-corp/roles \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

预期：`HTTP/1.1 403 Forbidden`（Alice 的 tenant_id=acme，不匹配 other-corp）

> ✅ **检查点**：双层安全模型完整工作。无 token → 401（JWT），有 token 但角色不对 → 403（OPA），token 有效且角色正确 → 200。

### 行为变化总结

| 请求场景 | 第一部分（无安全层） | 第三部分（仅 JWT） | 第四部分（JWT + OPA） |
|---|---|---|---|
| 无 token → /api/v1/admin/tenants | 200 ✅ | 401 ❌ | 401 ❌ |
| Bob (token) → POST /api/v1/admin/tenants | — | 200 ✅ | **403** ❌ |
| SuperAdmin (token) → POST /api/v1/admin/tenants | — | 200 ✅ | 200 ✅ |
| Alice (token) → /tenants/other-corp/roles | — | 200 ✅ | **403** ❌ |

---

# 第五·五部分：启用管理面 JWT + OPA 策略（初始化后）

> **目标**：为管理面接口（`/proxy/idb/*`、`/proxy/pep/*`）启用独立的 JWT 认证和 OPA 授权策略。此前这些接口无需 token 即可访问，是为了方便初始化（bootstrap）阶段操作。现在 Keycloak 已配置完成，可以安全地启用管理面策略。

> ⚠️ **重要前提**：确保第 5.3 步（master realm 初始化）和第 6 步（租户 realm 初始化）已完成。如果管理面策略在 bootstrap 之前启用，bootstrap 请求会被 JWT 策略拦截返回 `401`。

## 第 14.5 步：部署管理面策略

### 14.5.1 部署管理面 JWT 策略

管理面 JWT 策略是独立的 `AgentgatewayPolicy`，其 `targetRefs` 绑定到 `idb-proxy-route` 和 `pep-proxy-route`，与业务面的 `jwt-auth-policy` 分离。

```bash
envsubst < manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml | kubectl apply -f -
```

### 14.5.2 部署管理面 OPA 策略

管理面 OPA 策略绑定到同样的管理面路由，使用独立的 ext_authz 规则：

```bash
kubectl apply -f manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml
```

### 14.5.3 验证管理面策略已生效

```bash
# 查看所有策略
kubectl get AgentgatewayPolicy -n agentgateway-system
```

应看到 4 个策略：

```
NAME                       AGE
jwt-auth-policy            Xm    ← 业务面 JWT
opa-ext-auth-policy        Xm    ← 业务面 OPA
mgmt-jwt-auth-policy       Xs    ← 管理面 JWT
mgmt-opa-ext-auth-policy   Xs    ← 管理面 OPA
```

### 14.5.4 验证管理面接口已需要 token

```bash
# 管理面无 token → 401（之前返回 200）
echo "=== Mgmt API no token → 401 ==="
curl -i http://127.0.0.1:8080/proxy/idb/healthz \
  -H "host: www.example.com"
```

预期：`HTTP/1.1 401 Unauthorized`

```bash
# 超级管理员 token 访问管理面 → 200
echo "=== SuperAdmin → mgmt API → 200 ==="
curl -i http://127.0.0.1:8080/proxy/idb/healthz \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}"
```

预期：`HTTP/1.1 200 OK`

```bash
# 普通用户 token 访问管理面（非管理操作）→ 由 OPA 决定
echo "=== Bob → mgmt admin API → 403 ==="
curl -i -X POST http://127.0.0.1:8080/proxy/idb/tenants/acme/bootstrap \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_BOB}" \
  -H "Content-Type: application/json" \
  -d '{}'
```

预期：`HTTP/1.1 403 Forbidden`（Bob 没有管理权限）

> ✅ **检查点**：管理面和业务面都已受到 JWT + OPA 双层保护。至此整套安全体系完整。

---

# 第五部分：端到端完整验证

## 第 14 步：完整测试场景

确保 port-forward 仍在运行：

```bash
kubectl port-forward deployment/agentgateway-proxy -n agentgateway-system 8080:80 &
```

### 14.1 重新获取 tokens（防止过期）

```bash
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

### 14.2 ~ 14.12 一键执行完整测试并汇总结果

已将 14.2 开始的全部用例收敛到脚本：`scripts/tutorial-step14-full-tests.sh`。

```bash
bash scripts/tutorial-step14-full-tests.sh
```

脚本覆盖以下场景并输出 PASS/FAIL 汇总：

| # | 场景 | 用户 | 路径 | Method | 预期 |
|---|---|---|---|---|---|
| 0a | Keycloak OIDC Discovery | — | /realms/master/.well-known/... | GET | **200** |
| 0b | 通过 Gateway 获取 token | — | /realms/master/.../token | POST | **200** |
| 1 | 无 token 访问业务 API | — | /api/v1/admin/tenants | POST | **401** |
| 2 | 伪造 token | — | /api/v1/admin/tenants | POST | **401** |
| 3 | 超级管理员创建租户 | superadmin | /api/v1/admin/tenants | POST | **200** |
| 4 | 普通用户访问管理 API | bob | /api/v1/admin/tenants | POST | **403** |
| 5 | 租户管理员查看角色 | alice | /api/v1/tenants/acme/roles | GET | **200** |
| 6 | 租户管理员添加策略 | alice | /api/v1/tenants/acme/policies | POST | **200** |
| 7 | 普通用户管理策略 | bob | /api/v1/tenants/acme/policies | POST | **403** |
| 8 | 跨租户访问 | alice | /api/v1/tenants/other-corp/roles | GET | **403** |
| 9 | 业务 API GET | bob | /api/v1/tenants/acme/apps/.../orders | GET | **200** |
| 10 | 业务 API POST | bob | /api/v1/tenants/acme/apps/.../orders | POST | **403** |

> **排障提示**：如果测试 9 返回 403 而非 200，请检查 Bob 的 JWT 是否包含 `groups` claim：`echo "$ACCESS_TOKEN_BOB" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.groups'`。若缺失，请重新执行 bootstrap 并确认 IDB Proxy 已完成用户属性注册。

---

> **到这里（第五·五 + 第五部分结束）你已经完成核心主线。**
> 建议继续第六部分（动态策略管理）与第八部分（调试与运维）。

---

# 第六部分（可选扩展）：动态策略管理（通过 PEP Proxy + OPAL 实时更新）

## 第 15 步：通过 PEP Proxy 推送租户策略（由 OPAL 实时同步到 OPA）

从这一节开始，不再直连 OPA Data API。所有策略写入与读取都经由 `PEP Proxy (FastAPI)`，并通过 gateway 入口访问。
在本版本中，`PEP Proxy` 的写操作会触发 OPAL `/data/config`，再由 `OPAL Client` 实时写入 OPA 数据路径 `/tenant_policies/*`。
接口约定：`PUT /tenants/{tenant_id}/policies`（覆盖写入）、`GET /tenants/{tenant_id}/policies`（读取）、`DELETE /tenants/{tenant_id}/policies`（删除）、`POST /simulate`（透传 OPA 决策模拟）。

### 15.1 为 acme 租户推送策略数据

```bash
curl -s -X PUT http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
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

> **注意**：启用管理面策略后，策略操作需要携带有效 token（上例使用 Alice 的 tenant_admin token）。

### 15.2 验证策略数据已加载

```bash
curl -s http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" | jq '.[].name'

# （可选）观察 OPAL 实时同步链路日志
kubectl logs -n opal deploy/opal-server --tail=50
kubectl logs -n opal deploy/opal-client --tail=50
```

### 15.3 模拟 OPA 决策（通过 PEP Proxy）

```bash
curl -s -X POST http://127.0.0.1:8080/proxy/pep/simulate \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
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
                "groups": ["users"],
                "iss": "http://keycloak:8080/realms/acme"
              }
            }
          }
        }
      }
    }
  }' | jq .
```

预期：`result.allowed = true`

### 15.4 一键执行第六部分测试并汇总结果（推荐）

已补充完整测试脚本：`scripts/tutorial-test-step15-dynamic-policy.sh`。
该脚本会自动完成 `15.1 → 15.4`：策略写入、读取校验、simulate allow/deny、OPAL 快照校验，并输出 PASS/FAIL 汇总。

```bash
bash scripts/tutorial-test-step15-dynamic-policy.sh
```

---

# 第七部分（可选扩展）：添加更多租户

## 第 16 步：创建第二个租户（globex）

重复第 6 步的流程，使用不同 tenant_id，通过 IDB Proxy 快速完成初始化：

### 16.1 创建 globex 租户

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
      "group": "admin"
    }
  }')

echo "$GLOBEX_BOOTSTRAP" | jq .

export GLOBEX_CLIENT_ID=$(echo "$GLOBEX_BOOTSTRAP" | jq -r '.client_id')
export GLOBEX_CLIENT_SECRET=$(echo "$GLOBEX_BOOTSTRAP" | jq -r '.client_secret')
export GLOBEX_CLIENT_UUID=$(echo "$GLOBEX_BOOTSTRAP" | jq -r '.client_uuid')
export GLOBEX_ISSUER=$KEYCLOAK_URL/realms/${NEW_TENANT_ID}
export GLOBEX_JWKS_PATH=/realms/${NEW_TENANT_ID}/protocol/openid-connect/certs
```

> **注意**：如果已启用管理面策略（第五·五部分），此 bootstrap 请求需要携带超级管理员 token。如果尚未启用管理面策略，可以不带 token。

### 16.2 更新 JWT 策略（添加 globex realm provider）

```bash
envsubst < manifests/tutorial/61-jwt-auth-policy-add-globex.template.yaml | kubectl apply -f -

echo "Tenant '${NEW_TENANT_ID}' created and JWT policy updated."
```

> **验证租户隔离**：使用 globex 租户的 token 尝试访问 acme 的资源，应该返回 403。

---

# 第八部分：调试与运维（建议在第五部分后阅读）

## 查看 OPA 决策日志

```bash
kubectl logs -n opa -l app=opa -f
```

每次授权请求都会输出完整的 input 和 result。

授权通过时，OPA 会在上游请求头中注入 `x-authz-policy-version`（由 OPA 根据租户策略包版本生成），便于将业务日志与策略版本关联排查。

## 查看 OPAL 同步链路日志（实时更新排障）

```bash
kubectl logs -n opal deploy/opal-server -f
kubectl logs -n opal deploy/opal-client -f
```

排查重点：

- `opal-server` 是否收到 `/data/config` 更新事件
- `opal-client` 是否成功消费 `tenant_policies` topic
- `opal-client` 是否成功写入 `http://opa.opa.svc.cluster.local:8181/v1`

## 查看 OPA 中已加载的策略数据

```bash
# 通过 PEP Proxy 查看 acme 租户策略
curl -s http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" | jq .

# 查看完整策略包（包含 version / metadata / policies）
curl -s http://127.0.0.1:8080/proxy/pep/tenants/acme/policy-package \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" | jq .

# 通过 PEP Proxy 查看所有租户策略
curl -s http://127.0.0.1:8080/proxy/pep/tenants \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" | jq .
```

## 查看审计事件

```bash
# 查看 IDB Proxy 审计事件（身份面操作：tenant/group/saml 等）
curl -s "http://127.0.0.1:8080/proxy/idb/audit/events?limit=20" \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" | jq .

# 查看 PEP Proxy 审计事件（策略变更 / 回放）
curl -s "http://127.0.0.1:8080/proxy/pep/audit/events?limit=20" \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_SUPERADMIN}" | jq .
```

## 更新 OPA 策略（Rego 逻辑）

```bash
# 编辑策略
kubectl edit configmap opa-policy -n opa

# 重启 OPA Pod 使新策略生效
kubectl rollout restart deployment opa -n opa
```

> 注意：重启 OPA 会清除内存中的动态策略数据。若使用 OPAL，同步数据通常会在下一次策略发布或 OPAL Client 重连/重同步后恢复；生产环境建议为策略数据设计持久化来源（如数据库 + OPAL datasource）。
> 如需无重启更新 Rego，请参见第十二部分。

## 删除租户策略数据

```bash
curl -X DELETE http://127.0.0.1:8080/proxy/pep/tenants/acme/policies \
  -H "host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}"
```

## 查看 AgentGateway 策略状态

```bash
kubectl get AgentgatewayPolicy -n agentgateway-system
kubectl get AgentgatewayPolicy jwt-auth-policy -n agentgateway-system -o yaml
kubectl get AgentgatewayPolicy opa-ext-auth-policy -n agentgateway-system -o yaml
kubectl get AgentgatewayPolicy mgmt-jwt-auth-policy -n agentgateway-system -o yaml
kubectl get AgentgatewayPolicy mgmt-opa-ext-auth-policy -n agentgateway-system -o yaml
```

> 若启用了 JWT provider 自动注册，可在 `jwt-auth-policy` 中检查新增租户 realm 的 `issuer` 与 `jwksPath` 是否已自动写入。

## Token 过期处理

Keycloak 签发的 access_token 默认有效期较短（通常 5 分钟）。在实际应用中使用 refresh_token：

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

# 用 refresh_token 刷新
NEW_ACCESS_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${TENANT_ID}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=${ACME_CLIENT_ID}" \
  -d "client_secret=${ACME_CLIENT_SECRET}" \
  -d "refresh_token=${REFRESH_TOKEN}" | jq -r '.access_token')
```

## 常见问题与排查

1. **`AgentgatewayPolicy` 创建失败**
   - 检查 CRD 和 controller 是否已安装
2. **`HTTPRoute` 不生效**
   - 检查 Host 头是否与 `www.example.com` 一致
   - 检查 `Gateway` 状态是否 Programmed
3. **OPA ext_authz 不通**
   - 检查 `52-opa-referencegrant.yaml` 是否已应用
   - 检查 `opa` Service 的 gRPC 端口 `9191`
4. **管理面接口返回 401**
   - 说明 mgmt JWT 策略生效，需使用合法 token
   - 如果是 bootstrap 阶段，请先不要应用 `54/55` 管理面策略
5. **管理面接口返回 403**
   - 说明 JWT 已通过但 OPA 管理面规则拒绝（角色/租户不匹配）

---

# 第九部分：清理资源

```bash
# 删除所有 AgentgatewayPolicy
kubectl delete AgentgatewayPolicy opa-ext-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy jwt-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy mgmt-jwt-auth-policy -n agentgateway-system
kubectl delete AgentgatewayPolicy mgmt-opa-ext-auth-policy -n agentgateway-system

# 删除 OPA 与 OPAL
kubectl delete ns opa
kubectl delete ns opal

# 删除所有 HTTPRoute（都在 agentgateway-system）
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

# 第十部分（增补）：扩展功能验证（SAML / Groups / DB Authorize / Audit Replay）

## 10.1 新增接口能力（概览）

### IDB Proxy（`/proxy/idb/*`）

- Group CRUD：`/tenants/{tenant_id}/groups`
- 用户入组/移组：`/tenants/{tenant_id}/users/{username}/groups`
- SAML IdP 管理：`/tenants/{tenant_id}/saml/idps`
- SAML IdP 启停：`/tenants/{tenant_id}/saml/idps/{alias}/enabled`
- SAML 证书轮换：`/tenants/{tenant_id}/saml/idps/{alias}/certificates/rotate`
- SAML Mapper 管理：`/tenants/{tenant_id}/saml/idps/{alias}/mappers`
- JWT Provider 自动注册（可选）：`/tenants/{tenant_id}/jwt-providers/sync`
- 审计查询：`/audit/events`、`/audit/events/{event_id}`

### PEP Proxy（`/proxy/pep/*`）

- 策略包（带版本/元数据）查询：`/tenants/{tenant_id}/policy-package`
- 数据库资源授权检查：`/authorize/db`
- 审计查询/回放：`/audit/events`、`/audit/replay/{event_id}`
- 策略快照：`/opal/snapshots/tenant_policies`
- 模拟授权：`/simulate`

## 10.2 OPA/网关行为增补

- OPA ext_authz 决策路径为 `envoy/authz/decision`
- OPA 会向后端注入可信头（并移除同名来路头）：
  - `x-tenant-id`
  - `x-user`
  - `x-roles`
  - `x-groups`
  - `x-client-id`
  - `x-authz-policy-version`
- OPA 支持 `tenant_policies` 的"策略包格式"：
  - `version`
  - `metadata`
  - `policies[]`
- OPA 保持兼容旧格式（直接写 `policies[]` 数组）

## 10.3 启用 JWT Provider 自动注册（可选）

如果你希望"创建租户后自动把新 realm 注册到 `jwt-auth-policy`"，需要给 `idb-proxy` 额外 RBAC 权限：

```bash
kubectl apply -f manifests/tutorial/22-idb-proxy-jwt-sync-rbac.yaml
```

并在 `manifests/tutorial/20-idb-proxy-deployment.yaml` 中启用：

- `ENABLE_JWT_PROVIDER_AUTOREG=true`
- `KEYCLOAK_PUBLIC_ISSUER_BASE_URL`（建议设置为外部访问 Keycloak 的 base URL，例如 `http://www.example.com`）

> 若不启用自动注册，也可以使用 `POST /proxy/idb/tenants/{tenant_id}/jwt-providers/sync` 手动触发。

## 10.4 DB 授权检查

```bash
# 写入租户策略包（含 DB 资源授权规则）
curl -sS -X PUT "http://127.0.0.1:8080/proxy/pep/tenants/acme/policies" \
  -H "Host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
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

# 调用 DB 授权检查
curl -sS -X POST "http://127.0.0.1:8080/proxy/pep/authorize/db" \
  -H "Host: www.example.com" \
  -H "Authorization: Bearer ${ACCESS_TOKEN_ALICE}" \
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

## 10.5 扩展 curl 测试脚本

仓库提供了完整的扩展联调脚本：

```bash
# 前提：另一个终端已启动 port-forward
kubectl -n agentgateway-system port-forward deployment/agentgateway-proxy 8080:80

# 运行脚本（默认 tenant=acme, user=alice）
bash scripts/tutorial-curl-extended-tests.sh

# 自定义参数
GATEWAY_URL=http://127.0.0.1:8080 \
HOST_HEADER=www.example.com \
TENANT_ID=acme \
TENANT_USER=alice \
GROUP_NAME=finance \
SAML_ALIAS=corp-saml-demo \
CLEANUP_SAML=true \
bash scripts/tutorial-curl-extended-tests.sh
```

覆盖内容：Group 创建与用户入组、SAML IdP 管理、DB 授权检查、审计回放完整链路。

> Windows 用户说明：脚本为 Bash 脚本，建议使用 `Git Bash` / `WSL` 运行。

## 10.6 后端"仅信任网关来源流量"示例（可选加固）

```bash
kubectl apply -f manifests/tutorial/11-httpbin-networkpolicy.yaml
```

用途：限制示例后端 `httpbin` 仅接受来自 `agentgateway-system`（以及同 namespace）的流量，从网络层帮助你落实"后端只信任网关注入 metadata 头"的约束。

---

# 第十一部分（可选）：AgentGateway 挂载 OPA Sidecar + OPAL Client

> **目标**：将 OPA 和 OPAL Client 作为 sidecar 容器注入到 `agentgateway-proxy` Pod 中，使 ext_authz 走 localhost 而非跨 Namespace 网络调用，降低每请求延迟。

> **适用场景**：当你观测到 ext_authz 的跨 Namespace gRPC 延迟成为瓶颈，或需要 OPA 与 Gateway 同生同灭以提升可靠性时。

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
# 确认 Pod 中有 3 个容器
kubectl -n agentgateway-system get deploy agentgateway-proxy \
  -o jsonpath='{.spec.template.spec.containers[*].name}'

# 确认 sidecar OPA Service 存在
kubectl -n agentgateway-system get svc agentgateway-opa-sidecar

# 确认 OPAL 组件就绪
kubectl -n opal get deploy
```

---

# 第十二部分（可选）：OPA Rego 动态更新验证（无重启）

> **目标**：验证通过 OPAL 或 OPA REST API 动态推送 Rego 模块，无需重启 OPA Pod 即可改变授权逻辑。

> **前提**：已完成第十一部分（sidecar 模式），或已配置 OPAL Policy Updater。

```bash
bash scripts/tutorial-test-sidecar-opal-dynamic.sh
```

该脚本会验证完整闭环：

1. 基线请求：`200`（当前策略允许）
2. 动态下发 Rego 模块后：`403`（新策略拒绝）
3. 删除动态模块后恢复：`200`（回到基线）

期望输出：

```text
PASS sidecar+dynamic-rego: baseline=200, updated=403, restored=200
```

---

# Helm 部署参考

如果你走 umbrella chart 而非分步 manifest，请参考：

- [`docs/helm-umbrella-deploy.md`](docs/helm-umbrella-deploy.md) — Helm 部署完整指南
- [`charts/agentgateway-multi-tenant/values.yaml`](charts/agentgateway-multi-tenant/values.yaml) — 默认配置
- [`charts/agentgateway-multi-tenant/values-prod.example.yaml`](charts/agentgateway-multi-tenant/values-prod.example.yaml) — 生产配置示例
- [`docs/values-prod-example-fields-zh.md`](docs/values-prod-example-fields-zh.md) — 生产配置字段说明

核心思路一致，只是把教程中的分散 manifests 统一参数化为 Helm values。

---

# 相关文档

| 文档 | 说明 |
|---|---|
| [`agentgateway-multi-tenant-tutorial.md`](agentgateway-multi-tenant-tutorial.md) | 精简版教程（快速参考） |
| [`auth-chain-example.md`](auth-chain-example.md) | 认证链路完整示例（一个请求走完 JWT→OPA 全流程） |
| [`docs/helm-umbrella-deploy.md`](docs/helm-umbrella-deploy.md) | Helm Umbrella Chart 部署指南 |
| [`proxies/README.md`](proxies/README.md) | IDB / PEP Proxy 构建与 API 参考 |

