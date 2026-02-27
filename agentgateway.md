# AgentGateway 配置清单 �?OPA �?Keycloak 完整配置讲解

本文档从项目教程中提�?AgentGateway 需要为 **OPA（授权）** �?**Keycloak（认证）** 配置的所有内容，涵盖 Proxy 路由、ReferenceGrant、认证策略（AuthN）和外部授权策略（Ext AuthZ）�?

---

## 目录

1. [架构总览](#1-架构总览)
2. [AgentGateway �?Keycloak 配置的内容](#2-agentgateway-�?keycloak-配置的内�?
   - 2.1 [Keycloak OIDC Proxy 路由（免认证专区）](#21-keycloak-oidc-proxy-路由免认证专�?
   - 2.2 [JWT 认证策略（AuthN）](#22-jwt-认证策略authn)
   - 2.3 [JWT Provider 自动注册（可选扩展）](#23-jwt-provider-自动注册可选扩�?
3. [AgentGateway �?OPA 配置的内容](#3-agentgateway-�?opa-配置的内�?
   - 3.1 [OPA Proxy 路由与跨 Namespace 引用](#31-opa-proxy-路由与跨-namespace-引用)
   - 3.2 [OPA 外部授权策略（Ext AuthZ）](#32-opa-外部授权策略ext-authz)
4. [辅助 Proxy 路由（IDB Proxy + PEP Proxy）](#4-辅助-proxy-路由idb-proxy--pep-proxy)
   - 4.3 [管理面独立认证与授权策略](#43-管理面独立认证与授权策略)
5. [配置依赖关系与部署顺序](#5-配置依赖关系与部署顺�?
6. [Helm Chart 对应字段](#6-helm-chart-对应字段)
7. [生产环境注意事项](#7-生产环境注意事项)

---

## 1. 架构总览

AgentGateway 作为流量入口（基�?Envoy），对外暴露统一 HTTP 端口，流量通过路由规则分为两个区域�?

```
[Client]
   �?
   �?
[AgentGateway-Proxy] (Envoy, port 80)
   �?
   ├── 免认证专区（Keycloak OIDC 端点�?
   �?    不经�?JWT 认证 / OPA 授权
   �?    /realms/*  �? Keycloak
   �?
   ├── 业务鉴权区（所有业�?API�?
   �?     �?JWT 认证 (AuthN) �?jwt-auth-policy
   �?     �?外部授权 (AuthZ) �?opa-ext-auth-policy
   �?     �?两层都通过 �?路由到后端服�?
   �?
   └── 管理面鉴权区（IDB Proxy / PEP Proxy�?
          �?JWT 认证 (AuthN) �?独立策略（idb-proxy-jwt / pep-proxy-jwt�?
          �?外部授权 (AuthZ) �?独立 OPA 策略（idb-proxy-opa / pep-proxy-opa�?
             super_admin �?所有管理面路径
             tenant_admin �?�?/tenants/{own_tenant_id}/*
```

**核心设计决策**：JWT �?OPA 策略通过 `targetRefs` **精确绑定到业�?HTTPRoute**，而非 Gateway 整体。这�?Keycloak �?OIDC 路由可以免认证通行，避�?鸡生�?问题（客户端必须先无 token 调用 Keycloak 拿到 token，才能用 token 调业�?API）�?

---

## 2. AgentGateway �?Keycloak 配置的内�?

### 2.1 Keycloak OIDC Proxy 路由（免认证专区�?

#### 配置目的

�?Keycloak �?OIDC 端点通过 Gateway 对外暴露，使客户端可以通过统一入口�?
- 签发 Token：`/realms/{realm}/protocol/openid-connect/token`
- 获取 JWKS 公钥：`/realms/{realm}/protocol/openid-connect/certs`
- OIDC Discovery：`/realms/{realm}/.well-known/openid-configuration`

此路�?**不绑定任�?JWT/OPA 策略**，流量无需 token 即可通行�?

#### 配置清单

**配置 1：ReferenceGrant（跨 Namespace 引用授权�?*

> 文件：`manifests/tutorial/30-keycloak-oidc-route.yaml`（前半部分）

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-routes-to-keycloak
  namespace: keycloak               # 放在 Keycloak Service 所�?namespace
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: agentgateway-system   # 授权来源：HTTPRoute 所�?namespace
  to:
  - group: ""
    kind: Service
    name: keycloak                   # 授权目标：Keycloak Service
```

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `metadata.namespace` | 必须放在被引�?Service 所在的 namespace（`keycloak`），表示�?namespace 授权外部引用 |
| `spec.from.group` | 固定�?`gateway.networking.k8s.io`，表示来�?Gateway API 资源 |
| `spec.from.kind` | `HTTPRoute`，表示允�?HTTPRoute 类型的资源引用本 namespace �?Service |
| `spec.from.namespace` | HTTPRoute 所在的 namespace（`agentgateway-system`），限定只有�?namespace 的路由可以引�?|
| `spec.to.kind` | `Service`，授权引用的目标资源类型 |
| `spec.to.name` | `keycloak`，精确指定可以被引用�?Service 名称 |

**为什么需�?ReferenceGrant**：Keycloak 部署�?`keycloak` namespace，�?HTTPRoute 统一放在 `agentgateway-system`（与 AgentgatewayPolicy �?namespace）。Kubernetes Gateway API 默认不允许跨 namespace 引用后端 Service，必须通过 ReferenceGrant 显式授权�?

---

**配置 2：Keycloak OIDC HTTPRoute（免认证路由�?*

> 文件：`manifests/tutorial/30-keycloak-oidc-route.yaml`（后半部分）

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: keycloak-oidc-route
  namespace: agentgateway-system     # �?AgentgatewayPolicy �?namespace
spec:
  parentRefs:
  - name: agentgateway-proxy         # 绑定�?Gateway
    namespace: agentgateway-system
  hostnames:
  - "www.example.com"                # Host 头匹�?
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /realms                # 匹配所�?/realms/* 路径
    backendRefs:
    - name: keycloak                  # 后端 Service
      namespace: keycloak             # �?namespace 引用（需 ReferenceGrant�?
      port: 8080                      # Keycloak HTTP 端口
```

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `metadata.namespace` | 必须�?`agentgateway-system`，与后续 JWT/OPA 策略�?namespace（策略的 targetRefs 不支持跨 namespace�?|
| `spec.parentRefs` | 绑定�?Gateway 资源 `agentgateway-proxy`，声明该路由属于哪个网关 |
| `spec.hostnames` | 请求�?`Host` 头必须命中此列表，否则路由不生效 |
| `spec.rules[].matches[].path.type` | `PathPrefix` 表示前缀匹配 |
| `spec.rules[].matches[].path.value` | `/realms` 覆盖所�?realm �?OIDC 端点 |
| `spec.rules[].backendRefs` | 将流量转发到 Keycloak Service（跨 namespace，需配合 ReferenceGrant�?|

**安全说明**：此路由仅暴�?`/realms/*` 路径。Keycloak �?Admin API（`/admin/*`）不在此路由中，不会被外部直接访问�?

---

### 2.2 JWT 认证策略（AuthN�?

#### 配置目的

为业务路由叠�?JWT 认证层。AgentGateway 使用 Keycloak �?JWKS 公钥验证请求�?Bearer Token 的签名、有效期�?issuer。无 token �?token 无效的请求返�?`401 Unauthorized`�?

#### 配置清单

**配置 3：JWT 认证策略（AgentgatewayPolicy�?*

> 文件：`manifests/tutorial/31-jwt-auth-policy.template.yaml`

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: jwt-auth-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  # 精确绑定到业务路由，不绑定到 Gateway 整体
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: admin-api-route              # 管理�?API 路由
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: tenant-api-route             # 租户业务 API 路由
  traffic:
    jwtAuthentication:
      mode: Strict                     # 严格模式：所有请求必须携带有�?JWT
      providers:
      # Provider 1：master realm（超级管理员�?
      - issuer: "${MASTER_ISSUER}"     # 例如 http://www.example.com/realms/master
        jwks:
          remote:
            jwksPath: "${MASTER_JWKS_PATH}"   # /realms/master/protocol/openid-connect/certs
            cacheDuration: "5m"               # JWKS 公钥缓存时间
            backendRef:
              group: ""
              kind: Service
              name: keycloak                  # 从哪�?Service 拉取 JWKS
              namespace: keycloak
              port: 8080
      # Provider 2：acme 租户 realm
      - issuer: "${ACME_ISSUER}"       # 例如 http://www.example.com/realms/acme
        jwks:
          remote:
            jwksPath: "${ACME_JWKS_PATH}"     # /realms/acme/protocol/openid-connect/certs
            cacheDuration: "5m"
            backendRef:
              group: ""
              kind: Service
              name: keycloak
              namespace: keycloak
              port: 8080
```

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `apiVersion` | `agentgateway.dev/v1alpha1`，AgentGateway 自定�?CRD |
| `kind` | `AgentgatewayPolicy`，AgentGateway 的策略资�?|
| `metadata.name` | 策略名称，后�?IDB Proxy JWT 自动注册会用此名称定位策�?|
| `metadata.namespace` | 必须�?targetRefs 中的 HTTPRoute 在同一 namespace（CRD 限制：targetRefs 不支�?namespace 字段�?|
| `spec.targetRefs` | 策略绑定目标。精确指向业�?HTTPRoute，不包含 Keycloak 免认证路�?|
| `spec.targetRefs[].group` | `gateway.networking.k8s.io`，指�?Gateway API 资源 |
| `spec.targetRefs[].kind` | `HTTPRoute`，绑定到路由级别 |
| `spec.targetRefs[].name` | 具体�?HTTPRoute 名称（`admin-api-route` / `tenant-api-route`�?|
| `spec.traffic.jwtAuthentication.mode` | `Strict`：所有匹配请求必须携带有�?JWT；无 token �?401 |
| `spec.traffic.jwtAuthentication.providers` | JWT Provider 列表，支持多 issuer（多 Keycloak realm�?|
| `providers[].issuer` | JWT `iss` claim 的期望值�?*必须�?Keycloak 实际签发�?token �?`iss` 完全一�?*（包含协议、域名、路径） |
| `providers[].jwks.remote.jwksPath` | AgentGateway �?Keycloak 拉取 JWKS 公钥�?HTTP 路径 |
| `providers[].jwks.remote.cacheDuration` | 公钥缓存时间（`5m` = 5 分钟），减少频繁请求 Keycloak |
| `providers[].jwks.remote.backendRef` | JWKS 拉取的后�?Service 引用，指�?Keycloak（跨 namespace，复用前面的 ReferenceGrant�?|

**关键说明**�?

1. **为什么绑定到 HTTPRoute 而非 Gateway�?* 如果绑定�?Gateway 整体，Keycloak �?token 端点也会要求 JWT，但客户端还没有 token，形成死循环�?
2. **�?Provider 支持**：每新增一个租�?realm，需�?`providers` 中添加对应条目。`issuer` �?`jwksPath` 都是 realm 特定的�?
3. **模板变量**：文件使�?`${MASTER_ISSUER}` 等变量，部署时需要通过 `envsubst` 渲染�?
4. **issuer 值关�?*：issuer 必须�?token �?`iss` claim 完全一致。如�?Keycloak 通过 Gateway 暴露，issuer 应为 `http://www.example.com/realms/master`；如果直�?Keycloak，则�?`http://localhost:9080/realms/master`�?

---

### 2.3 JWT Provider 自动注册（可选扩展）

#### 配置目的

创建新租户时，自动将�?realm �?JWT Provider（issuer + jwksPath）注册到 `jwt-auth-policy`，无需手动编辑策略 YAML�?

#### 配置清单

**配置 4：RBAC 授权（允�?IDB Proxy 更新 AgentgatewayPolicy�?*

> 文件：`manifests/tutorial/22-idb-proxy-jwt-sync-rbac.yaml`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: idb-proxy-agentgateway-policy-editor
rules:
  - apiGroups: ["agentgateway.dev"]
    resources: ["agentgatewaypolicies"]
    verbs: ["get", "list", "watch", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: idb-proxy-agentgateway-policy-editor
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: idb-proxy-agentgateway-policy-editor
subjects:
  - kind: ServiceAccount
    name: idb-proxy
    namespace: proxy-system
```

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `ClusterRole.rules.apiGroups` | `agentgateway.dev`，AgentGateway CRD �?API group |
| `ClusterRole.rules.resources` | `agentgatewaypolicies`，允许操�?AgentgatewayPolicy 资源 |
| `ClusterRole.rules.verbs` | `get/list/watch/update/patch`，读取和更新权限 |
| `ClusterRoleBinding.subjects` | 绑定�?`idb-proxy` ServiceAccount（`proxy-system` namespace�?|

**配置 5：IDB Proxy 环境变量（JWT 自动注册相关�?*

> 文件：`manifests/tutorial/20-idb-proxy-deployment.yaml`（相关部分）

```yaml
env:
- name: ENABLE_JWT_PROVIDER_AUTOREG
  value: "true"                         # 启用自动注册
- name: KEYCLOAK_PUBLIC_ISSUER_BASE_URL
  value: "http://www.example.com"       # 外部访问 Keycloak �?base URL
- name: AGENTGATEWAY_POLICY_NAMESPACE
  value: agentgateway-system            # jwt-auth-policy 所�?namespace
- name: AGENTGATEWAY_POLICY_NAME
  value: jwt-auth-policy                # 要更新的策略名称
- name: AGENTGATEWAY_KEYCLOAK_SERVICE_NAME
  value: keycloak                       # JWT backendRef 中的 Service 名称
- name: AGENTGATEWAY_KEYCLOAK_SERVICE_NAMESPACE
  value: keycloak                       # JWT backendRef 中的 Service namespace
- name: AGENTGATEWAY_KEYCLOAK_SERVICE_PORT
  value: "8080"                         # JWT backendRef 中的 Service 端口
```

**字段讲解**�?

| 环境变量 | 说明 |
|---|---|
| `ENABLE_JWT_PROVIDER_AUTOREG` | `true` 启用自动注册。创建新租户 realm 后，IDB Proxy 自动�?jwt-auth-policy 添加�?provider |
| `KEYCLOAK_PUBLIC_ISSUER_BASE_URL` | 拼接 issuer 的基地址。最�?issuer = `${baseUrl}/realms/{tenant_id}` |
| `AGENTGATEWAY_POLICY_NAMESPACE` | 目标 AgentgatewayPolicy �?namespace |
| `AGENTGATEWAY_POLICY_NAME` | 目标 AgentgatewayPolicy 的名�?|
| `AGENTGATEWAY_KEYCLOAK_SERVICE_*` | 写入�?JWT provider �?`backendRef` 信息 |

---

## 3. AgentGateway �?OPA 配置的内�?

### 3.1 OPA Proxy 路由与跨 Namespace 引用

#### 配置目的

AgentGateway 需要通过 gRPC 调用 OPA �?`envoy_ext_authz_grpc` 插件进行授权决策。由�?OPA 部署�?`opa` namespace，�?AgentgatewayPolicy �?`agentgateway-system`，需�?ReferenceGrant 授权�?namespace �?Service 引用�?

#### 配置清单

**配置 6：ReferenceGrant（允�?AgentgatewayPolicy 引用 OPA Service�?*

> 文件：`manifests/tutorial/52-opa-referencegrant.yaml`

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-agentgateway-to-opa
  namespace: opa                        # 放在 OPA Service 所�?namespace
spec:
  from:
  - group: agentgateway.dev             # 注意：这里是 agentgateway.dev，不�?gateway.networking.k8s.io
    kind: AgentgatewayPolicy            # 来源类型�?AgentgatewayPolicy（不�?HTTPRoute�?
    namespace: agentgateway-system      # 策略所�?namespace
  to:
  - group: ""
    kind: Service
    name: opa                           # 授权引用 OPA Service
```

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `metadata.namespace` | `opa`，放在被引用 Service 所�?namespace |
| `spec.from.group` | **`agentgateway.dev`**（不�?`gateway.networking.k8s.io`）。因为引用来源是 `AgentgatewayPolicy`，它属于 `agentgateway.dev` API group |
| `spec.from.kind` | **`AgentgatewayPolicy`**（不�?`HTTPRoute`）。ext_authz �?backendRef �?AgentgatewayPolicy 中定�?|
| `spec.from.namespace` | `agentgateway-system`，策略所�?namespace |
| `spec.to.name` | `opa`，精确指定可被引用的 Service 名称 |

**�?Keycloak ReferenceGrant 的关键区�?*�?
- Keycloak �?ReferenceGrant 授权 **HTTPRoute** 引用 Keycloak Service（用于路由流量）
- OPA �?ReferenceGrant 授权 **AgentgatewayPolicy** 引用 OPA Service（用�?ext_authz 后端�?
- 因此 `from.group` �?`from.kind` 不同

---

### 3.2 OPA 外部授权策略（Ext AuthZ�?

#### 配置目的

为业务路由叠�?OPA 授权层。即�?JWT 验证通过（token 有效），OPA 会进一步检查用户的角色、tenant_id、请求路径等，做细粒�?RBAC。未通过授权的请求返�?`403 Forbidden`�?

#### 配置清单

**配置 7：OPA 外部授权策略（AgentgatewayPolicy�?*

> 文件：`manifests/tutorial/53-opa-ext-auth-policy.yaml`

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: opa-ext-auth-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  # �?JWT 策略一致，精确绑定到业务路�?
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: admin-api-route
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: tenant-api-route
  traffic:
    extAuth:
      backendRef:
        name: opa                      # OPA Service 名称
        namespace: opa                 # OPA Service namespace（跨 namespace，需 ReferenceGrant�?
        port: 9191                     # OPA gRPC ext_authz 端口
      grpc: {}                         # 使用 gRPC 协议（Envoy ext_authz gRPC�?
```

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `metadata.name` | `opa-ext-auth-policy`，与 jwt-auth-policy 分开，职责清�?|
| `metadata.namespace` | `agentgateway-system`，与业务路由�?namespace |
| `spec.targetRefs` | �?JWT 策略绑定相同的业务路由。两个策略叠加在同一路由上，�?JWT 认证�?OPA 授权 |
| `spec.traffic.extAuth` | 外部授权配置�?|
| `spec.traffic.extAuth.backendRef.name` | `opa`，OPA Kubernetes Service 名称 |
| `spec.traffic.extAuth.backendRef.namespace` | `opa`，跨 namespace 引用（需配合配置 6 �?ReferenceGrant�?|
| `spec.traffic.extAuth.backendRef.port` | `9191`，OPA `envoy_ext_authz_grpc` 插件监听�?gRPC 端口 |
| `spec.traffic.extAuth.grpc` | `{}`，声明使�?gRPC 协议�?OPA 通信（Envoy ext_authz 标准协议�?|

**OPA 侧的对应配置**（说�?AgentGateway �?OPA 如何对接）：

OPA 使用 `openpolicyagent/opa:0.70.0-envoy` 镜像，启动参数中配置�?ext_authz 插件�?

```bash
opa run --server \
  --addr=0.0.0.0:8181 \
  --set=plugins.envoy_ext_authz_grpc.addr=:9191 \                    # gRPC 监听端口（与 AgentGateway �?port: 9191 对应�?
  --set=plugins.envoy_ext_authz_grpc.path=envoy/authz/decision \     # 决策路径
  --set=decision_logs.console=true \
  /policy/policy.rego
```

| OPA 参数 | 对应关系 |
|---|---|
| `plugins.envoy_ext_authz_grpc.addr=:9191` | 对应 AgentGateway extAuth.backendRef.port = 9191 |
| `plugins.envoy_ext_authz_grpc.path=envoy/authz/decision` | OPA 策略决策入口路径（AgentGateway 侧无需配置，由 gRPC 协议自动协商�?|

**OPA Service 定义**（`manifests/tutorial/41-opa-deployment-service.yaml`）：

```yaml
apiVersion: v1
kind: Service
metadata:
  name: opa
  namespace: opa
spec:
  ports:
  # gRPC 端口：供 AgentGateway ext_authz 使用
  - port: 9191
    targetPort: 9191
    protocol: TCP
    name: grpc
    appProtocol: kubernetes.io/h2c    # 声明 HTTP/2 cleartext（gRPC 必须�?
  # HTTP 端口：供 OPAL Client / PEP Proxy 访问 OPA Data API
  - port: 8181
    targetPort: 8181
    protocol: TCP
    name: http
  selector:
    app: opa
```

| 字段 | 说明 |
|---|---|
| `port: 9191` + `appProtocol: kubernetes.io/h2c` | gRPC 端口，`h2c` 声明确保 AgentGateway 使用 HTTP/2 连接 |
| `port: 8181` | OPA REST API 端口，供 OPAL Client 同步数据、PEP Proxy 查询策略使用 |

---

## 4. 辅助 Proxy 路由（IDB Proxy + PEP Proxy�?

AgentGateway 还需要为 IDB Proxy �?PEP Proxy 配置路由入口�?

### 4.1 IDB Proxy 路由

> 文件：`manifests/tutorial/21-idb-proxy-gateway-routes.yaml`

**ReferenceGrant**�?

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-routes-to-idb-proxy
  namespace: proxy-system
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: agentgateway-system
  to:
  - group: ""
    kind: Service
    name: idb-proxy
```

**HTTPRoute**�?

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: idb-proxy-route
  namespace: agentgateway-system
spec:
  parentRefs:
  - name: agentgateway-proxy
    namespace: agentgateway-system
  hostnames:
  - "www.example.com"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /proxy/idb             # IDB Proxy 入口路径
    filters:
    - type: URLRewrite
      urlRewrite:
        path:
          type: ReplacePrefixMatch
          replacePrefixMatch: /       # �?/proxy/idb/xxx 重写�?/xxx
    backendRefs:
    - name: idb-proxy
      namespace: proxy-system
      port: 8080
```

| 字段 | 说明 |
|---|---|
| `path.value: /proxy/idb` | 客户端通过 `/proxy/idb/*` 访问 IDB Proxy |
| `URLRewrite.replacePrefixMatch: /` | 去掉 `/proxy/idb` 前缀，IDB Proxy 收到的路径为 `/*` |

**注意**：IDB Proxy 路由在首�?bootstrap 时可以不绑定策略。完成初始化后，应部署独立的 JWT + OPA 策略（见 4.3 节）保护管理面路由�?

### 4.2 PEP Proxy 路由

> 文件：`manifests/tutorial/51-pep-proxy-gateway-routes.yaml`

结构�?IDB Proxy 路由完全一致，路径前缀�?`/proxy/pep`�?

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: pep-proxy-route
  namespace: agentgateway-system
spec:
  parentRefs:
  - name: agentgateway-proxy
    namespace: agentgateway-system
  hostnames:
  - "www.example.com"
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /proxy/pep
    filters:
    - type: URLRewrite
      urlRewrite:
        path:
          type: ReplacePrefixMatch
          replacePrefixMatch: /
    backendRefs:
    - name: pep-proxy
      namespace: proxy-system
      port: 8080
```

### 4.3 管理面独立认证与授权策略

#### 配置目的

�?`idb-proxy-route` �?`pep-proxy-route` 提供 **独立�?JWT + OPA 策略**，不复用业务路由�?`jwt-auth-policy` / `opa-ext-auth-policy`。这样管理面可以独立控制认证和授权逻辑，OPA 按管理面路径分级�?
- `super_admin`（master realm）→ 可访问所有管理面路径
- `tenant_admin`（租�?realm）→ 仅可访问 `/tenants/{own_tenant_id}/*`
- 普通用�?�?403

#### 配置清单

**配置 8：IDB Proxy 独立 JWT + OPA 策略**

> 文件：`manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml`

```yaml
# JWT 认证策略
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: idb-proxy-jwt-auth-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: idb-proxy-route              # 仅绑定到 idb-proxy-route
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
      - issuer: "${MASTER_ISSUER}"
        jwks:
          remote:
            jwksPath: "${MASTER_JWKS_PATH}"
            cacheDuration: "5m"
            backendRef:
              group: ""
              kind: Service
              name: keycloak
              namespace: keycloak
              port: 8080
      - issuer: "${ACME_ISSUER}"
        jwks:
          remote:
            jwksPath: "${ACME_JWKS_PATH}"
            cacheDuration: "5m"
            backendRef:
              group: ""
              kind: Service
              name: keycloak
              namespace: keycloak
              port: 8080
---
# OPA 外部授权策略
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: idb-proxy-opa-ext-auth-policy
  namespace: agentgateway-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: idb-proxy-route
  traffic:
    extAuth:
      backendRef:
        name: opa
        namespace: opa
        port: 9191
      grpc: {}
```

**配置 9：PEP Proxy 独立 JWT + OPA 策略**

> 文件：`manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml`

结构�?IDB Proxy 完全一致，`targetRefs` 指向 `pep-proxy-route`�?
- `pep-proxy-jwt-auth-policy`：JWT 认证
- `pep-proxy-opa-ext-auth-policy`：OPA 授权

**字段讲解**�?

| 字段 | 说明 |
|---|---|
| `name: idb-proxy-jwt-auth-policy` | 独立策略名称，与业务 `jwt-auth-policy` 分开 |
| `targetRefs[].name: idb-proxy-route` | 仅绑定到 IDB Proxy 路由，不影响业务路由 |
| `providers` | 与业务策略使用相同的 Keycloak Provider 列表。JWT 自动注册会同步更新此策略 |

**关键设计**�?
1. **独立 targetRefs**：管理面策略仅绑�?`idb-proxy-route` / `pep-proxy-route`，不干扰业务路由策略
2. **OPA 规则分级**：OPA �?`_is_mgmt_proxy_path` 规则识别管理面路径（`/bootstrap`、`/tenants`、`/healthz`、`/audit` 等），按角色分级放行
3. **JWT 自动同步**：IDB Proxy 创建新租户时，会同时更新 `jwt-auth-policy`、`idb-proxy-jwt-auth-policy`、`pep-proxy-jwt-auth-policy` 三个策略
4. **ReferenceGrant 复用**：OPA �?ReferenceGrant（`allow-agentgateway-to-opa`）已授权 `AgentgatewayPolicy` 引用 OPA Service，新策略无需额外 ReferenceGrant

**配置 10：JWT 自动注册扩展环境变量**

IDB Proxy 新增两个环境变量，用于将�?JWT Provider 同步到管理面策略�?

```yaml
env:
- name: AGENTGATEWAY_IDB_POLICY_NAME
  value: "idb-proxy-jwt-auth-policy"      # IDB Proxy JWT 策略名称
- name: AGENTGATEWAY_PEP_POLICY_NAME
  value: "pep-proxy-jwt-auth-policy"      # PEP Proxy JWT 策略名称
```

| 环境变量 | 说明 |
|---|---|
| `AGENTGATEWAY_IDB_POLICY_NAME` | 创建租户时同步更新的 IDB Proxy JWT 策略名称 |
| `AGENTGATEWAY_PEP_POLICY_NAME` | 创建租户时同步更新的 PEP Proxy JWT 策略名称 |

> 如果管理面策略尚未部署（例如首轮 bootstrap 阶段），自动注册会跳过这两个策略（`status: skipped`），不影响主流程�?

---

## 5. 配置依赖关系与部署顺�?

```
                     ┌─ 00-gateway.yaml
                     �?    Gateway 资源
                     �?
              ┌─ 10-baseline-routes.yaml
              �?    业务 HTTPRoute（admin-api-route + tenant-api-route�?
              �?    + ReferenceGrant（→ httpbin�?
              �?
        ┌─ 21-idb-proxy-gateway-routes.yaml
        �?    IDB Proxy 路由 + ReferenceGrant
        �?
   ┌─ 30-keycloak-oidc-route.yaml
   �?    Keycloak OIDC 免认证路�?+ ReferenceGrant
   �?
┌─ 31-jwt-auth-policy.template.yaml
�?    业务 JWT 认证策略 �?绑定�?admin-api-route + tenant-api-route
�?    依赖：Keycloak JWKS 端点可访�?
�?
┌─ 51-pep-proxy-gateway-routes.yaml
�?    PEP Proxy 路由 + ReferenceGrant
�?
┌─ 52-opa-referencegrant.yaml
�?    OPA ReferenceGrant
�?
┌─ 53-opa-ext-auth-policy.yaml
�?    业务 OPA 外部授权策略 �?绑定�?admin-api-route + tenant-api-route
�?    依赖：OPA Service 可访�?
�?
┌─ 54-mgmt-jwt-auth-policy.template.yaml
�?    IDB Proxy 独立 JWT + OPA 策略 �?绑定�?idb-proxy-route
�?
└─ 55-mgmt-opa-ext-auth-policy.yaml
      PEP Proxy 独立 JWT + OPA 策略 �?绑定�?pep-proxy-route
```

**关键依赖**�?
1. Gateway 必须先创建，所�?HTTPRoute �?`parentRefs` 引用�?
2. 业务 HTTPRoute 必须�?JWT/OPA 策略之前创建（策略的 `targetRefs` 引用路由名称�?
3. JWT 策略依赖 Keycloak Service 可达（用于拉�?JWKS 公钥�?
4. OPA ext_authz 策略依赖 OPA Service 可达
5. ReferenceGrant 必须在对应的路由/策略之前创建
6. 管理面策略（54/55）依赖对应的 Proxy 路由�?1/51）和 OPA ReferenceGrant�?2）已创建

---

## 6. Helm Chart 对应字段

�?Helm 部署模式下，以上配置通过 `values.yaml` 统一管理�?

### Keycloak 相关

```yaml
agentgateway:
  routes:
    keycloakOidc:
      enabled: true                     # 是否创建 Keycloak OIDC 路由
      pathPrefix: "/realms"             # 路由前缀
      service:
        name: "keycloak"                # Keycloak Service 名称
        port: 8080                      # Keycloak Service 端口
    jwtPolicy:
      enabled: true                     # 是否创建 JWT 认证策略
      mode: Strict                      # 认证模式
      providers:                        # JWT Provider 列表
        - issuer: "http://www.example.com/realms/master"
          jwksPath: "/realms/master/protocol/openid-connect/certs"
        - issuer: "http://www.example.com/realms/acme"
          jwksPath: "/realms/acme/protocol/openid-connect/certs"
```

### OPA 相关

OPA ext_authz 策略�?Helm 模板中使用以下固定值（来自 `opa-opal-pep-proxy` �?chart）：

| 参数 | �?| 来源 |
|---|---|---|
| `backendRef.name` | `opa` | OPA Service 名称 |
| `backendRef.namespace` | 来自 `global.namespaces.opa` | 全局 namespace 配置 |
| `backendRef.port` | `9191` | OPA gRPC ext_authz 端口 |
| `grpc: {}` | 固定 | gRPC 协议 |

### 全局配置

```yaml
global:
  hostnames:
    - "www.example.com"                 # 所有路由的 Host 匹配
  namespaces:
    agentgateway: "agentgateway-system" # Gateway/HTTPRoute/Policy namespace
    keycloak: "keycloak"                # Keycloak namespace
    proxy: "proxy-system"              # IDB Proxy / PEP Proxy namespace
    opa: "opa"                         # OPA namespace
  gateway:
    name: "agentgateway-proxy"          # Gateway 名称
    gatewayClassName: "agentgateway"    # GatewayClass 名称
  businessRoutes:
    admin:
      name: "admin-api-route"           # 管理员路由名称（�?JWT/OPA 策略引用�?
      pathPrefix: "/api/v1/admin"
    tenant:
      name: "tenant-api-route"          # 租户路由名称（被 JWT/OPA 策略引用�?
      pathPrefix: "/api/v1/tenants"
```

---

## 7. 生产环境注意事项

### issuer 匹配

`jwtPolicy.providers[].issuer` 必须�?token �?`iss` claim **完全一�?*（包含协议、域名、端口、路径）。这是最常见的生产踩坑点�?

### Namespace 统一原则

所�?HTTPRoute �?AgentgatewayPolicy 必须在同一�?namespace（`agentgateway-system`），因为 `targetRefs` 不支持跨 namespace 引用。后�?Service 通过 ReferenceGrant �?namespace 引用�?

### 策略叠加顺序

在同一业务路由上同时绑�?`jwt-auth-policy` �?`opa-ext-auth-policy` 时，执行顺序为：
1. **JWT 认证** �?验签、检查有效期 �?失败返回 `401`
2. **OPA 授权** �?检查角色、租户隔�?�?失败返回 `403`
3. 两层都通过 �?路由到后端服�?

### OPA 可信头注�?

OPA 通过 ext_authz 决策结果向后端注入以下可信请求头（并移除客户端同名头，防止伪造）�?

| 注入�?| 来源 | 说明 |
|---|---|---|
| `x-tenant-id` | JWT `tenant_id` claim | 租户标识 |
| `x-user` | JWT `preferred_username` claim | 用户�?|
| `x-roles` | JWT `roles` claim | 角色列表 |
| `x-groups` | JWT `groups` claim | 用户组（数组�?|
| `x-client-id` | JWT `azp` claim | 客户�?ID |
| `x-authz-policy-version` | OPA 动态策略数�?| 策略版本（便于审计关联） |

### 安全加固建议

- IDB Proxy �?PEP Proxy 路由已配置独立的 JWT + OPA 策略（`idb-proxy-jwt-auth-policy` / `pep-proxy-jwt-auth-policy` + 对应 OPA 策略），管理面鉴权独立于业务路由
- 可选部�?`NetworkPolicy`（`manifests/tutorial/11-httpbin-networkpolicy.yaml`）限制后端仅接受来自 `agentgateway-system` 的流�?
- 生产环境不应使用 `start-dev` 启动 Keycloak

---

## 配置总结（速查表）

| # | 资源类型 | 名称 | 用�?| 关联组件 |
|---|---|---|---|---|
| 1 | ReferenceGrant | `allow-routes-to-keycloak` | 授权 HTTPRoute 引用 Keycloak Service | Keycloak |
| 2 | HTTPRoute | `keycloak-oidc-route` | Keycloak OIDC 免认证路�?| Keycloak |
| 3 | AgentgatewayPolicy | `jwt-auth-policy` | JWT �?Provider 认证策略 | Keycloak |
| 4 | ClusterRole + Binding | `idb-proxy-agentgateway-policy-editor` | JWT 自动注册 RBAC（可选） | Keycloak |
| 5 | ReferenceGrant | `allow-agentgateway-to-opa` | 授权 AgentgatewayPolicy 引用 OPA Service | OPA |
| 6 | AgentgatewayPolicy | `opa-ext-auth-policy` | OPA gRPC 外部授权策略 | OPA |
| 7 | ReferenceGrant | `allow-routes-to-idb-proxy` | 授权 HTTPRoute 引用 IDB Proxy Service | IDB Proxy |
| 8 | HTTPRoute | `idb-proxy-route` | IDB Proxy 路由（`/proxy/idb/*`�?| IDB Proxy |
| 9 | ReferenceGrant | `allow-routes-to-pep-proxy` | 授权 HTTPRoute 引用 PEP Proxy Service | PEP Proxy |
| 10 | HTTPRoute | `pep-proxy-route` | PEP Proxy 路由（`/proxy/pep/*`�?| PEP Proxy |
| 11 | AgentgatewayPolicy | `idb-proxy-jwt-auth-policy` | IDB Proxy 独立 JWT 认证策略 | Keycloak |
| 12 | AgentgatewayPolicy | `idb-proxy-opa-ext-auth-policy` | IDB Proxy 独立 OPA 授权策略 | OPA |
| 13 | AgentgatewayPolicy | `pep-proxy-jwt-auth-policy` | PEP Proxy 独立 JWT 认证策略 | Keycloak |
| 14 | AgentgatewayPolicy | `pep-proxy-opa-ext-auth-policy` | PEP Proxy 独立 OPA 授权策略 | OPA |
