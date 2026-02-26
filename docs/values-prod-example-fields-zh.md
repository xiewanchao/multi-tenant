# `values-prod.example.yaml` 字段级说明（中文版）

适用文件：`charts/agentgateway-multi-tenant/values-prod.example.yaml`

说明：

- 本文只解释示例文件里已经出现的字段（逐项说明）。
- 未在示例文件出现但在默认 `values.yaml` 中存在的字段，会继续沿用默认值。
- 字段路径使用 `.` 表示层级，例如 `global.gateway.name`。

## 一、`global`（全局配置）

### `global.hostnames`

- 类型：`[]string`
- 作用：所有 `HTTPRoute` 的主机名匹配列表（`Host` 头必须命中）。
- 示例：`["api.company.example"]`
- 生产建议：
  - 使用实际对外域名。
  - 若有多域名入口，可配置多个。

### `global.clusterDomain`

- 类型：`string`
- 作用：集群内部 DNS 后缀，用于拼接 `*.svc.<clusterDomain>` 服务地址。
- 默认常见值：`cluster.local`
- 生产建议：
  - 大多数集群保持 `cluster.local`。
  - 如果你的集群改过 DNS domain，需要同步修改。

### `global.namespaces.agentgateway`

- 类型：`string`
- 作用：AgentGateway 相关资源命名空间（`Gateway`、`HTTPRoute`、`AgentgatewayPolicy`）。
- 生产建议：
  - 通常由平台团队管理，建议固定且稳定。

### `global.namespaces.keycloak`

- 类型：`string`
- 作用：Keycloak 资源命名空间。
- 示例值：`identity-system`
- 生产建议：
  - 身份组件与业务组件分离，便于权限隔离。

### `global.namespaces.proxy`

- 类型：`string`
- 作用：`idb-proxy`、`pep-proxy` 所在命名空间。
- 生产建议：
  - 与 `agentgateway` 分开，减少组件耦合。

### `global.namespaces.opa`

- 类型：`string`
- 作用：OPA 所在命名空间。
- 生产建议：
  - 与 `opal` 分开可提升职责清晰度（可选）。

### `global.namespaces.opal`

- 类型：`string`
- 作用：OPAL server/client（及可选 postgres）所在命名空间。

### `global.gateway.name`

- 类型：`string`
- 作用：要创建/绑定的 `Gateway` 名称。多个子 chart 的路由会引用该名称。
- 注意：
  - 改名后要保证各子 chart 都通过全局值引用同一个网关。

### `global.gateway.create`

- 类型：`bool`
- 作用：是否由该 chart 创建 `Gateway` 资源。
- `true`：chart 创建网关
- `false`：使用集群中已有网关（只创建路由与策略）
- 生产建议：
  - 若网关由平台层统一维护，可设为 `false`。

### `global.gateway.gatewayClassName`

- 类型：`string`
- 作用：`Gateway.spec.gatewayClassName`。
- 示例值：`agentgateway`
- 注意：
  - 必须与集群已安装的 GatewayClass 一致。

### `global.gateway.listener.name`

- 类型：`string`
- 作用：Gateway listener 名称。
- 示例值：`http`

### `global.gateway.listener.port`

- 类型：`int`
- 作用：Gateway listener 监听端口。
- 示例值：`80`
- 生产建议：
  - 如前面有 LB/Ingress，可仍使用 80；如直出 TLS，可按需配合后续 TLS listener 扩展。

### `global.gateway.listener.protocol`

- 类型：`string`
- 作用：Gateway listener 协议。
- 示例值：`HTTP`
- 生产建议：
  - 生产通常还会扩展 `HTTPS` listener（当前示例未展开）。

## 二、`global.businessRoutes`（业务路由）

这两组配置决定：

- 管理员 API 路由（`admin`）
- 租户业务/API 路由（`tenant`）

示例文件里只覆盖了后端 service 和 rewrite 开关；路由名与路径前缀会沿用默认值（来自 `values.yaml`）。

### `global.businessRoutes.admin.backendService.name`

- 类型：`string`
- 作用：管理员 API 的后端 Kubernetes Service 名称。
- 示例值：`tenant-admin-api`

### `global.businessRoutes.admin.backendService.namespace`

- 类型：`string`
- 作用：管理员 API 后端 Service 所在命名空间。
- 示例值：`business-api`

### `global.businessRoutes.admin.backendService.port`

- 类型：`int`
- 作用：管理员 API 后端 Service 端口。
- 示例值：`8080`

### `global.businessRoutes.admin.urlRewrite.enabled`

- 类型：`bool`
- 作用：是否对管理员 API 路由启用 URL 重写。
- 示例值：`false`
- 说明：
  - Demo 对接 `httpbin` 时通常 `true`。
  - 生产接真实业务服务时通常 `false`。

### `global.businessRoutes.admin.createReferenceGrant`

- 类型：`bool`
- 作用：当后端 Service 跨 namespace 时，是否自动创建 `ReferenceGrant`。
- 示例值：`true`
- 生产建议：
  - 跨 namespace 路由时通常要开。
  - 如果你已由平台统一创建授权对象，也可关掉避免重复。

### `global.businessRoutes.tenant.backendService.name`

- 类型：`string`
- 作用：租户业务/API 后端 Service 名称。
- 示例值：`tenant-app-api`

### `global.businessRoutes.tenant.backendService.namespace`

- 类型：`string`
- 作用：租户业务/API 后端 Service 所在命名空间。
- 示例值：`business-api`

### `global.businessRoutes.tenant.backendService.port`

- 类型：`int`
- 作用：租户业务/API 后端 Service 端口。
- 示例值：`8080`

### `global.businessRoutes.tenant.urlRewrite.enabled`

- 类型：`bool`
- 作用：是否对租户 API 路由启用 URL 重写。
- 示例值：`false`

### `global.businessRoutes.tenant.createReferenceGrant`

- 类型：`bool`
- 作用：是否自动创建指向租户后端 Service 的 `ReferenceGrant`。
- 示例值：`true`

## 三、`keycloak-idb-proxy`（身份域）

### `keycloak-idb-proxy.keycloak.enabled`

- 类型：`bool`
- 作用：是否在该 chart 内部署 Keycloak。
- 生产常见场景：
  - `true`：同 chart 部署（简化）
  - `false`：接入外部/已有 Keycloak（需确保路由与 JWT provider 指向正确）

### `keycloak-idb-proxy.keycloak.image.repository`

- 类型：`string`
- 作用：Keycloak 镜像仓库。

### `keycloak-idb-proxy.keycloak.image.tag`

- 类型：`string`
- 作用：Keycloak 镜像版本标签。
- 生产建议：
  - 固定版本，不用 `latest`。

### `keycloak-idb-proxy.keycloak.image.pullPolicy`

- 类型：`string`
- 作用：镜像拉取策略。
- 常用值：`IfNotPresent`

### `keycloak-idb-proxy.keycloak.replicaCount`

- 类型：`int`
- 作用：Keycloak 副本数。
- 示例值：`2`
- 生产建议：
  - 多副本前应先规划数据库与会话策略。

### `keycloak-idb-proxy.keycloak.service.port`

- 类型：`int`
- 作用：Keycloak Service 暴露端口。
- 示例值：`8080`

### `keycloak-idb-proxy.keycloak.command`

- 类型：`[]string`
- 作用：Keycloak 启动参数（模板中作为 `kc.sh` 的 args）。
- 当前示例：
  - `start-dev`
  - `--http-port=8080`
  - `--proxy-headers=xforwarded`
  - `--hostname-strict=false`
- 生产建议：
  - 不建议长期使用 `start-dev`
  - 建议改为生产启动方式并接外部数据库、持久化

### `keycloak-idb-proxy.keycloak.admin.createSecret`

- 类型：`bool`
- 作用：是否由 chart 创建 Keycloak 管理员账号 secret。
- 示例值：`false`
- 生产建议：
  - 生产通常 `false`，使用外部 secret（例如 External Secrets/Vault/手工预创建）。

### `keycloak-idb-proxy.keycloak.admin.existingSecret`

- 类型：`string`
- 作用：已有 Keycloak 管理员 secret 名称。
- 要求 secret key：
  - `KEYCLOAK_ADMIN_USER`
  - `KEYCLOAK_ADMIN_PASSWORD`

### `keycloak-idb-proxy.keycloak.resources.requests.cpu`

- 类型：`string`
- 作用：Keycloak CPU 请求值。
- 示例值：`500m`

### `keycloak-idb-proxy.keycloak.resources.requests.memory`

- 类型：`string`
- 作用：Keycloak 内存请求值。
- 示例值：`1Gi`

### `keycloak-idb-proxy.keycloak.resources.limits.cpu`

- 类型：`string`
- 作用：Keycloak CPU 限制值。
- 示例值：`2`

### `keycloak-idb-proxy.keycloak.resources.limits.memory`

- 类型：`string`
- 作用：Keycloak 内存限制值。
- 示例值：`2Gi`

### `keycloak-idb-proxy.idbProxy.replicaCount`

- 类型：`int`
- 作用：`idb-proxy` 副本数。

### `keycloak-idb-proxy.idbProxy.image.repository`

- 类型：`string`
- 作用：`idb-proxy` 镜像仓库。
- 生产建议：
  - 使用你自己的镜像仓库与固定 tag。

### `keycloak-idb-proxy.idbProxy.image.tag`

- 类型：`string`
- 作用：`idb-proxy` 镜像版本。

### `keycloak-idb-proxy.idbProxy.image.pullPolicy`

- 类型：`string`
- 作用：`idb-proxy` 镜像拉取策略。

### `keycloak-idb-proxy.idbProxy.keycloak.url`

- 类型：`string`
- 作用：`idb-proxy` 访问 Keycloak 的基础 URL。
- 示例值：`http://keycloak.identity-system.svc.cluster.local:8080`
- 注意：
  - 若 `keycloak.enabled=false`，这里必须指向外部或已有 Keycloak。

### `keycloak-idb-proxy.idbProxy.keycloak.verifyTls`

- 类型：`bool`
- 作用：`idb-proxy` 调 Keycloak 时是否校验 TLS。
- 示例值：`false`
- 生产建议：
  - 如走 HTTPS，建议开启并确保 CA 配置完整。

### `keycloak-idb-proxy.idbProxy.keycloak.adminSecretName`

- 类型：`string`
- 作用：`idb-proxy` 使用的 Keycloak 管理员凭据 secret 名称（位于 `proxy` namespace）。
- 说明：
  - 通常与 Keycloak 管理员密钥保持同名，但命名空间不同。

### `keycloak-idb-proxy.idbProxy.resources.requests.cpu`

- 类型：`string`
- 作用：`idb-proxy` CPU 请求。

### `keycloak-idb-proxy.idbProxy.resources.requests.memory`

- 类型：`string`
- 作用：`idb-proxy` 内存请求。

### `keycloak-idb-proxy.idbProxy.resources.limits.cpu`

- 类型：`string`
- 作用：`idb-proxy` CPU 限制。

### `keycloak-idb-proxy.idbProxy.resources.limits.memory`

- 类型：`string`
- 作用：`idb-proxy` 内存限制。

## 四、`agentgateway`（入口网关与认证策略）

### `agentgateway.upstream.installCRDs`

- 类型：`bool`
- 作用：是否在子 chart 内安装官方 `agentgateway-crds` 依赖。
- 示例值：`false`
- 生产建议：
  - 通常由平台层统一安装，保持 `false`。

### `agentgateway.upstream.installController`

- 类型：`bool`
- 作用：是否在子 chart 内安装官方 `agentgateway` controller 依赖。
- 示例值：`false`
- 生产建议：
  - 平台层统一运维时保持 `false`。
  - 测试/一体化环境可开启。

### `agentgateway.routes.keycloakOidc.pathPrefix`

- 类型：`string`
- 作用：Keycloak OIDC 无认证专区路由前缀。
- 示例值：`/realms`
- 说明：
  - 用于 token、JWKS、OIDC discovery 等端点透传。

### `agentgateway.routes.keycloakOidc.service.name`

- 类型：`string`
- 作用：OIDC 路由后端 Service 名称（通常是 Keycloak Service）。

### `agentgateway.routes.keycloakOidc.service.port`

- 类型：`int`
- 作用：OIDC 路由后端 Service 端口。

### `agentgateway.routes.jwtPolicy.enabled`

- 类型：`bool`
- 作用：是否创建 `jwt-auth-policy`（绑定到业务路由）。
- 示例值：`true`

### `agentgateway.routes.jwtPolicy.providers`

- 类型：`[]object`
- 作用：JWT provider 列表，支持多 issuer（多 realm）。
- 每项字段：
  - `issuer`：JWT `iss` 值，必须与 Keycloak 实际签发一致
  - `jwksPath`：该 issuer 对应的 JWKS 路径（通过 Keycloak Service 获取）
- 生产建议：
  - `issuer` 必须和客户端实际拿到 token 的 `iss` 完全一致（包含域名/路径）。

### `agentgateway.routes.jwtPolicy.providers[].issuer`

- 示例值：
  - `http://api.company.example/realms/master`
  - `http://api.company.example/realms/acme`
- 作用：允许哪些 realm 签发的 token 通过 JWT 认证。

### `agentgateway.routes.jwtPolicy.providers[].jwksPath`

- 示例值：
  - `/realms/master/protocol/openid-connect/certs`
  - `/realms/acme/protocol/openid-connect/certs`
- 作用：AgentGateway 拉取 JWKS 公钥的路径。

## 五、`opa-opal-pep-proxy`（授权域）

### A. `opa-opal-pep-proxy.opa`

#### `opa-opal-pep-proxy.opa.replicaCount`

- 类型：`int`
- 作用：OPA 副本数。
- 示例值：`2`

#### `opa-opal-pep-proxy.opa.image.repository`

- 类型：`string`
- 作用：OPA 镜像仓库。

#### `opa-opal-pep-proxy.opa.image.tag`

- 类型：`string`
- 作用：OPA 镜像标签（示例使用 `envoy` 变体，支持 ext_authz）。

#### `opa-opal-pep-proxy.opa.image.pullPolicy`

- 类型：`string`
- 作用：OPA 镜像拉取策略。

### B. `opa-opal-pep-proxy.opal`

#### `opa-opal-pep-proxy.opal.enabled`

- 类型：`bool`
- 作用：是否部署 OPAL server/client。
- 示例值：`true`
- 说明：
  - 关闭后 `pep-proxy` 仍可按你的实现切换为直写 OPA 模式（取决于应用配置）。

#### `opa-opal-pep-proxy.opal.auth.existingSecret`

- 类型：`string`
- 作用：已有 OPAL 鉴权 secret 名称（位于 `opal` namespace）。
- 常用 key：
  - `OPAL_AUTH_MASTER_TOKEN`
  - `OPAL_CLIENT_TOKEN`

#### `opa-opal-pep-proxy.opal.auth.createSecret`

- 类型：`bool`
- 作用：是否由 chart 创建 OPAL 鉴权 secret。
- 示例值：`false`
- 生产建议：
  - 使用外部 secret，避免明文 token 进入 values。

#### `opa-opal-pep-proxy.opal.postgres.enabled`

- 类型：`bool`
- 作用：是否部署内置 Postgres（供 OPAL 使用）。
- 示例值：`false`
- 生产建议：
  - 生产应使用外部数据库，示例已按此设置。

#### `opa-opal-pep-proxy.opal.postgres.host`

- 类型：`string`
- 作用：外部 Postgres 主机名（或 Service DNS）。
- 示例值：`postgresql-ha-rw.database.svc.cluster.local`

#### `opa-opal-pep-proxy.opal.postgres.port`

- 类型：`int`
- 作用：外部 Postgres 端口。
- 示例值：`5432`

#### `opa-opal-pep-proxy.opal.postgres.database`

- 类型：`string`
- 作用：OPAL 使用的数据库名。
- 示例值：`opal`

#### `opa-opal-pep-proxy.opal.postgres.username`

- 类型：`string`
- 作用：OPAL 连接数据库用户名。

#### `opa-opal-pep-proxy.opal.postgres.password`

- 类型：`string`
- 作用：OPAL 连接数据库密码。
- 生产建议：
  - 不建议明文写在 values 中，建议改为 secret 注入（当前示例仅占位）。

#### `opa-opal-pep-proxy.opal.server.replicaCount`

- 类型：`int`
- 作用：OPAL Server 副本数。

#### `opa-opal-pep-proxy.opal.server.image.repository`

- 类型：`string`
- 作用：OPAL Server 镜像仓库。

#### `opa-opal-pep-proxy.opal.server.image.tag`

- 类型：`string`
- 作用：OPAL Server 镜像标签。
- 生产建议：
  - 固定版本，不用 `latest`。

#### `opa-opal-pep-proxy.opal.server.image.pullPolicy`

- 类型：`string`
- 作用：OPAL Server 镜像拉取策略。

#### `opa-opal-pep-proxy.opal.server.policyRepoUrl`

- 类型：`string`
- 作用：OPAL policy repo 地址（用于策略代码/规则同步）。
- 示例值：`https://github.com/permitio/opal-example-policy-repo.git`
- 生产建议：
  - 替换为你自己的策略仓库。

#### `opa-opal-pep-proxy.opal.client.replicaCount`

- 类型：`int`
- 作用：OPAL Client 副本数。

#### `opa-opal-pep-proxy.opal.client.image.repository`

- 类型：`string`
- 作用：OPAL Client 镜像仓库。

#### `opa-opal-pep-proxy.opal.client.image.tag`

- 类型：`string`
- 作用：OPAL Client 镜像标签。

#### `opa-opal-pep-proxy.opal.client.image.pullPolicy`

- 类型：`string`
- 作用：OPAL Client 镜像拉取策略。

### C. `opa-opal-pep-proxy.pepProxy`

#### `opa-opal-pep-proxy.pepProxy.replicaCount`

- 类型：`int`
- 作用：`pep-proxy` 副本数。

#### `opa-opal-pep-proxy.pepProxy.image.repository`

- 类型：`string`
- 作用：`pep-proxy` 镜像仓库。

#### `opa-opal-pep-proxy.pepProxy.image.tag`

- 类型：`string`
- 作用：`pep-proxy` 镜像版本标签。

#### `opa-opal-pep-proxy.pepProxy.image.pullPolicy`

- 类型：`string`
- 作用：`pep-proxy` 镜像拉取策略。

#### `opa-opal-pep-proxy.pepProxy.opal.masterToken.existingSecret`

- 类型：`string`
- 作用：`pep-proxy` 使用的 OPAL master token secret 名称（位于 `proxy` namespace）。
- 示例值：`pep-proxy-opal-auth`

#### `opa-opal-pep-proxy.pepProxy.opal.masterToken.createSecret`

- 类型：`bool`
- 作用：是否由 chart 创建 `pep-proxy` 的 OPAL token secret。
- 示例值：`false`
- 生产建议：
  - 保持 `false`，使用外部 secret。

#### `opa-opal-pep-proxy.pepProxy.resources.requests.cpu`

- 类型：`string`
- 作用：`pep-proxy` CPU 请求。

#### `opa-opal-pep-proxy.pepProxy.resources.requests.memory`

- 类型：`string`
- 作用：`pep-proxy` 内存请求。

#### `opa-opal-pep-proxy.pepProxy.resources.limits.cpu`

- 类型：`string`
- 作用：`pep-proxy` CPU 限制。

#### `opa-opal-pep-proxy.pepProxy.resources.limits.memory`

- 类型：`string`
- 作用：`pep-proxy` 内存限制。

## 六、示例文件未覆盖但仍然有效的默认字段（提醒）

这些字段在示例文件中没写，但会从 `charts/agentgateway-multi-tenant/values.yaml` 继承：

1. `global.createNamespaces`
   - 默认 `true`
   - 控制是否自动创建 `agentgateway/keycloak/proxy/opa/opal` namespace
2. `global.businessRoutes.admin.name`
   - 默认 `admin-api-route`
3. `global.businessRoutes.admin.pathPrefix`
   - 默认 `/api/v1/admin`
4. `global.businessRoutes.tenant.name`
   - 默认 `tenant-api-route`
5. `global.businessRoutes.tenant.pathPrefix`
   - 默认 `/api/v1/tenants`
6. `agentgateway.routes.jwtPolicy.mode`
   - 默认 `Strict`
7. `opa-opal-pep-proxy` 下部分端口、路由、超时字段
   - 例如 `pepProxy.service.port`、`pepProxy.route.pathPrefix` 等

## 七、生产落地最容易踩坑的 5 个字段

1. `global.hostnames`
- 必须与实际请求 `Host` 一致，否则路由不匹配。

2. `agentgateway.routes.jwtPolicy.providers[].issuer`
- 必须与 token 中 `iss` 完全一致（路径也要一致）。

3. `global.businessRoutes.*.backendService.*`
- Service 名称/namespace/端口错一个就会路由失败。

4. `keycloak-idb-proxy.idbProxy.keycloak.url`
- 如果 Keycloak 不在同 chart 或 namespace 改了，这里最容易忘改。

5. `opa-opal-pep-proxy.opal.auth.*` 与 `pepProxy.opal.masterToken.*`
- OPAL server/client 与 pep-proxy token 不一致会导致策略同步失败。

## 八、增补字段（SAML / Groups / 审计 / JWT 自动注册）

以下字段已在新版 `values-prod.example.yaml` 中加入，用于支持新增能力。

### A. `keycloak-idb-proxy.idbProxy.audit.*`

#### `keycloak-idb-proxy.idbProxy.audit.maxEvents`

- 类型：`int`
- 作用：`idb-proxy` 内存中保留的审计事件条数上限（超出后滚动丢弃旧事件）
- 示例值：`5000`

#### `keycloak-idb-proxy.idbProxy.audit.logPath`

- 类型：`string`
- 作用：可选，若设置则将审计事件按 JSONL 追加写入容器文件
- 示例值：`""`（空表示不落盘）
- 生产建议：
  - 如需合规审计，建议挂载持久卷或对接日志采集系统

### B. `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.*`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.enabled`

- 类型：`bool`
- 作用：创建租户后，`idb-proxy` 是否自动将新 realm 的 `issuer/jwksPath` 注册到 `AgentgatewayPolicy(jwt-auth-policy)`
- 示例值：`true`
- 注意：
  - 需要配合 RBAC（见 `...rbac.*`）才能真正生效

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.keycloakPublicIssuerBaseUrl`

- 类型：`string`
- 作用：生成 JWT provider `issuer` 时使用的对外 Keycloak 基础地址（例如通过 Gateway 暴露的域名）
- 示例值：`https://api.company.example`
- 说明：
  - 最终 `issuer` 会拼成 `${baseUrl}/realms/{tenant_id}`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.agentgatewayPolicyNamespace`

- 类型：`string`
- 作用：目标 `AgentgatewayPolicy` 所在 namespace
- 示例值：`agentgateway-system`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.agentgatewayPolicyName`

- 类型：`string`
- 作用：要自动更新的 JWT 策略名称（通常是 `jwt-auth-policy`）
- 示例值：`jwt-auth-policy`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.keycloakService.name`

- 类型：`string`
- 作用：写入 JWT provider `backendRef` 时使用的 Keycloak Service 名称
- 示例值：`keycloak`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.keycloakService.namespace`

- 类型：`string`
- 作用：写入 JWT provider `backendRef` 时使用的 Keycloak Service namespace
- 示例值：`identity-system`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.keycloakService.port`

- 类型：`int`
- 作用：写入 JWT provider `backendRef` 时使用的 Keycloak Service 端口
- 示例值：`8080`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.rbac.create`

- 类型：`bool`
- 作用：是否由 chart 自动创建 `idb-proxy` 的 `ServiceAccount + ClusterRole + ClusterRoleBinding`，以便更新 `AgentgatewayPolicy`
- 示例值：`true`

#### `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.rbac.serviceAccountName`

- 类型：`string`
- 作用：`idb-proxy` 使用的 ServiceAccount 名称（自动创建 RBAC 时也会使用该名称）
- 示例值：`idb-proxy`

### C. `opa-opal-pep-proxy.pepProxy.audit.*`

#### `opa-opal-pep-proxy.pepProxy.audit.maxEvents`

- 类型：`int`
- 作用：`pep-proxy` 内存审计事件上限（用于策略变更与审计回放追踪）
- 示例值：`5000`

#### `opa-opal-pep-proxy.pepProxy.audit.logPath`

- 类型：`string`
- 作用：可选，落盘审计事件（JSONL）
- 示例值：`""`

## 九、与新增接口对应的运行时行为（补充理解）

1. `idb-proxy` 新增接口（经 `/proxy/idb/*` 暴露）
- Group CRUD：`/tenants/{tenant_id}/groups`
- 用户入组：`/tenants/{tenant_id}/users/{username}/groups`
- SAML IdP：`/tenants/{tenant_id}/saml/idps`
- JWT provider sync：`/tenants/{tenant_id}/jwt-providers/sync`
- 审计查询：`/audit/events`

2. `pep-proxy` 新增接口（经 `/proxy/pep/*` 暴露）
- 策略包查询：`/tenants/{tenant_id}/policy-package`
- 数据库授权：`/authorize/db`
- 审计回放：`/audit/replay/{event_id}`

3. OPA ext_authz 变更
- 插件路径从 `envoy/authz/allow` 改为 `envoy/authz/decision`
- 可向后端注入可信头，并携带 `x-authz-policy-version` 便于审计关联
