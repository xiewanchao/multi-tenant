# AgentGateway 多租户方案（Umbrella Helm Chart 部署，偏生产）

本文把原来分散的 `manifests/tutorial/*.yaml` 打包成一个 Helm umbrella chart，并拆成 3 个子 chart，支持一次 `helm upgrade --install` 完成部署。

## 目标

- 一个 Helm release 部署整套多租户身份与策略控制方案
- 子 chart 拆分清晰，便于独立演进
- `values.yaml` / `values-prod.yaml` 分层配置，贴近生产
- 保留原教程中的关键命名（`admin-api-route`、`tenant-api-route`、`jwt-auth-policy`、`opa-ext-auth-policy`）

## Chart 结构

路径：`charts/agentgateway-multi-tenant`

包含：

1. `keycloak-idb-proxy`
   - Keycloak（OIDC / JWKS / token）
   - `idb-proxy`（身份管理 facade）
   - `/proxy/idb/*` 路由与 `ReferenceGrant`
2. `agentgateway`
   - `Gateway`
   - 业务 `HTTPRoute`（admin / tenant）
   - Keycloak OIDC `HTTPRoute`
   - `jwt-auth-policy`
   - 可选依赖官方 `agentgateway-crds` / `agentgateway` chart（默认关闭）
3. `opa-opal-pep-proxy`
   - OPA（ext_authz gRPC + Data API）
   - OPAL（server/client，可选内置 postgres）
   - `pep-proxy`
   - `/proxy/pep/*` 路由与 `ReferenceGrant`
   - `opa-ext-auth-policy`

说明：

- `agentgateway` 子 chart 默认不安装 AgentGateway controller / CRDs（平台层通常独立运维）
- 如果希望“一次 Helm 装完平台层 + 业务层”，可开启 `agentgateway.upstream.installCRDs=true` 和 `agentgateway.upstream.installController=true`

## 1. 前置准备（生产建议）

至少确认：

- Kubernetes 集群可用
- `helm` >= 3.13
- 镜像可拉取（或已同步到私有仓库）
  - `quay.io/keycloak/keycloak`
  - `openpolicyagent/opa`
  - `permitio/opal-server`
  - `permitio/opal-client`
  - 你的 `idb-proxy` / `pep-proxy` 镜像

构建代理镜像示例：

```bash
docker build -t ghcr.io/your-org/idb-proxy-fastapi:0.1.0 proxies/idb-proxy
docker build -t ghcr.io/your-org/pep-proxy-fastapi:0.1.0 proxies/pep-proxy
docker push ghcr.io/your-org/idb-proxy-fastapi:0.1.0
docker push ghcr.io/your-org/pep-proxy-fastapi:0.1.0
```

## 2. 准备生产 values 文件

```bash
cp charts/agentgateway-multi-tenant/values-prod.example.yaml charts/agentgateway-multi-tenant/values-prod.yaml
```

重点修改项（生产必须）：

1. 域名与 host
   - `global.hostnames[0]`
2. 后端业务服务
   - `global.businessRoutes.admin.backendService`
   - `global.businessRoutes.tenant.backendService`
3. 代理镜像
   - `keycloak-idb-proxy.idbProxy.image.*`
   - `opa-opal-pep-proxy.pepProxy.image.*`
4. JWT Issuer / JWKS
   - `agentgateway.routes.jwtPolicy.providers[*]`
5. OPAL / PEP Token
   - `opa-opal-pep-proxy.opal.auth.*`
   - `opa-opal-pep-proxy.pepProxy.opal.masterToken.*`
6. 副本与资源
   - `*.replicaCount`
   - `*.resources`

## 3. 拉取依赖（如开启 AgentGateway 官方子依赖）

```bash
helm dependency update charts/agentgateway-multi-tenant
helm dependency update charts/agentgateway-multi-tenant/charts/agentgateway
```

## 4. 部署（一个 Helm Release）

```bash
helm upgrade --install agentgateway-mt charts/agentgateway-multi-tenant \
  -f charts/agentgateway-multi-tenant/values-prod.yaml
```

如果你希望 Helm release 元数据放在固定 namespace：

```bash
helm upgrade --install agentgateway-mt charts/agentgateway-multi-tenant \
  -n agentgateway-system --create-namespace \
  -f charts/agentgateway-multi-tenant/values-prod.yaml
```

说明：

- 业务组件会按 `global.namespaces.*` 分散部署到多个 namespace
- Helm release namespace 只影响 Helm 元数据，不等于资源实际 namespace

## 5. 验证部署状态

```bash
kubectl get ns | grep -E "agentgateway|keycloak|proxy|opa|opal"
kubectl get deploy -A | grep -E "keycloak|idb-proxy|pep-proxy|opa|opal"
kubectl get httproute -n agentgateway-system
kubectl get gateway -n agentgateway-system
kubectl get referencegrant -A
```

重点检查：

1. `Gateway` 已 `Accepted/Programmed`
2. `HTTPRoute` 已绑定到 `agentgateway-proxy`
3. `keycloak` / `idb-proxy` / `opa` / `pep-proxy` Pod Ready
4. `opal-server` 与 `opal-client` 正常（如启用）

## 6. 最小联调验证

```bash
kubectl -n agentgateway-system port-forward deployment/agentgateway-proxy 8080:80
```

OIDC 路由（无需 token）：

```bash
curl -i http://127.0.0.1:8080/realms/master/.well-known/openid-configuration \
  -H "Host: api.company.example"
```

代理路由：

```bash
curl -i http://127.0.0.1:8080/proxy/idb/healthz -H "Host: api.company.example"
curl -i http://127.0.0.1:8080/proxy/pep/healthz -H "Host: api.company.example"
```

业务路由（无 token 应返回 401，前提已启用 JWT policy）：

```bash
curl -i http://127.0.0.1:8080/api/v1/admin/tenants -H "Host: api.company.example"
```

## 7. 生产建议

1. Keycloak 使用外部 PostgreSQL（持久化），不要长期使用 `start-dev`
2. OPAL Postgres 使用外部高可用数据库，关闭 `opal.postgres.enabled`
3. 使用 `existingSecret` 管理管理员密码和 OPAL token
4. 给关键组件配置 `resources`、副本数、反亲和策略（后续可继续扩展 chart）
5. 将示例 `httpbin` 后端替换为真实 `admin-api` / `tenant-api`
6. 根据你的接入层为域名配置 TLS

## 8. 为什么拆成这 3 个子 chart

你提出的拆分方式是合理的，我保留了这个结构：

1. `keycloak-idb-proxy`：身份域（Identity plane）
2. `agentgateway`：流量入口与策略绑定域（Traffic / Gateway plane）
3. `opa-opal-pep-proxy`：授权与策略分发域（Policy / AuthZ plane）

优点：

- 组件职责清晰，变更影响面小
- 方便按团队边界维护（平台、身份、授权）
- 后续可以把某一子 chart 独立抽出单独发布

## 9. 升级与回滚

```bash
helm upgrade agentgateway-mt charts/agentgateway-multi-tenant \
  -f charts/agentgateway-multi-tenant/values-prod.yaml
```

```bash
helm history agentgateway-mt -n agentgateway-system
helm rollback agentgateway-mt <REVISION> -n agentgateway-system
```

## 10. 常见问题

1. `AgentgatewayPolicy` 创建失败
   - 可能是 CRD 未安装或 controller 未运行
2. `HTTPRoute` 不生效
   - 检查 `Gateway` 是否 `Programmed`
   - 检查请求 `Host` 是否与 `global.hostnames` 一致
3. OPA ext_authz 不通
   - 检查 `allow-agentgateway-to-opa` `ReferenceGrant`
   - 检查 OPA `Service` gRPC 端口 `9191`
4. PEP / OPAL 不同步
   - 检查 OPAL token 是否一致
   - 检查 `opal-server` 到 `pep-proxy` 服务地址是否可达

## 11. 扩展功能（SAML / Groups / 审计 / JWT 自动注册）

本仓库后续增补了以下能力：

1. `idb-proxy`：
   - SAML IdP 管理接口（导入/更新/启停/证书轮换/mapper）
   - Keycloak Group CRUD
   - 用户入组/移组
   - 审计事件查询
   - 可选：创建租户后自动注册 JWT provider 到 `AgentgatewayPolicy(jwt-auth-policy)`
2. `pep-proxy`：
   - 策略包（带 `version` / `metadata`）
   - `/authorize/db`（数据库资源授权检查）
   - 审计查询与策略回放
3. OPA ext_authz：
   - 决策路径改为 `envoy/authz/decision`
   - 向后端注入可信头（`x-tenant-id/x-user/x-roles/x-groups/x-client-id/x-authz-policy-version`）

### 11.1 `values-prod.yaml` 建议新增配置

```yaml
keycloak-idb-proxy:
  idbProxy:
    audit:
      maxEvents: 5000
      logPath: ""
    jwtProviderAutoRegistration:
      enabled: true
      keycloakPublicIssuerBaseUrl: "https://api.company.example"
      agentgatewayPolicyNamespace: "agentgateway-system"
      agentgatewayPolicyName: "jwt-auth-policy"
      keycloakService:
        name: "keycloak"
        namespace: "identity-system"
        port: 8080
      rbac:
        create: true
        serviceAccountName: "idb-proxy"

opa-opal-pep-proxy:
  pepProxy:
    audit:
      maxEvents: 5000
      logPath: ""
```

### 11.2 JWT Provider 自动注册（RBAC 注意）

当 `keycloak-idb-proxy.idbProxy.jwtProviderAutoRegistration.enabled=true` 时：

- `idb-proxy` 需要具备更新 `AgentgatewayPolicy` 的权限
- umbrella chart 已支持按 `rbac.create=true` 自动创建所需 `ServiceAccount + ClusterRole + ClusterRoleBinding`

如果你使用 tutorial manifests 而不是 Helm chart，请手动应用：

```bash
kubectl apply -f manifests/tutorial/22-idb-proxy-jwt-sync-rbac.yaml
```

### 11.3 扩展 curl 测试脚本

新增脚本：`scripts/tutorial-curl-extended-tests.sh`

覆盖：

- SAML IdP API
- Group / 用户入组 API
- 数据库授权（`/proxy/pep/authorize/db`）
- 审计回放（`/proxy/pep/audit/replay/{event_id}`）

```bash
bash scripts/tutorial-curl-extended-tests.sh
```

如需自定义：

```bash
TENANT_ID=acme TENANT_USER=alice GROUP_NAME=finance bash scripts/tutorial-curl-extended-tests.sh
```
