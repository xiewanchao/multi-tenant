用一个具体例子来走完整个链路：

**场景**：租户 `acme` 的管理员 `alice` 请求 `GET /api/v1/tenants/acme/apps/myapp`

---

## 第一步：客户端拿 Token（提前完成）

客户端先向 Keycloak 登录拿 Token（这不是鉴权链路的一部分，但得先有 token）：

```http
POST http://www.example.com/realms/acme/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=alice&password=xxx&client_id=acme-frontend
```

Keycloak 返回一个 JWT，解码后 Payload 是：

```json
{
  "iss": "http://www.example.com/realms/acme",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "azp": "acme-frontend",
  "preferred_username": "alice",
  "tenant_id": "acme",
  "roles": ["tenant_admin"],
  "groups": ["/admin"],
  "exp": 1740000000,
  "iat": 1739996400
}
```

---

## 第二步：Gateway 缓存 JWKS 公钥（后台定期，不是每次请求）

Gateway 启动或缓存过期时（每 5 分钟），主动去 Keycloak 拉公钥：

```http
GET http://keycloak:8080/realms/acme/protocol/openid-connect/certs
```

Keycloak 返回 JWKS（公钥集合）：

```json
{
  "keys": [{
    "kid": "abc123",
    "kty": "RSA",
    "alg": "RS256",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps...",
    "e": "AQAB"
  }]
}
```

**这个公钥缓存在 Gateway 内存里**。之后验证签名完全在本地完成，不再调 Keycloak。

---

## 第三步：客户端发请求到 Gateway

```http
GET /api/v1/tenants/acme/apps/myapp HTTP/1.1
Host: www.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOiJodHRwOi8v...
x-tenant-id: master          ← 客户端试图伪造！
x-user: superuser            ← 客户端试图伪造！
```

---

## 第四步：Gateway 本地 JWT 验证

Gateway 拦截请求，用缓存的公钥本地完成验证：

```
1. 从 Authorization: Bearer ... 提取 token
2. 检查 header.kid = "abc123" → 找到对应缓存公钥
3. 用 RSA 公钥验证签名 → 通过
4. 检查 exp=1740000000 > 当前时间 → 未过期
5. 检查 iss="http://www.example.com/realms/acme"
   → 匹配 providers 列表中的 acme provider → 通过
6. 把 JWT Payload 写入 Envoy FilterMetadata
```

此时请求在 Gateway 内部附加了一个**内部元数据**（不在 HTTP Header 里，是 Envoy 内部传递）：

```
FilterMetadata["envoy.filters.http.jwt_authn"] = {
  "jwt_payload": {
    "iss": "http://www.example.com/realms/acme",
    "sub": "550e8400-...",
    "azp": "acme-frontend",
    "preferred_username": "alice",
    "tenant_id": "acme",
    "roles": ["tenant_admin"],
    "groups": ["/admin"],
    "exp": 1740000000
  }
}
```

---

## 第五步：Gateway gRPC 调用 OPA

Gateway 把完整信息打包成 `CheckRequest`，通过 gRPC 发给 OPA（`opa:9191`）：

```json
{
  "attributes": {
    "request": {
      "http": {
        "method": "GET",
        "path": "/api/v1/tenants/acme/apps/myapp",
        "headers": {
          "authorization": "Bearer eyJhbGci...",
          "x-tenant-id": "master",
          "x-user": "superuser",
          "host": "www.example.com"
        }
      }
    },
    "metadataContext": {
      "filterMetadata": {
        "envoy.filters.http.jwt_authn": {
          "jwt_payload": {              ← 第四步写进来的 JWT 数据
            "iss": "http://www.example.com/realms/acme",
            "preferred_username": "alice",
            "tenant_id": "acme",
            "roles": ["tenant_admin"],
            "groups": ["/admin"]
          }
        }
      }
    }
  }
}
```

---

## 第六步：OPA 执行 policy.rego

OPA 收到上面的 input，开始执行规则：

```python
# ① 从 FilterMetadata 读 JWT（不从 HTTP Header 读！）
_jwt_payload = { "tenant_id": "acme", "roles": ["tenant_admin"], ... }

# ② 提取关键字段
_token_tenant_id = "acme"
_username        = "alice"
_roles           = {"tenant_admin"}

# ③ 处理 groups："/admin" 去掉前缀斜杠 → "admin"
#    _normalize_group_name("/admin"):
#      split("/admin", "/") = ["", "admin"]
#      取最后一个 = "admin"
_groups = {"admin"}

# ④ 解析路径
_path_parts      = ["", "api", "v1", "tenants", "acme", "apps", "myapp"]
_path_tenant_id  = "acme"    （index 4）
_path_resource_type = "apps" （index 5）

# ⑤ 命中哪条 _allow_core 规则？
_allow_core if {
    _is_app_path          # ✓ resource_type == "apps"
    _tenant_match         # ✓ token "acme" == path "acme"
    not _has_dynamic_policy_rules   # ✓ 假设无动态策略
    some group in _groups           # group = "admin"
    some permission in _static_group_permissions["admin"]
    # _static_group_permissions["admin"] = [
    #   { method: "GET", path_pattern: "/api/v1/tenants/*/apps/**" },
    #   { method: "POST", path_pattern: "/api/v1/tenants/*/apps/**" }
    # ]
    permission.method == "GET"      # ✓
    glob.match("/api/v1/tenants/*/apps/**", ["/"],
               "/api/v1/tenants/acme/apps/myapp")  # ✓
}
# → allow = true
```

OPA 构造决策并返回：

```json
{
  "allowed": true,
  "headers": {
    "x-tenant-id":           "acme",
    "x-user":                "alice",
    "x-roles":               "tenant_admin",
    "x-groups":              "admin",
    "x-client-id":           "acme-frontend",
    "x-authz-policy-version":"static-fallback"
  },
  "request_headers_to_remove": [
    "x-tenant-id",
    "x-user",
    "x-roles",
    "x-groups",
    "x-client-id",
    "x-authz-policy-version"
  ]
}
```

---

## 第七步：Gateway 改写请求，转发给后端

Gateway 按 OPA 决策操作 HTTP 请求：

```
操作顺序：
1. 先执行 request_headers_to_remove → 删掉客户端发来的 x-tenant-id: master、x-user: superuser
2. 再注入 headers → 写入 OPA 从 JWT 里提取的可信值
```

最终转发给后端服务的请求：

```http
GET /api/v1/tenants/acme/apps/myapp HTTP/1.1
Host: www.example.com
Authorization: Bearer eyJhbGci...    ← 原样保留
x-tenant-id: acme                    ← OPA 注入（来自 JWT，伪造的已被删掉）
x-user: alice                        ← OPA 注入
x-roles: tenant_admin                ← OPA 注入
x-groups: admin                      ← OPA 注入（"/admin" 已规范化）
x-client-id: acme-frontend           ← OPA 注入
x-authz-policy-version: static-fallback  ← OPA 注入
```
