$ErrorActionPreference = "Stop"

function Invoke-Http {
  param(
    [string]$Method,
    [string]$Url,
    [hashtable]$Headers,
    [string]$Body = $null,
    [string]$ContentType = $null
  )
  try {
    if ($Body) {
      if ($ContentType) {
        $resp = Invoke-WebRequest -Uri $Url -Method $Method -Headers $Headers -Body $Body -ContentType $ContentType -UseBasicParsing
      }
      else {
        $resp = Invoke-WebRequest -Uri $Url -Method $Method -Headers $Headers -Body $Body -UseBasicParsing
      }
    }
    else {
      $resp = Invoke-WebRequest -Uri $Url -Method $Method -Headers $Headers -UseBasicParsing
    }
    return [pscustomobject]@{ status = [int]$resp.StatusCode; content = [string]$resp.Content }
  }
  catch {
    if ($_.Exception.Response -ne $null) {
      $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
      $content = $sr.ReadToEnd()
      $sr.Close()
      return [pscustomobject]@{ status = [int]$_.Exception.Response.StatusCode; content = [string]$content }
    }
    throw
  }
}

$base = "http://127.0.0.1:18080"
$headers = @{ Host = "www.example.com" }

$job = Start-Job -ScriptBlock { kubectl -n agentgateway-system port-forward service/agentgateway-proxy 18080:80 }
$opaJob = Start-Job -ScriptBlock { kubectl -n agentgateway-system port-forward service/agentgateway-opa-sidecar 18182:8181 }
Start-Sleep -Seconds 4

try {
  # cleanup from previous failed runs
  $cleanupResp = Invoke-Http -Method DELETE -Url "http://127.0.0.1:18182/v1/policies/dynamic-test" -Headers @{}
  if ($cleanupResp.status -ne 200 -and $cleanupResp.status -ne 404) {
    throw "OPA cleanup failed: $($cleanupResp.status) $($cleanupResp.content)"
  }

  # bootstrap window
  kubectl -n agentgateway-system delete agentgatewaypolicy mgmt-jwt-auth-policy mgmt-opa-ext-auth-policy --ignore-not-found=true | Out-Null
  Start-Sleep -Seconds 2

  $masterBody = @{
    client_id            = "master-gateway-client"
    super_admin_username = "superadmin"
    super_admin_password = "superadmin123"
    super_admin_email    = "superadmin@gateway.local"
  } | ConvertTo-Json
  $master = Invoke-Http -Method POST -Url "$base/proxy/idb/bootstrap/master" -Headers $headers -Body $masterBody -ContentType "application/json"
  if ($master.status -ne 200) { throw "bootstrap master failed: $($master.status) $($master.content)" }
  $masterObj = $master.content | ConvertFrom-Json

  $tenantBody = @{
    display_name = "Acme Corp"
    client_id    = "acme-frontend"
    tenant_admin = @{
      username = "alice"
      password = "alice123"
      email    = "alice@acme.local"
      groups   = @("admin")
      roles    = @("tenant_admin")
    }
    users       = @()
  } | ConvertTo-Json -Depth 6
  $tenant = Invoke-Http -Method POST -Url "$base/proxy/idb/tenants/acme/bootstrap" -Headers $headers -Body $tenantBody -ContentType "application/json"
  if ($tenant.status -ne 200) { throw "bootstrap tenant failed: $($tenant.status) $($tenant.content)" }
  $tenantObj = $tenant.content | ConvertFrom-Json

  # re-enable mgmt policies
  $m = Get-Content -Raw manifests/tutorial/54-mgmt-jwt-auth-policy.template.yaml
  $m = $m.Replace('${MASTER_ISSUER}', 'http://www.example.com/realms/master').Replace('${MASTER_JWKS_PATH}', '/realms/master/protocol/openid-connect/certs').Replace('${ACME_ISSUER}', 'http://www.example.com/realms/acme').Replace('${ACME_JWKS_PATH}', '/realms/acme/protocol/openid-connect/certs')
  $m | kubectl apply -f - | Out-Null
  kubectl apply -f manifests/tutorial/55-mgmt-opa-ext-auth-policy.yaml | Out-Null
  Start-Sleep -Seconds 2

  $tokResp = Invoke-Http -Method POST -Url "$base/realms/acme/protocol/openid-connect/token" -Headers $headers -Body ("grant_type=password&client_id=acme-frontend&client_secret={0}&username=alice&password=alice123" -f $tenantObj.client_secret) -ContentType "application/x-www-form-urlencoded"
  if ($tokResp.status -ne 200) { throw "get token failed: $($tokResp.status) $($tokResp.content)" }
  $token = ($tokResp.content | ConvertFrom-Json).access_token
  $authHeaders = @{ Host = "www.example.com"; Authorization = "Bearer $token" }

  $before = Invoke-Http -Method GET -Url "$base/api/v1/tenants/acme/apps/myapp" -Headers $authHeaders
  if ($before.status -ne 200) { throw "baseline business request failed: $($before.status)" }

  # dynamic rego update: push an extra policy module into sidecar OPA (no gateway restart).
  # Important: static fallback allow only works when `not _has_dynamic_policy_rules`.
  # So this module forces dynamic mode + deny for app path requests.
  $dynamicModule = @"
package envoy.authz

import future.keywords.if

_has_dynamic_policy_rules if {
  true
}

_envoy_dynamic_deny if {
  _is_app_path
}
"@
  $putResp = Invoke-Http -Method PUT -Url "http://127.0.0.1:18182/v1/policies/dynamic-test" -Headers @{} -Body $dynamicModule -ContentType "text/plain"
  if ($putResp.status -ne 200) { throw "OPA policy push failed: $($putResp.status) $($putResp.content)" }
  Start-Sleep -Seconds 3

  $during = Invoke-Http -Method GET -Url "$base/api/v1/tenants/acme/apps/myapp" -Headers $authHeaders
  if ($during.status -ne 403) { throw "dynamic update not effective, expected 403 got $($during.status)" }

  # restore policy
  $delResp = Invoke-Http -Method DELETE -Url "http://127.0.0.1:18182/v1/policies/dynamic-test" -Headers @{}
  if ($delResp.status -ne 200) { throw "OPA policy delete failed: $($delResp.status) $($delResp.content)" }
  Start-Sleep -Seconds 3

  $after = Invoke-Http -Method GET -Url "$base/api/v1/tenants/acme/apps/myapp" -Headers $authHeaders
  if ($after.status -ne 200) { throw "policy restore not effective, expected 200 got $($after.status)" }

  Write-Output "PASS sidecar+dynamic-rego: baseline=$($before.status), updated=$($during.status), restored=$($after.status)"
}
finally {
  Stop-Job $job | Out-Null
  Remove-Job $job | Out-Null
  Stop-Job $opaJob | Out-Null
  Remove-Job $opaJob | Out-Null
}
