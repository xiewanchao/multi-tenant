$ErrorActionPreference = "Stop"

kubectl apply -f manifests/tutorial/42-opal-server.yaml
kubectl apply -f manifests/tutorial/56-agentgateway-sidecar-opa-service.yaml

# Ensure temp directory exists for patch files.
New-Item -ItemType Directory -Path .tmp -Force | Out-Null

# Create/update sidecar policy configmap from the canonical Rego file.
kubectl -n agentgateway-system create configmap agw-opa-sidecar-policy `
  --from-file=policy.rego=charts/agentgateway-multi-tenant/charts/opa-opal-pep-proxy/files/policy.rego `
  --dry-run=client -o yaml | kubectl apply -f -

$patch = @"
spec:
  template:
    spec:
      volumes:
      - name: opa-sidecar-policy
        configMap:
          name: agw-opa-sidecar-policy
      containers:
      - name: opa-sidecar
        image: openpolicyagent/opa:0.70.0-envoy
        args:
        - "run"
        - "--server"
        - "--watch"
        - "--addr=0.0.0.0:8181"
        - "--set=plugins.envoy_ext_authz_grpc.addr=:9191"
        - "--set=plugins.envoy_ext_authz_grpc.path=envoy/authz/decision"
        - "--set=decision_logs.console=true"
        - "/policy/policy.rego"
        ports:
        - name: opa-grpc
          containerPort: 9191
        - name: opa-http
          containerPort: 8181
        volumeMounts:
        - name: opa-sidecar-policy
          mountPath: /policy
          readOnly: true
      - name: opal-client-sidecar
        image: permitio/opal-client:latest
        env:
        - name: OPAL_SERVER_URL
          value: http://opal-server.opal.svc.cluster.local:7002
        - name: OPAL_CLIENT_TOKEN
          value: THIS_IS_A_DEV_SECRET_CHANGE_ME
        - name: OPAL_DATA_TOPICS
          value: tenant_policies
        - name: OPAL_POLICY_UPDATER_ENABLED
          value: "false"
        - name: OPAL_DATA_UPDATER_ENABLED
          value: "true"
        - name: OPAL_INLINE_OPA_ENABLED
          value: "false"
        - name: OPAL_POLICY_STORE_URL
          value: http://127.0.0.1:8181/v1
"@

$patch | Set-Content -Path .tmp/agentgateway-sidecar-patch.yaml -Encoding ascii
kubectl -n agentgateway-system patch deployment agentgateway-proxy --type strategic --patch-file .tmp/agentgateway-sidecar-patch.yaml

# Route ext_authz policies to the sidecar-backed service in the gateway namespace.
$policyPatch = @"
spec:
  traffic:
    extAuth:
      backendRef:
        name: agentgateway-opa-sidecar
        namespace: agentgateway-system
        port: 9191
      grpc: {}
"@
$policyPatch | Set-Content -Path .tmp/policy-extauth-sidecar-patch.yaml -Encoding ascii
kubectl -n agentgateway-system patch agentgatewaypolicy opa-ext-auth-policy --type merge --patch-file .tmp/policy-extauth-sidecar-patch.yaml
kubectl -n agentgateway-system get agentgatewaypolicy mgmt-opa-ext-auth-policy 1>$null 2>$null
if ($LASTEXITCODE -eq 0) {
  kubectl -n agentgateway-system patch agentgatewaypolicy mgmt-opa-ext-auth-policy --type merge --patch-file .tmp/policy-extauth-sidecar-patch.yaml
}

kubectl -n opal rollout status deploy/postgres --timeout=240s
kubectl -n opal rollout status deploy/opal-server --timeout=240s
kubectl -n agentgateway-system rollout status deploy/agentgateway-proxy --timeout=240s
