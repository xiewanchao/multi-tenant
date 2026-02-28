#!/usr/bin/env bash
set -euo pipefail

# Enable OPA sidecar + OPAL client sidecar on agentgateway-proxy (Linux version).

NAMESPACE_AGW="${NAMESPACE_AGW:-agentgateway-system}"
NAMESPACE_OPAL="${NAMESPACE_OPAL:-opal}"

kubectl apply -f manifests/tutorial/42-opal-server.yaml
kubectl apply -f manifests/tutorial/56-agentgateway-sidecar-opa-service.yaml

kubectl -n "${NAMESPACE_AGW}" create configmap agw-opa-sidecar-policy \
  --from-file=policy.rego=charts/agentgateway-multi-tenant/charts/opa-opal-pep-proxy/files/policy.rego \
  --dry-run=client -o yaml | kubectl apply -f -

PATCH_FILE="$(mktemp)"
POLICY_PATCH_FILE="$(mktemp)"
cleanup() {
  rm -f "$PATCH_FILE" "$POLICY_PATCH_FILE"
}
trap cleanup EXIT

cat >"$PATCH_FILE" <<'YAML'
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
YAML

kubectl -n "${NAMESPACE_AGW}" patch deployment agentgateway-proxy --type strategic --patch-file "$PATCH_FILE"

cat >"$POLICY_PATCH_FILE" <<'YAML'
spec:
  traffic:
    extAuth:
      backendRef:
        name: agentgateway-opa-sidecar
        namespace: agentgateway-system
        port: 9191
      grpc: {}
YAML

kubectl -n "${NAMESPACE_AGW}" patch agentgatewaypolicy opa-ext-auth-policy --type merge --patch-file "$POLICY_PATCH_FILE"
if kubectl -n "${NAMESPACE_AGW}" get agentgatewaypolicy mgmt-opa-ext-auth-policy >/dev/null 2>&1; then
  kubectl -n "${NAMESPACE_AGW}" patch agentgatewaypolicy mgmt-opa-ext-auth-policy --type merge --patch-file "$POLICY_PATCH_FILE"
fi

kubectl -n "${NAMESPACE_OPAL}" rollout status deploy/postgres --timeout=240s
kubectl -n "${NAMESPACE_OPAL}" rollout status deploy/opal-server --timeout=240s
kubectl -n "${NAMESPACE_AGW}" rollout status deploy/agentgateway-proxy --timeout=240s

echo "Sidecar enablement completed."
