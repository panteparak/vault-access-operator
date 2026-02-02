#!/usr/bin/env bash
# E2E local development setup script.
# Configures k3s (from docker-compose) with Vault, Dex bridge, auth methods, and operator.
#
# Prerequisites: docker compose -f docker-compose.e2e.yaml up -d
# Usage: bash scripts/e2e-setup.sh [--skip-operator] [--skip-build]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.e2e.yaml"
KUBECONFIG_PATH="$PROJECT_ROOT/tmp/e2e/kubeconfig.yaml"
OPERATOR_IMAGE="vault-access-operator:local"

# Parse flags
SKIP_OPERATOR=false
SKIP_BUILD=false
for arg in "$@"; do
  case $arg in
    --skip-operator) SKIP_OPERATOR=true ;;
    --skip-build) SKIP_BUILD=true ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# --- Colors and helpers ---
info()  { echo "==> $*"; }
ok()    { echo "  -> $*"; }
warn()  { echo "  !! $*"; }
fail()  { echo "ERROR: $*" >&2; exit 1; }

# --- Check prerequisites ---
info "Checking prerequisites"
for cmd in kubectl helm docker go; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd is required but not found"
  ok "$cmd found"
done
docker compose version >/dev/null 2>&1 || fail "docker compose plugin is required"
ok "docker compose found"

# --- Wait for k3s ---
info "Waiting for k3s kubeconfig"
for i in $(seq 1 60); do
  if [ -f "$KUBECONFIG_PATH" ]; then
    ok "Kubeconfig found"
    break
  fi
  if [ "$i" -eq 60 ]; then
    fail "Timed out waiting for k3s kubeconfig at $KUBECONFIG_PATH"
  fi
  sleep 2
done

# Fix kubeconfig server URL: k3s writes its internal container IP, we need localhost
# The kubeconfig may have something like https://10.x.x.x:6443 or https://k3s:6443
sed -i.bak 's|server: https://.*:6443|server: https://127.0.0.1:6443|' "$KUBECONFIG_PATH"
rm -f "${KUBECONFIG_PATH}.bak"
export KUBECONFIG="$KUBECONFIG_PATH"

info "Waiting for k3s node to be ready"
kubectl wait --for=condition=Ready nodes --all --timeout=120s
ok "k3s node ready"

# --- Deploy Vault ---
info "Deploying Vault"
kubectl apply -f "$PROJECT_ROOT/test/e2e/fixtures/vault.yaml"
kubectl rollout status statefulset/vault -n vault --timeout=300s
ok "Vault deployed and ready"

# --- Bridge Dex into k3s ---
info "Creating Dex K8s Service bridge"

# Get Dex container's IP on the e2e-net network
DEX_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q dex)
if [ -z "$DEX_CONTAINER" ]; then
  fail "Dex container not found. Is docker-compose running?"
fi

# Try to get IP from the compose network
DEX_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DEX_CONTAINER")
if [ -z "$DEX_IP" ]; then
  fail "Could not determine Dex container IP"
fi
ok "Dex container IP: $DEX_IP"

# Create K8s Service + Endpoints pointing to Dex container
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: dex
  namespace: default
spec:
  ports:
    - port: 5556
      targetPort: 5556
---
apiVersion: v1
kind: Endpoints
metadata:
  name: dex
  namespace: default
subsets:
  - addresses:
      - ip: ${DEX_IP}
    ports:
      - port: 5556
EOF
ok "Dex K8s Service + Endpoints created"

info "Verifying Dex reachable from inside k3s"
kubectl run dex-test --rm -i --restart=Never \
  --image=curlimages/curl --timeout=60s -- \
  curl -sf http://dex.default.svc.cluster.local:5556/.well-known/openid-configuration >/dev/null 2>&1 \
  && ok "Dex reachable from inside k3s" \
  || warn "Dex verification probe failed (may still work — continuing)"

# --- Configure Vault ---
info "Configuring Vault for E2E tests"

# Create operator policy (mirrors CI and operatorPolicyHCL in e2e_suite_test.go)
kubectl exec -i -n vault vault-0 -- vault policy write vault-access-operator - <<'POLICY'
# Policy management
path "sys/policies/acl/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policies/acl" { capabilities = ["list"] }
# Kubernetes auth
path "auth/kubernetes/role/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/kubernetes/role" { capabilities = ["list"] }
path "auth/kubernetes/config" { capabilities = ["create", "read", "update", "delete"] }
# JWT auth
path "auth/jwt/role/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/jwt/role" { capabilities = ["list"] }
path "auth/jwt/config" { capabilities = ["create", "read", "update", "delete"] }
# AppRole auth
path "auth/approle/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/approle" { capabilities = ["read"] }
# OIDC (JWT at oidc path) auth
path "auth/oidc/*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
path "auth/oidc" { capabilities = ["read"] }
# Auth method management
path "sys/auth" { capabilities = ["read"] }
path "sys/auth/*" { capabilities = ["sudo", "create", "read", "update", "delete", "list"] }
# Health + mounts
path "sys/mounts" { capabilities = ["read"] }
path "sys/health" { capabilities = ["read"] }
# KV v2 managed resource metadata
path "secret/data/vault-access-operator/managed/*" { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/vault-access-operator/managed/*" { capabilities = ["list", "read", "delete"] }
POLICY
ok "Operator policy created"

# Enable auth methods
kubectl exec -n vault vault-0 -- vault auth enable jwt 2>/dev/null || true
ok "JWT auth enabled"

kubectl exec -n vault vault-0 -- vault auth enable approle 2>/dev/null || true
ok "AppRole auth enabled"

kubectl exec -n vault vault-0 -- vault auth enable -path=oidc jwt 2>/dev/null || true
ok "OIDC (JWT at oidc path) auth enabled"

# Get K8s OIDC/JWKS configuration
OIDC_CONFIG=$(kubectl get --raw /.well-known/openid-configuration)
ISSUER=$(echo "$OIDC_CONFIG" | jq -r '.issuer')
ok "K8s OIDC Issuer: $ISSUER"

# Get K8s CA cert for TLS verification
K8S_CA=$(kubectl get secret -n vault vault-token -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d || \
         kubectl exec -n vault vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

# Pre-fetch JWKS
JWKS=$(kubectl get --raw /openid/v1/jwks)

# Configure JWT auth — try OIDC discovery first, fall back to JWKS
if kubectl exec -i -n vault vault-0 -- vault write auth/jwt/config \
     oidc_discovery_url="$ISSUER" \
     bound_issuer="$ISSUER" \
     oidc_discovery_ca_pem="$K8S_CA" 2>/dev/null; then
  ok "JWT auth configured with OIDC discovery"
else
  warn "OIDC discovery failed for JWT, falling back to JWKS"
  kubectl exec -n vault vault-0 -- vault write auth/jwt/config \
    jwt_validation_pubkeys="$JWKS" \
    bound_issuer="$ISSUER" || \
  warn "JWT auth configuration failed (tests will skip JWT auth)"
fi

# Configure OIDC (JWT at oidc path) auth with Dex
kubectl exec -n vault vault-0 -- vault write auth/oidc/config \
  oidc_discovery_url="http://dex.default.svc.cluster.local:5556" \
  bound_issuer="http://dex.default.svc.cluster.local:5556"
ok "OIDC auth configured with Dex discovery"

# --- Build + deploy operator ---
if [ "$SKIP_OPERATOR" = true ]; then
  info "Skipping operator build/deploy (--skip-operator)"
else
  if [ "$SKIP_BUILD" = true ]; then
    info "Skipping operator build (--skip-build)"
  else
    info "Building operator image"
    make -C "$PROJECT_ROOT" docker-build IMG="$OPERATOR_IMAGE"
    ok "Operator image built: $OPERATOR_IMAGE"
  fi

  info "Importing operator image into k3s"
  docker save "$OPERATOR_IMAGE" | \
    docker compose -f "$COMPOSE_FILE" exec -T k3s ctr --namespace k8s.io images import -
  ok "Image imported into k3s containerd"

  info "Deploying operator via Helm"
  helm install vault-access-operator "$PROJECT_ROOT/charts/vault-access-operator" \
    --namespace vault-access-operator-system --create-namespace \
    --set image.repository=vault-access-operator \
    --set image.tag=local \
    --set image.pullPolicy=Never \
    --set webhook.enabled=false \
    --wait --timeout 5m
  ok "Operator deployed"

  kubectl wait --for=condition=Available deployment \
    -l app.kubernetes.io/name=vault-access-operator \
    -n vault-access-operator-system --timeout=120s
  ok "Operator ready"
fi

# --- Summary ---
echo ""
echo "========================================"
echo "  E2E stack is ready!"
echo "========================================"
echo ""
echo "  KUBECONFIG: export KUBECONFIG=$KUBECONFIG_PATH"
echo ""
echo "  Run tests:   make e2e-local-test"
echo "  Status:      make e2e-local-status"
echo "  Tear down:   make e2e-local-down"
echo ""
