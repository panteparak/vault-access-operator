# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 0.0.1

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# platform.io/vault-access-operator-bundle:$VERSION and platform.io/vault-access-operator-catalog:$VERSION.
IMAGE_TAG_BASE ?= platform.io/vault-access-operator

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)

# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Set the Operator SDK version to use. By default, what is installed on the system is used.
# This is useful for CI or a project to utilize a specific version of the operator-sdk toolkit.
OPERATOR_SDK_VERSION ?= v1.42.0
# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

CHART_DIR ?= charts/vault-access-operator

.PHONY: helm-update-crds
helm-update-crds: manifests ## Copy CRDs to Helm chart
	cp config/crd/bases/*.yaml $(CHART_DIR)/crds/

.PHONY: compare-templates
compare-templates: ## Compare kustomize and helm template outputs
	@./scripts/compare-templates.sh

.PHONY: verify-templates
verify-templates: manifests helm-update-crds compare-templates ## Full template verification

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run unit tests (excludes e2e and integration tests via build tags).
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# E2E tests run in CI (docker-compose k3s with Vault + operator pre-deployed).
# This target assumes a running cluster — see .github/workflows/ci.yaml for full setup.
# E2E_K8S_HOST tells the test suite where Vault can reach the K8s API (docker network DNS for external Vault).
E2E_K8S_HOST ?= https://k3s:6443

.PHONY: test-e2e
test-e2e: manifests generate fmt vet ## Run E2E tests (requires running cluster with Vault + operator deployed)
	E2E_K8S_HOST=$(E2E_K8S_HOST) go test ./test/e2e/ -v -ginkgo.v -ginkgo.fail-fast -timeout 10m

##@ E2E Tests - Sequential Execution

.PHONY: test-e2e-sequential
test-e2e-sequential: test-e2e-auth test-e2e-modules ## Run E2E tests: auth first, then modules

.PHONY: test-e2e-auth
test-e2e-auth: ## Run auth tests only
	E2E_K8S_HOST=$(E2E_K8S_HOST) go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="auth" -timeout 10m

.PHONY: test-e2e-modules
test-e2e-modules: ## Run module tests only (after auth)
	E2E_K8S_HOST=$(E2E_K8S_HOST) go test ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="module || setup" -timeout 15m

##@ E2E Infrastructure (Mini-Step Targets)
# These targets are used by both local development and CI.
# CI calls the same make targets as local — single source of truth.

E2E_KUBECONFIG      := $(shell pwd)/tmp/e2e/kubeconfig.yaml
E2E_COMPOSE         := docker compose -f docker-compose.e2e.yaml
E2E_VAULT_EXEC      := $(E2E_COMPOSE) exec -T vault vault
E2E_KUBECTL          = KUBECONFIG=$(E2E_KUBECONFIG) kubectl
E2E_HELM             = KUBECONFIG=$(E2E_KUBECONFIG) helm
E2E_OPERATOR_IMAGE  ?= vault-access-operator:local

.PHONY: e2e-compose-up
e2e-compose-up: ## Start docker-compose stack (k3s + Vault + Dex)
	@mkdir -p tmp/e2e
	$(E2E_COMPOSE) up -d
	@echo "Waiting for Vault healthcheck..."
	@for i in $$(seq 1 30); do \
		if $(E2E_COMPOSE) exec -T vault vault status >/dev/null 2>&1; then \
			echo "Vault is ready"; break; \
		fi; \
		if [ "$$i" -eq 30 ]; then echo "ERROR: Vault failed to start"; $(E2E_COMPOSE) logs vault; exit 1; fi; \
		sleep 2; \
	done

.PHONY: e2e-compose-down
e2e-compose-down: ## Stop docker-compose stack and clean up
	$(E2E_COMPOSE) down -v 2>/dev/null || true
	rm -rf tmp/e2e

.PHONY: e2e-wait-cluster
e2e-wait-cluster: ## Wait for k3s kubeconfig, fix URL, wait for node + kube-system
	@echo "Waiting for k3s kubeconfig..."
	@for i in $$(seq 1 60); do \
		if [ -f "$(E2E_KUBECONFIG)" ]; then echo "Kubeconfig found"; break; fi; \
		if [ "$$i" -eq 60 ]; then echo "ERROR: Timed out waiting for kubeconfig"; exit 1; fi; \
		sleep 2; \
	done
	@# Fix kubeconfig server URL — k3s writes its internal container IP, we need localhost
	@sed -i.bak 's|server: https://.*:6443|server: https://127.0.0.1:6443|' "$(E2E_KUBECONFIG)"
	@rm -f "$(E2E_KUBECONFIG).bak"
	@echo "Waiting for k3s node to be ready..."
	$(E2E_KUBECTL) wait --for=condition=Ready nodes --all --timeout=120s
	@echo "Waiting for kube-system pods to appear..."
	@for i in $$(seq 1 30); do \
		if $(E2E_KUBECTL) get pods -n kube-system 2>/dev/null | grep -q .; then break; fi; \
		if [ "$$i" -eq 30 ]; then echo "ERROR: Timed out waiting for kube-system pods"; exit 1; fi; \
		sleep 2; \
	done
	$(E2E_KUBECTL) wait --for=condition=Ready pods --all -n kube-system --timeout=120s

.PHONY: e2e-check-context
e2e-check-context: ## Verify KUBECONFIG points to E2E cluster (safety check)
	@if [ ! -f "$(E2E_KUBECONFIG)" ]; then \
		echo "ERROR: E2E kubeconfig not found at $(E2E_KUBECONFIG)"; \
		echo "Run 'make e2e-compose-up e2e-wait-cluster' first"; \
		exit 1; \
	fi
	@SERVER=$$($(E2E_KUBECTL) config view --minify -o jsonpath='{.clusters[0].cluster.server}'); \
	case "$$SERVER" in \
		*127.0.0.1*|*localhost*|*k3s*) echo "KUBECONFIG OK: $$SERVER" ;; \
		*) echo "ERROR: KUBECONFIG points to $$SERVER — refusing to run against non-local cluster"; exit 1 ;; \
	esac

.PHONY: e2e-deploy-vault-rbac
e2e-deploy-vault-rbac: e2e-check-context ## Deploy Vault RBAC resources (namespace, SA, ClusterRole)
	$(E2E_KUBECTL) apply -f test/e2e/fixtures/vault-rbac.yaml

.PHONY: e2e-bridge-vault
e2e-bridge-vault: e2e-check-context ## Create K8s Service+Endpoints bridging to Vault container
	@CID=$$($(E2E_COMPOSE) ps -q vault); \
	if [ -z "$$CID" ]; then echo "ERROR: Vault container not found"; exit 1; fi; \
	VAULT_IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$$CID"); \
	if [ -z "$$VAULT_IP" ]; then echo "ERROR: Could not get Vault container IP"; exit 1; fi; \
	echo "Vault container IP: $$VAULT_IP"; \
	sed "s/__VAULT_IP__/$$VAULT_IP/" test/e2e/fixtures/vault-bridge.yaml | $(E2E_KUBECTL) apply -f -

.PHONY: e2e-bridge-dex
e2e-bridge-dex: e2e-check-context ## Create K8s Service+Endpoints bridging to Dex container
	@CID=$$($(E2E_COMPOSE) ps -q dex); \
	if [ -z "$$CID" ]; then echo "ERROR: Dex container not found"; exit 1; fi; \
	DEX_IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$$CID"); \
	if [ -z "$$DEX_IP" ]; then echo "ERROR: Could not get Dex container IP"; exit 1; fi; \
	echo "Dex container IP: $$DEX_IP"; \
	sed "s/__DEX_IP__/$$DEX_IP/" test/e2e/fixtures/dex-bridge.yaml | $(E2E_KUBECTL) apply -f -

.PHONY: e2e-configure-vault
e2e-configure-vault: ## Configure Vault auth methods and policies for E2E
	@echo "Creating operator policy..."
	@cat test/e2e/fixtures/policies/e2e-operator-bootstrap.hcl | $(E2E_VAULT_EXEC) policy write vault-access-operator -
	@echo "Enabling auth methods..."
	@$(E2E_VAULT_EXEC) auth enable kubernetes 2>/dev/null || true
	@$(E2E_VAULT_EXEC) auth enable jwt 2>/dev/null || true
	@$(E2E_VAULT_EXEC) auth enable approle 2>/dev/null || true
	@$(E2E_VAULT_EXEC) auth enable -path=oidc jwt 2>/dev/null || true
	@echo "Configuring Kubernetes auth..."
	@# Extract the TLS server CA from kubeconfig (NOT the SA CA — they differ in k3s 1.25+)
	@# Use a 24h token to avoid expiration during long test runs
	@# Also configure issuer for proper JWT validation
	@K8S_CA=$$($(E2E_KUBECTL) config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d); \
	VAULT_AUTH_TOKEN=$$($(E2E_KUBECTL) create token vault-auth -n vault --duration=24h); \
	ISSUER=$$($(E2E_KUBECTL) get --raw /.well-known/openid-configuration | jq -r '.issuer'); \
	jq -n \
		--arg host "https://k3s:6443" \
		--arg jwt "$$VAULT_AUTH_TOKEN" \
		--arg ca "$$K8S_CA" \
		--arg issuer "$$ISSUER" \
		'{kubernetes_host: $$host, token_reviewer_jwt: $$jwt, kubernetes_ca_cert: $$ca, issuer: $$issuer}' | \
	$(E2E_VAULT_EXEC) write auth/kubernetes/config -
	@echo "Kubernetes auth configured (host=https://k3s:6443, issuer=$$ISSUER)"
	@echo "Creating operator role in Kubernetes auth..."
	@$(E2E_VAULT_EXEC) write auth/kubernetes/role/vault-access-operator \
		bound_service_account_names=vault-access-operator \
		bound_service_account_namespaces=vault-access-operator-system \
		policies=vault-access-operator \
		ttl=1h
	@echo "Operator role created"
	@echo "Configuring JWT auth..."
	@# External Vault can't reach k3s JWKS endpoint due to TLS issues
	@# Convert JWKS to PEM and provide directly via jwt_validation_pubkeys
	@JWKS=$$($(E2E_KUBECTL) get --raw /openid/v1/jwks); \
	ISSUER=$$($(E2E_KUBECTL) get --raw /.well-known/openid-configuration | jq -r '.issuer'); \
	PEM=$$(echo "$$JWKS" | python3 hack/jwk-to-pem.py); \
	$(E2E_VAULT_EXEC) write auth/jwt/config \
		jwt_validation_pubkeys="$$PEM" \
		bound_issuer="$$ISSUER"
	@echo "JWT auth configured with static public key"
	@echo "Configuring OIDC auth with Dex..."
	@# Dex has docker network alias dex.default.svc.cluster.local — Vault resolves it via docker DNS
	@$(E2E_VAULT_EXEC) write auth/oidc/config \
		oidc_discovery_url="http://dex.default.svc.cluster.local:5556" \
		bound_issuer="http://dex.default.svc.cluster.local:5556"
	@echo "OIDC auth configured with Dex"

.PHONY: e2e-build-operator
e2e-build-operator: ## Build operator docker image
	docker build -t $(E2E_OPERATOR_IMAGE) .

.PHONY: e2e-import-operator
e2e-import-operator: ## Import operator image into k3s containerd
	docker save $(E2E_OPERATOR_IMAGE) | \
		$(E2E_COMPOSE) exec -T k3s ctr --namespace k8s.io images import -

# cert-manager version for E2E webhook testing
CERT_MANAGER_VERSION ?= v1.14.4

.PHONY: e2e-install-cert-manager
e2e-install-cert-manager: e2e-check-context ## Install cert-manager for webhook TLS certificates
	@echo "Installing cert-manager $(CERT_MANAGER_VERSION)..."
	$(E2E_KUBECTL) apply -f https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
	@echo "Waiting for cert-manager to be ready..."
	$(E2E_KUBECTL) wait --for=condition=Available deployment \
		-l app.kubernetes.io/instance=cert-manager \
		-n cert-manager --timeout=120s
	@echo "cert-manager is ready"

.PHONY: e2e-deploy-operator
e2e-deploy-operator: e2e-check-context ## Deploy operator via Helm into k3s (without webhooks)
	@# Parse repository and tag from E2E_OPERATOR_IMAGE
	@REPO=$$(echo "$(E2E_OPERATOR_IMAGE)" | sed 's/:.*//'); \
	TAG=$$(echo "$(E2E_OPERATOR_IMAGE)" | sed 's/.*://'); \
	$(E2E_HELM) upgrade --install vault-access-operator ./charts/vault-access-operator \
		--namespace vault-access-operator-system --create-namespace \
		--set image.repository=$$REPO \
		--set image.tag=$$TAG \
		--set image.pullPolicy=Never \
		--set webhook.enabled=false \
		--set 'extraEnv[0].name=OPERATOR_REQUEUE_SUCCESS_INTERVAL' \
		--set 'extraEnv[0].value=30s' \
		--set 'extraEnv[1].name=OPERATOR_MIN_SCAN_INTERVAL' \
		--set 'extraEnv[1].value=15s' \
		--wait --timeout 5m
	$(E2E_KUBECTL) wait --for=condition=Available deployment \
		-l app.kubernetes.io/name=vault-access-operator \
		-n vault-access-operator-system --timeout=120s

.PHONY: e2e-deploy-operator-with-webhooks
e2e-deploy-operator-with-webhooks: e2e-check-context e2e-install-cert-manager ## Deploy operator with webhooks enabled (requires cert-manager)
	@# Parse repository and tag from E2E_OPERATOR_IMAGE
	@REPO=$$(echo "$(E2E_OPERATOR_IMAGE)" | sed 's/:.*//'); \
	TAG=$$(echo "$(E2E_OPERATOR_IMAGE)" | sed 's/.*://'); \
	$(E2E_HELM) upgrade --install vault-access-operator ./charts/vault-access-operator \
		--namespace vault-access-operator-system --create-namespace \
		--set image.repository=$$REPO \
		--set image.tag=$$TAG \
		--set image.pullPolicy=Never \
		--set webhook.enabled=true \
		--set 'extraEnv[0].name=OPERATOR_REQUEUE_SUCCESS_INTERVAL' \
		--set 'extraEnv[0].value=30s' \
		--set 'extraEnv[1].name=OPERATOR_MIN_SCAN_INTERVAL' \
		--set 'extraEnv[1].value=15s' \
		--wait --timeout 5m
	$(E2E_KUBECTL) wait --for=condition=Available deployment \
		-l app.kubernetes.io/name=vault-access-operator \
		-n vault-access-operator-system --timeout=120s
	@echo "Operator deployed with webhooks enabled"

##@ E2E Local Development (Composite)

.PHONY: e2e-local-up
e2e-local-up: ## Set up full local E2E stack (k3s + Vault + Dex + operator, no webhooks)
e2e-local-up: e2e-compose-up e2e-wait-cluster e2e-deploy-vault-rbac e2e-bridge-vault e2e-bridge-dex e2e-configure-vault e2e-build-operator e2e-import-operator e2e-deploy-operator

.PHONY: e2e-local-up-with-webhooks
e2e-local-up-with-webhooks: ## Set up full local E2E stack with webhooks enabled (includes cert-manager)
e2e-local-up-with-webhooks: e2e-compose-up e2e-wait-cluster e2e-deploy-vault-rbac e2e-bridge-vault e2e-bridge-dex e2e-configure-vault e2e-build-operator e2e-import-operator e2e-deploy-operator-with-webhooks
	@echo ""
	@echo "========================================"
	@echo "  E2E stack is ready!"
	@echo "========================================"
	@echo ""
	@echo "  KUBECONFIG: export KUBECONFIG=$(E2E_KUBECONFIG)"
	@echo ""
	@echo "  Run tests:   make e2e-local-test"
	@echo "  Status:      make e2e-local-status"
	@echo "  Tear down:   make e2e-local-down"
	@echo ""

.PHONY: e2e-local-down
e2e-local-down: ## Tear down local E2E stack
	-$(E2E_HELM) uninstall vault-access-operator -n vault-access-operator-system 2>/dev/null
	$(MAKE) e2e-compose-down

.PHONY: e2e-local-status
e2e-local-status: ## Show status of local E2E stack
	@$(E2E_COMPOSE) ps
	@echo ""
	@$(E2E_KUBECTL) get pods -A 2>/dev/null || echo "k3s not ready"

.PHONY: e2e-local-test
e2e-local-test: ## Run all E2E tests against local stack
	KUBECONFIG=$(E2E_KUBECONFIG) VAULT_ADDR=http://localhost:8200 \
		E2E_K8S_HOST=https://k3s:6443 \
		E2E_OPERATOR_IMAGE=$(E2E_OPERATOR_IMAGE) \
		E2E_SKIP_BUILD=true E2E_SKIP_IMAGE_LOAD=true \
		go test ./test/e2e/ -v -ginkgo.v -ginkgo.fail-fast -timeout 10m

.PHONY: e2e-local-test-auth
e2e-local-test-auth: ## Run auth E2E tests only
	KUBECONFIG=$(E2E_KUBECONFIG) VAULT_ADDR=http://localhost:8200 \
		E2E_K8S_HOST=https://k3s:6443 \
		E2E_OPERATOR_IMAGE=$(E2E_OPERATOR_IMAGE) \
		E2E_SKIP_BUILD=true E2E_SKIP_IMAGE_LOAD=true \
		go test ./test/e2e/ -v -ginkgo.v -ginkgo.fail-fast -ginkgo.label-filter="auth" -timeout 10m

.PHONY: e2e-local-test-modules
e2e-local-test-modules: ## Run module E2E tests only
	KUBECONFIG=$(E2E_KUBECONFIG) VAULT_ADDR=http://localhost:8200 \
		E2E_K8S_HOST=https://k3s:6443 \
		E2E_OPERATOR_IMAGE=$(E2E_OPERATOR_IMAGE) \
		E2E_SKIP_BUILD=true E2E_SKIP_IMAGE_LOAD=true \
		go test ./test/e2e/ -v -ginkgo.v -ginkgo.fail-fast -ginkgo.label-filter="module || setup" -timeout 15m

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	$(GOLANGCI_LINT) config verify

##@ Integration Tests (testcontainers-go)

INTEGRATION_TIMEOUT ?= 10m
PROFILING_OUTPUT ?= reports/profiling

.PHONY: test-integration
test-integration: manifests generate setup-envtest ## Run integration tests (requires Docker for Vault containers)
	@echo "Running integration tests..."
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test -tags=integration ./test/integration/... -v -timeout $(INTEGRATION_TIMEOUT)

.PHONY: test-integration-parallel
test-integration-parallel: manifests generate setup-envtest ## Run integration tests with Ginkgo parallelism
	@echo "Running integration tests with Ginkgo parallelism..."
	@command -v ginkgo >/dev/null 2>&1 || go install github.com/onsi/ginkgo/v2/ginkgo@latest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" ginkgo -v -p --tags=integration --timeout=$(INTEGRATION_TIMEOUT) ./test/integration/...

.PHONY: test-security
test-security: manifests generate setup-envtest ## Run security-focused integration tests
	@echo "Running security tests..."
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test -tags=integration ./test/integration/security/... -v -timeout $(INTEGRATION_TIMEOUT) --ginkgo.label-filter="security"

.PHONY: test-integration-profiled
test-integration-profiled: manifests generate setup-envtest ## Run integration tests with CPU/memory profiling
	@echo "Running integration tests with profiling..."
	@mkdir -p $(PROFILING_OUTPUT)
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" INTEGRATION_PROFILING=true go test -tags=integration ./test/integration/... -v -timeout $(INTEGRATION_TIMEOUT)

.PHONY: test-integration-report
test-integration-report: test-integration-profiled ## Run profiled tests and generate HTML report
	@echo "Opening profiling report..."
	@if [ -f $(PROFILING_OUTPUT)/summary.html ]; then \
		echo "Report available at: $(PROFILING_OUTPUT)/summary.html"; \
	else \
		echo "No report generated. Check test output for errors."; \
	fi

.PHONY: testcontainers-cleanup
testcontainers-cleanup: ## Clean up orphaned testcontainers
	@echo "Cleaning up testcontainers..."
	@docker ps -a --filter "label=org.testcontainers" -q | xargs -r docker rm -f || true
	@docker network ls --filter "label=org.testcontainers" -q | xargs -r docker network rm || true

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name vault-access-operator-builder
	$(CONTAINER_TOOL) buildx use vault-access-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm vault-access-operator-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.18.0
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
GOLANGCI_LINT_VERSION ?= v2.8.0

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@$(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: operator-sdk
OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk
operator-sdk: ## Download operator-sdk locally if necessary.
ifeq (,$(wildcard $(OPERATOR_SDK)))
ifeq (, $(shell which operator-sdk 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPERATOR_SDK)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$${OS}_$${ARCH} ;\
	chmod +x $(OPERATOR_SDK) ;\
	}
else
OPERATOR_SDK = $(shell which operator-sdk)
endif
endif

.PHONY: bundle
bundle: manifests kustomize operator-sdk ## Generate bundle manifests and metadata, then validate generated files.
	$(OPERATOR_SDK) generate kustomize manifests -q
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/manifests | $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	$(CONTAINER_TOOL) build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

.PHONY: opm
OPM = $(LOCALBIN)/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.55.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool $(CONTAINER_TOOL) --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)

##@ Pre-commit

.PHONY: pre-commit-install
pre-commit-install: ## Install pre-commit hooks
	@command -v pre-commit >/dev/null 2>&1 || { echo "Installing pre-commit..."; pip install pre-commit; }
	pre-commit install

.PHONY: pre-commit-run
pre-commit-run: ## Run pre-commit on all files
	pre-commit run --all-files

.PHONY: pre-commit-update
pre-commit-update: ## Update pre-commit hooks to latest versions
	pre-commit autoupdate
