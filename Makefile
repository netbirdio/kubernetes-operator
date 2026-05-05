# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

GOARCH = $(shell go env GOARCH)
ifeq (,$(shell go env GOBIN))
GOBIN = $(shell go env GOPATH)/bin
else
GOBIN = $(shell go env GOBIN)
endif

IMG_REGISTRY ?= ghcr.io
IMG_REPOSITORY ?= netbirdio/netbird-operator
IMG_TAG ?= dev
IMG_REF := $(IMG_REGISTRY)/$(IMG_REPOSITORY):$(IMG_TAG)

.PHONY: generate
generate: api/v1/zz_generated.deepcopy.go api/v1alpha1/zz_generated.deepcopy.go pkg/applyconfigurations charts/netbird-operator/crds docs/api-reference.md

api/v1/zz_generated.deepcopy.go api/v1alpha1/zz_generated.deepcopy.go: $(shell find api -not -name 'zz_generated*') hack/boilerplate.go.txt
	@go tool controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."

pkg/applyconfigurations: $(shell find api -not -name 'zz_generated*') hack/boilerplate.go.txt
	@go tool controller-gen applyconfiguration:headerFile="hack/boilerplate.go.txt" object:headerFile="hack/boilerplate.go.txt" paths="./..."
	@touch pkg/applyconfigurations

charts/netbird-operator/crds: $(shell find api)
	@go tool controller-gen crd paths="./..." output:crd:artifacts:config=charts/netbird-operator/crds
	@touch charts/netbird-operator/crds

docs/api-reference.md: $(shell find api) docs/.crd-ref-docs.yaml
	@go tool crd-ref-docs --log-level error --output-path docs/api-reference.md --renderer markdown --source-path api/v1alpha1 --config docs/.crd-ref-docs.yaml

.PHONY: lint
lint:
	@golangci-lint run ./...

.PHONY: test
test: setup-envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test -v $$(go list ./... | grep -v /e2e) -coverprofile cover.out

test-e2e: build-image
	cd ./test/e2e && IMG_REF=${IMG_REF} go test ./... -v -count 1

.PHONY: build
build: generate bin/linux-$(GOARCH)/netbird-operator

bin/linux-%/netbird-operator: $(shell find api cmd internal pkg) go.mod go.sum
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags="-w -s" -trimpath -o $@ cmd/main.go

.PHONY: build-image
build-image: build
	@DOCKER_BUILDKIT=1 docker build -t ${IMG_REF} .
	@echo ${IMG_REF}

.PHONY: build-image-multiarch
build-image-multiarch: generate bin/linux-amd64/netbird-operator bin/linux-arm64/netbird-operator
	@DOCKER_BUILDKIT=1 docker build --platform linux/amd64,linux/arm64 -t ${IMG_REF} .
	@echo ${IMG_REF}

## Generate a consolidated YAML with CRDs and deployment.
.PHONY: build-installer
build-installer: generate
	mkdir -p manifests
	helm template --include-crds netbird-operator charts/netbird-operator > manifests/install.yaml

##@ Deployment

.PHONY: install
install: generate
	kubectl apply --server-side -f charts/netbird-operator/crds

.PHONY: uninstall
uninstall:
	kubectl delete -f charts/netbird-operator/crds

run: install
	kubectl create namespace netbird --dry-run=client -o yaml | kubectl apply -f -
	go run cmd/main.go --enable-webhooks=false --netbird-api-key=$${NB_API_KEY}  --runtime-namespace netbird

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
ENVTEST ?= $(LOCALBIN)/setup-envtest

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')

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
