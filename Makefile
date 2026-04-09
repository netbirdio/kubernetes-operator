# Image URL to use all building/pushing image targets
IMG ?= docker.io/netbirdio/kubernetes-operator:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ Development

## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
.PHONY: manifests
manifests:
	go tool controller-gen crd paths="./..." output:crd:artifacts:config=helm/kubernetes-operator/crds

## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
.PHONY: generate
generate:
	go tool controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: test
test: manifests setup-envtest
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test -v $$(go list ./... | grep -v /e2e) -coverprofile cover.out

.PHONY: test-e2e
test-e2e: manifests
	@command -v kind >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@kind get clusters | grep -q 'kind' || { \
		echo "No Kind cluster is running. Please start a Kind cluster before running the e2e tests."; \
		exit 1; \
	}
	go test ./test/e2e/ -v -ginkgo.v

.PHONY: lint
lint:
	@golangci-lint run ./...

##@ Build

.PHONY: build
build: manifests
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests
	go run ./cmd/main.go

.PHONY: docker-build
docker-build:
	docker build -t ${IMG} .

## Generate a consolidated YAML with CRDs and deployment.
.PHONY: build-installer
build-installer: manifests
	mkdir -p manifests
	helm template --include-crds kubernetes-operator helm/kubernetes-operator > manifests/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

## Install CRDs into the K8s cluster specified in ~/.kube/config.
.PHONY: install
install: manifests
	kubectl apply -f helm/kubernetes-operator/crds

## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
.PHONY: uninstall
uninstall: manifests
	kubectl delete -f helm/kubernetes-operator/crds

## Deploy controller to the K8s cluster specified in ~/.kube/config.
.PHONY: deploy
deploy: manifests
	helm install -n netbird --create-namespace kubernetes-operator --set operator.image.tag=$(word 2,$(subst :, ,${IMG})) helm/kubernetes-operator

## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
.PHONY: undeploy
undeploy:
	helm uninstall -n netbird kubernetes-operator

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
