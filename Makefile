# Image URL to use all building/pushing image targets
IMG ?= docker.io/netbirdio/kubernetes-operator:latest

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
test: generate manifests
	LOCALBIN=$(shell pwd)/bin
	echo $$LOCALBIN
	exit 1
	mkdir -p ${LOCALBIN}
	ENVTEST_K8S_VERSION=$(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
	@go tool setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}
	KUBEBUILDER_ASSETS="$(shell go tool setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test -v $$(go list ./... | grep -v /e2e) -coverprofile cover.out

.PHONY: test-e2e
test-e2e: generate manifests
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
build: generate manifests
	go build -o bin/manager cmd/main.go

.PHONY: run
run: generate manifests
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
