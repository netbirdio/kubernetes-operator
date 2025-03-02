# NetBird Kubernetes Operator
For easily provisioning access to Kubernetes resources using NetBird.

https://github.com/user-attachments/assets/5472a499-e63d-4301-a513-ad84cfe5ca7b

## Description

This operator enables easily provisioning NetBird access on kubernetes clusters, allowing users to access internal resources directly.

## Getting Started

### Prerequisites
- (Recommended) helm version 3+
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
- (Recommended) Cert Manager.


### Deployment
> [!NOTE]
> Helm Installation method is recommended due to automation of multiple settings within the deployment.

#### Using Helm

1. Add helm repository.
```sh
helm repo add netbirdio https://netbirdio.github.io/kubernetes-operator
```
2. (Recommended) Install [cert-manager](https://cert-manager.io/docs/installation/#default-static-install).
1. (Recommended) Create a values.yaml file, check `helm show values netbirdio/kubernetes-operator` for more info.
1. Install using `helm install --create-namespace -f values.yaml -n netbird netbird-operator netbirdio/kubernetes-operator`.

#### Using install.yaml

> [!IMPORTANT]
> install.yaml only includes a very basic template for deploying a stripped down version of kubernetes-operator.
> This excludes any and all configuration for ingress capabilities, and requires cert-manager to be installed.

```sh
kubectl create namespace netbird
kubectl apply -n netbird -f https://raw.githubusercontent.com/netbirdio/kubernetes-operator/refs/heads/main/manifests/install.yaml
```

### Usage

Checks [usage.md](docs/usage.md).

## Contributing

### Prerequisites

To be able to develop on this project, you need to have the following tools installed:

- [Git](https://git-scm.com/).
- [Make](https://www.gnu.org/software/make/).
- [Go programming language](https://golang.org/dl/).
- [Docker CE](https://www.docker.com/community-edition).
- [Kubernetes cluster (v1.16+)](https://kubernetes.io/docs/setup/). [KIND](https://github.com/kubernetes-sigs/kind) is recommended.
- [Kubebuilder](https://book.kubebuilder.io/).

### Running tests

**Running unit tests**
```sh
make test
```

**Running E2E tests**
```sh
kind create cluster # If not already created, you can check with `kind get clusters`
make test-e2e
```