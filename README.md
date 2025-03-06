# NetBird Kubernetes Operator
For easily provisioning access to Kubernetes resources using NetBird.

https://github.com/user-attachments/assets/5472a499-e63d-4301-a513-ad84cfe5ca7b

## Description

This operator easily provides NetBird access on Kubernetes clusters, allowing users to access internal resources directly.

## Getting Started

### Prerequisites
- (Recommended) helm version 3+
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
- (Recommended) Cert Manager.


### Deployment
> [!NOTE]
> Helm Installation method is recommended due to the automation of multiple settings within the deployment.

#### Using Helm

1. Add helm repository.
```sh
helm repo add netbirdio https://netbirdio.github.io/kubernetes-operator
```
2. (Recommended) Install [cert-manager](https://cert-manager.io/docs/installation/#default-static-install) for k8s API to communicate with the NetBird operator.
```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.0/cert-manager.yaml
```
3. Add NetBird API token
```shell
kubectl create namespace netbird
kubectl -n netbird create secret generic netbird-mgmt-api-key --from-literal=NB_API_KEY=$(cat ~/nb-pat.secret)
```
4. (Recommended) Create a [`values.yaml`](examples/ingress/values.yaml) file, check `helm show values netbirdio/kubernetes-operator` for more info.
5. Install using `helm install --create-namespace -f values.yaml -n netbird netbird-operator netbirdio/kubernetes-operator`.
6. (Recommended) Check pod status using `kubectl get pods -n netbird`.
6. (Optional) Create an [`exposed-nginx.yaml`](examples/ingress/exposed-nginx.yaml) file to create a Nginx service for testing.
7. (Optional) Apply the Nginx service:
```sh
kubectl apply -f exposed-nginx.yaml
```

> Learn more about the values.yaml options [here](helm/kubernetes-operator/values.yaml) and  [Granting controller access to NetBird Management](docs/usage.md#granting-controller-access-to-netbird-management).
#### Using install.yaml

> [!IMPORTANT]
> install.yaml only includes a very basic template for deploying a stripped-down version of Kubernetes-operator.
> This excludes any and all configurations for ingress capabilities and requires the cert-manager to be installed.

```sh
kubectl create namespace netbird
kubectl apply -n netbird -f https://raw.githubusercontent.com/netbirdio/kubernetes-operator/refs/heads/main/manifests/install.yaml
```

### Version
We have developed and executed tests against Kubernetes v1.31, but it should work with most recent Kubernetes version.

Latest operator version: v0.1.1.

Tested against:
|Distribution|Test status|Kubernetes Version|
|---|---|---|
|Google GKE|Pass|1.31.5|
|AWS EKS|Pass|1.31|
|Azure AKS|Not tested|N/A|
|OpenShift|Not tested|N/A|

> We would love community feedback to improve the test matrix. Please submit a PR with your test results.

### Usage

Check the usage of [usage.md](docs/usage.md) and examples.

## Contributing

### Prerequisites

To be able to develop this project, you need to have the following tools installed:

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