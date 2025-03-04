# NetBird Kubernetes Operator
For easily provisioning access to Kubernetes resources using NetBird.

## Description

This operator enables easily provisioning NetBird access on kubernetes clusters, allowing users to access internal resources directly.

## Getting Started

### Prerequisites
- helm version 3+
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
- (Optional for Helm chart installation) Cert Manager.

### To Deploy on the cluster

**Using the install.yaml**

```sh
kubectl create namespace netbird
kubectl apply -n netbird -f https://github.com/netbirdio/kubernetes-operator/releases/latest/manifests/install.yaml
```

**Using the Helm Chart**

```sh
helm repo add netbirdio https://netbirdio.github.io/kubernetes-operator
helm install -n netbird kubernetes-operator netbirdio/kubernetes-operator
```

For more options, check the default values by running
```sh
helm show values netbirdio/kubernetes-operator
```

### To Uninstall
**Using install.yaml**

```sh
kubectl delete -n netbird -f https://github.com/netbirdio/kubernetes-operator/releases/latest/manifests/install.yaml
kubectl delete namespace netbird
```

**Using helm**

```sh
helm uninstall -n netbird kubernetes-operator
```

### Provision pods with NetBird access

1. Create a Setup Key in your [NetBird console](https://docs.netbird.io/how-to/register-machines-using-setup-keys#using-setup-keys).
1. Create a Secret object in the namespace where you need to provision NetBird access (secret name and field can be anything).
```yaml
apiVersion: v1
stringData:
  setupkey: EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE
kind: Secret
metadata:
  name: test
```
1. Create an NBSetupKey object referring to your secret.
```yaml
apiVersion: netbird.io/v1
kind: NBSetupKey
metadata:
  name: test
spec:
  # Optional, overrides management URL for this setupkey only
  # defaults to https://api.netbird.io
  managementURL: https://netbird.example.com 
  secretKeyRef:
    name: test # Required
    key: setupkey # Required
```
1. Annotate the pods you need to inject NetBird into with `netbird.io/setup-key`.
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment
spec:
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
      annotations:
        netbird.io/setup-key: test # Must match the name of an NBSetupKey object in the same namespace
    spec:
      containers:
      - image: yourimage
        name: container

```

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