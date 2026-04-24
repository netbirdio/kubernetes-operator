# Getting Started

## Prerequisites

- A NetBird [service user access token](https://docs.netbird.io/manage/public-api).
- Access to Kubernetes cluster.
- Kubectl and Helm installed locally.

## Steps

Add the Helm repository.

```sh
helm repo add netbirdio https://netbirdio.github.io/kubernetes-operator
```

Install cert-manager, it is recommended so the Kubernetes API can communicate with the operator's admission webhooks. Skip this step if you already have cert-manager installed.

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.0/cert-manager.yaml
```

Create the NetBird namespace and API secret. The operator needs a NetBird personal access token to authenticate with the NetBird Management API.

```sh
kubectl create namespace netbird
kubectl -n netbird create secret generic netbird-mgmt-api-key --from-literal=NB_API_KEY=${ACCESS_TOKEN}
```

Install the Netbird operator.

```sh
helm install netbird-operator netbirdio/kubernetes-operator --create-namespace --namespace netbird
```

Verify the installation. All pods should be in a `Running` state before continuing.

```sh
kubectl get pods -n netbird
```

Once the operator is running, see the [usage guide](/docs/usage.md) to start exposing services to your NetBird network.
