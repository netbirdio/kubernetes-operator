s# NetBird Kubernetes Operator

The NetBird Kubernetes Operator automates the provisioning of NetBird network access for services running in your cluster. It extends the Kubernetes API with CRDs, letting you manage NetBird peers, routes, and groups declaratively, the same way you manage the rest of your infrastructure.

# Features

* Declarative peer management - define NetBird peers as Kubernetes resources and let the operator handle provisioning and lifecycle
* Automatic secret management - setup keys and credentials are stored and rotated as Kubernetes secrets
* Namespace-scoped or cluster-wide - deploy per-namespace for multi-tenant clusters or cluster-wide for full coverage
* Works with any NetBird deployment - compatible with NetBird Cloud and self-hosted instances

## Getting Started

For full setup instructions, see the [Getting Started](https://docs.netbird.io/manage/integrations/kubernetes) documentation.

Once your secret is configured, install the operator with Helm.

```shell
helm upgrade --install --create-namespace -n netbird netbird-operator oci://ghcr.io/netbirdio/helm-charts/netbird-operator
```

## API

| Kind | API Version |
|------|-------------|
| [Group](docs/api-reference.md#group) | `netbird.io/v1alpha1` |
| [NetworkResource](docs/api-reference.md#networkresource) | `netbird.io/v1alpha1` |
| [NetworkRouter](docs/api-reference.md#networkrouter) | `netbird.io/v1alpha1` |
| [SetupKey](docs/api-reference.md#setupkey) | `netbird.io/v1alpha1` |
| [SidecarProfile](docs/api-reference.md#sidecarprofile) | `netbird.io/v1alpha1` |
| [ClusterProxy](docs/api-reference.md#clusterproxy) | `netbird.io/v1alpha1` |
