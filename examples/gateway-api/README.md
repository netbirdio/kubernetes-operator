# Gateway API

This example walks you through how to setup a Netbird Gateway API and expose Nginx through the Netbird proxy service.

Build image locally and load it into Kind.
```shell
make docker-build IMG=docker.io/netbirdio/kubernetes-operator:dev
kind load docker-image docker.io/netbirdio/kubernetes-operator:dev
```

Install the Gateway API CRDs.

```shell
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/experimental-install.yaml
```

Create Netbird namespace and API key secret.

```shell
kubectl create namespace netbird
kubectl -n netbird create secret generic netbird-mgmt-api-key --from-literal NB_API_KEY=${NETBIRD_API_KEY}
```

Install the Kubernetes Operator. Make sure to use the customized values to enable Gateway API support. This assumes you have already created a secret containing a Netbird API key.

```shell
helm upgrade --install --create-namespace -f ./examples/gateway-api/values.yaml -n netbird netbird-operator ./helm/kubernetes-operator
```

Create the gateway along with the routing peer. This will deploy Netbird clients that route traffic into the cluster.

```shell
kubectl apply -f ./examples/gateway-api/gateway.yaml
```

Deploy the test Nginx application along with a HTTPRoute. The HTTPRoute will expose the service through Netbirds public proxy.

```shell
kubectl apply -f ./examples/gateway-api/nginx.yaml
```

Expose the Kubernetes API server service as a network resource in Netbird.

```shell
kubectl apply -f ./examples/gateway-api/kubernetes.yaml
```
