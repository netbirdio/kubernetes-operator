# Usage

## Provision pods with NetBird access using side-cars

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
kind: Deployment
...
spec:
...
  template:
    metadata:
      annotations:
        netbird.io/setup-key: test # Must match the name of an NBSetupKey object in the same namespace
...
    spec:
      containers:
...
```

Since v0.27.0, NetBird supports extra DNS labels, which extends the DNS names that you can link to peers by grouping them and load balancing access using DNS round-robin. To enable this feature, add the following annotation to the pod:
```yaml
    netbird.io/extra-dns-labels: "label1,label2"
```
With this setup, all peers with the same extra label would be used in a DNS round-robin fashion.

## Provisioning Networks (Ingress Functionality)

### Granting controller access to NetBird Management

> [!IMPORTANT]
> The NetBird Kubernetes operator generates configurations using NetBird API; editing or deleting these configurations in the NetBird console may cause temporary network disconnection until the operator reconciles the configuration.

1. Create a Service User on your NetBird dashboard (Must be Admin). [Doc](https://docs.netbird.io/how-to/access-netbird-public-api#creating-a-service-user).
1. Create an access token for the Service User (Must be Admin). [Doc](https://docs.netbird.io/how-to/access-netbird-public-api#creating-a-service-user).
1. Add access token to your helm values file under `netbirdAPI.key`.
    1. Alternatively, provision secret in the same namespace as the operator and set the key `NB_API_KEY` to the access token generated.
    1. Set `netbirdAPI.keyFromSecret` to the name of the secret created.
1. Set `ingress.enabled` to `true`.
    1. Optionally, to provision the network immediately, set `ingress.router.enabled` to `true`.
    1. Optionally, to provision 1 network per namespace, set `ingress.namespacedNetworks` to `true`.
1. Run `helm install` or `helm upgrade`.

Minimum values.yaml example:
```yaml
netbirdAPI:
  key: "nbp_XXxxxxxxXXXXxxxxXXXXXxxx"

ingress:
  enabled: true
cluster:
  name: kubernetes
```
> Learn more about the values.yaml options [here](../helm/kubernetes-operator/values.yaml).

### Exposing Kubernetes API

1. Ensure Ingress functionality is enabled.
1. Set `ingress.kubernetesAPI.enabled` to true.
1. Set `ingress.kubernetesAPI.groups` to a list of groups to assign to the Network Resource to be created for kubernetes API.
1. Set `ingress.kubernetesAPI.policies` to a list of policy names to connect to the resource (See #managing-policies for more details).
1. Apply Helm changes through `helm upgrade`.
1. Replace the server URL in your kubeconfig file with `https://kubernetes.default.<cluster DNS>` (by default `https://kubernetes.default.svc.cluster.local`), for example:
```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /home/user/.minikube/ca.crt
    server: https://kubernetes.default.svc.cluster.local
  name: minikube
```

### Exposing a Service

> [!IMPORTANT]  
> Ingress DNS Resolution requires DNS Wildcard Routing to be enabled and at least one DNS Nameserver configured for clients.

|Annotation|Description|Default|Valid Values|
|---|---|---|---|
|`netbird.io/expose`| Expose service using NetBird Network Resource ||(`null`, `true`)|
|`netbird.io/groups`| Comma-separated list of group names to assign to Network Resource |`{ClusterName}-{Namespace}-{Service}`|Any comma-separated list of strings.|
|`netbird.io/resource-name`| Network Resource name |`{Namespace}-{Service}`|Any valid network resource name, make sure they're unique!|
|`netbird.io/policy`| Name(s) of NBPolicy to propagate service ports as destination. ||Comma-separated list of names of any NBPolicy resource|
|`netbird.io/policy-ports`| Narrow down exposed ports in a policy. Leave empty for all ports. ||Comma-separated integer list, integers must be between 0-65535|
|`netbird.io/policy-protocol`| Narrow down protocol for use in a policy. Leave empty for all protocols. ||(`tcp`,`udp`)|
|`netbird.io/policy-source-groups`| Specify source groups for auto-generated policies. Required for auto-generating policies||Any comma-separated list of strings.|
|`netbird.io/policy-name`| Specify human-friendly names for auto-generated policies. ||comma-separated list of `policy:friendly-name`, where policy is the name of the kubernetes object.|

Example service:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 0
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:latest
          ports:
            - containerPort: 80

---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
  annotations:
    netbird.io/expose: "true"
    netbird.io/groups: "groupA,groupB"
spec:
  selector:
    app: nginx
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 80
  type: ClusterIP
```
### Notes
* `netbird.io/expose` will interpret any string as a `true` value; the only `false` value is `null`.
* The operator does **not** handle duplicate resource names within the same network, it is up to you to ensure resource names are unique within the same network.
* While the NetBird console will allow group names to contain commas, this is not allowed in `netbird.io/groups` annotation as commas are used as separators.
* If a group already exists on NetBird console with the same name, NetBird Operator will use that group ID instead of creating a new group.
* NetBird Operator will attempt to clean up any resources created, including groups created for resources.
    * If a group is used by resources that the operator cannot clean up, the operator will eventually ignore the group in NetBird.
    * It's recommended that unique groups be used per NetBird Operator installation to remove any possible conflicts.
* The Operator does not validate service annotations on updates, as this may cause unnecessary overhead on any Service update.

### Managing Policies

Policies can be either created through the Helm chart or they can be auto-generated from Service annotation definitions.

#### Helm

Simply add policies under `ingress.policies`, for example:
1. Add the following configuration in your `values.yaml` file.
```yaml
ingress:
  policies:
    default:
      name: Kubernetes Default Policy # Required, name of policy in NetBird console
      description: Default # Optional
      sourceGroups: # Required, name of groups to assign as source in Policy.
      - All
      ports: # Optional, resources annotated 'netbird.io/policy=default' will append to this.
      - 443
      protocols: # Optional, restricts protocols allowed to resources, defaults to ['tcp', 'udp'].
      - tcp
      - udp
      bidirectional: true # Optional, defaults to true
```
2. Reference policies in Services using `netbird.io/policy=default,otherpolicy,...`, this will add relevant ports and destination groups to policies.
3. (Optional) Limit specific ports in exposed service by adding `netbird.io/policy-ports=443`.
4. (Optional) Limit specific protocol in exposed service by adding `netbird.io/policy-protocol=tcp`.

#### Auto-Generated Policies

1. Ensure `ingress.allowAutomaticPolicyCreation` is set to true in the Helm chart and apply.
2. Annotate a service with `netbird.io/policy` with the name of the policy as a kubernetes object, for example `netbird.io/policy: default`. This will create an NBPolicy with the name `default-<Service Namespace>-<Service Name>`.
3. Annotate the same service with `netbird.io/policy-source-groups` with a comma-separated list of group names to allow as a source, for example `netbird.io/policy-source-groups: dev`.
4. (Optional) Annotate the service with `netbird.io/policy-name` for a human-friendly name, for example `netbird.io/policy-name: "default:Default policy for kubernetes cluster"`.

#### Notes on Policies
* Each NBPolicy will only create policies in the NetBird console when the information provided is enough to create one. If no services act as a destination or specified services do not conform to the protocol(s) defined, the policy will not be created.
* Each NBPolicy will create one policy in the NetBird console per protocol specified as long as the protocol has destinations; this ensures better-secured policies by separating ports for TCP and UDP.
* Policies currently do not support ICMP protocol, as ICMP is not supported in Kubernetes services, and there are [no current plans to support it](https://discuss.kubernetes.io/t/icmp-support-for-kubernetes-service/21738).
* NetBird currently does not support SCTP protocol.
