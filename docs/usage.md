# Usage

## Provision pods with NetBird access

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

## Provisioning Networks (Ingress Functionality)

### Granting controller access to NetBird Management

> [!IMPORTANT]
> NetBird kubernetes operator generates configurations using NetBird API, editing or deleting these configurations in the NetBird console may cause temporary network disconnection until the operator reconciles the configuration.

1. Create a Service User on your NetBird dashboard (Must be Admin). [Doc](https://docs.netbird.io/how-to/access-netbird-public-api#creating-a-service-user).
1. Create access token for the Service User (Must be Admin). [Doc](https://docs.netbird.io/how-to/access-netbird-public-api#creating-a-service-user).
1. Add access token to your helm values file under `netbirdAPI.key`.
    1. Alternatively, provision secret in the same namespace as the operator and set the key `NB_API_KEY` to the access token generated.
    1. Set `netbirdAPI.keyFromSecret` to the name of the secret created.
1. Set `ingress.enabled` to `true`.
    1. Optionally, to provision network immediately, set `ingress.router.enabled` to `true`.
    1. Optionally, to provision 1 network per kubernetes namespace, set `ingress.namespacedNetworks` to `true`.
1. Run `helm install` or `helm upgrade`.

### Exposing a Service

> [!IMPORTANT]  
> Ingress DNS Resolution requires DNS Wildcard Routing to be enabled, and at least one DNS Nameserver configured for clients.

|Annotation|Description|Default|Valid Values|
|---|---|---|---|
|`netbird.io/expose`|Expose service using NetBird Network Resource||(`null`, `true`)|
|`netbird.io/groups`|Comma-separated list of group names to assign to Network Resource|`{ClusterName}-{Namespace}-{Service}`|Any comma-separated list of strings.|
|`netbird.io/resource-name`|Network Resource name|`{Namespace}-{Service}`|Any valid network resource name, make sure they're unique!|
|`netbird.io/policy`|Name of NBPolicy to propagate service ports as destination.||Name of any NBPolicy resource|
|`netbird.io/policy-ports`|Narrow down exposed ports in policy, leave empty for all ports.||Comma-separated integer list, integers must be between 0-65535|
|`netbird.io/policy-protocol`|Narrow down protocol for use in policy, leave empty for all protocols.||(`tcp`,`udp`)|

### Notes
* `netbird.io/expose` will interpret any string as true value, the only false value is `null`.
* The operator does **not** handle duplicate resource names within the same network, it is up to you to ensure resource names are unique within the same network.
* While the NetBird console will allow group names to contain commas, this is not allowed in `netbird.io/groups` annotation as commas are used as separators.
* If a group already exists on NetBird console with the same name, NetBird Operator will use that group ID instead of creating a new group.
* NetBird Operator will attempt to clean up any resources created, including groups created for resources.
    * In case a group is used by resources that cannot be cleaned up by the operator, the operator will eventually ignore the group in NetBird.
    * It's recommended to use unique groups per NetBird Operator installation to remove any possible conflicts.
* NetBird Operator does not validate service annotations on update, as this may cause unnecessary overhead on any Service update.

### Managing Policies

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
2. Reference policy in Services using `netbird.io/policy=default`, this will add relevant ports and destination groups to Policy.
3. (Optional) limit specific ports in exposed service by adding `netbird.io/policy-ports=443`.
4. (Optional) limit specific protocol in exposed service by adding `netbird.io/policy-protocol=tcp`.

#### Notes
* Each NBPolicy will only create policies in NetBird console when information provided is enough to create one. If there are no services acting as destination, or specified services do not conform to the protocol(s) defined, policy will not be created.
* Each NBPolicy will create one Policy in NetBird console per protocol specified as long as protocol has destinations, this ensures better secured policies by separating ports for TCP and UDP.
* Policies currently do not support ICMP protocol, as ICMP is not supported in kubernetes services, and there are [no current plans to support it](https://discuss.kubernetes.io/t/icmp-support-for-kubernetes-service/21738).
