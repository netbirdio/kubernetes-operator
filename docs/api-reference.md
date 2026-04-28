# API Reference

## Packages
- [netbird.io/v1alpha1](#netbirdiov1alpha1)


## netbird.io/v1alpha1

Package v1alpha1 contains API Schema definitions for the  v1alpha1 API group.

### Resource Types
- [Group](#group)
- [NetworkResource](#networkresource)
- [NetworkRouter](#networkrouter)
- [SetupKey](#setupkey)
- [SidecarProfile](#sidecarprofile)



#### ContainerOverride







_Appears in:_
- [SidecarProfileSpec](#sidecarprofilespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `image` _string_ | Image overrides the image used by the client. |  | Optional: \{\} <br /> |
| `env` _[EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#envvar-v1-core) array_ |  |  | Optional: \{\} <br /> |
| `securityContext` _[SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#securitycontext-v1-core)_ |  |  | Optional: \{\} <br /> |


#### CrossNamespaceReference







_Appears in:_
- [NetworkResourceSpec](#networkresourcespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the referent. |  | Required: \{\} <br /> |
| `namespace` _string_ | Namespace of the referent. |  | Required: \{\} <br /> |


#### DNSZoneReference



DNSZoneReference references a Netbird DNS zone by domain name.



_Appears in:_
- [NetworkRouterSpec](#networkrouterspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the domain name of an existing Netbird DNS zone, e.g. "example.com". |  | Required: \{\} <br /> |


#### Group



Group is the Schema for the groups API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `netbird.io/v1alpha1` | | |
| `kind` _string_ | `Group` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  | Optional: \{\} <br /> |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  | Optional: \{\} <br /> |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[GroupSpec](#groupspec)_ |  |  | Required: \{\} <br /> |
| `status` _[GroupStatus](#groupstatus)_ |  | \{ observedGeneration:-1 \} |  |


#### GroupReference







_Appears in:_
- [NetworkResourceSpec](#networkresourcespec)
- [SetupKeySpec](#setupkeyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the group. |  | Optional: \{\} <br /> |
| `id` _string_ | ID is the id of the group. |  | Optional: \{\} <br /> |
| `localRef` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#localobjectreference-v1-core)_ | LocalReference is a reference to a group in the same namespace. |  | Optional: \{\} <br /> |


#### GroupSpec



GroupSpec defines the desired state of Group.



_Appears in:_
- [Group](#group)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the group. |  | MinLength: 1 <br /> |


#### GroupStatus



GroupStatus defines the observed state of Group.



_Appears in:_
- [Group](#group)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last reconciled generation. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Conditions holds the conditions for the Group. |  | Optional: \{\} <br /> |
| `groupID` _string_ | GroupID is the id of the created group. |  | Optional: \{\} <br /> |


#### InjectionMode

_Underlying type:_ _string_

InjectionMode defines how the sidecar is injected into the pod.

_Validation:_
- Enum: [Sidecar Container]

_Appears in:_
- [SidecarProfileSpec](#sidecarprofilespec)

| Field | Description |
| --- | --- |
| `Sidecar` | InjectionModeSidecar injects the client as a sidecar container.<br /> |
| `Container` | InjectionModeContainer injects the client as a regular container.<br /> |


#### NetworkResource



NetworkResource is the Schema for the networkresources API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `netbird.io/v1alpha1` | | |
| `kind` _string_ | `NetworkResource` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  | Optional: \{\} <br /> |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  | Optional: \{\} <br /> |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkResourceSpec](#networkresourcespec)_ |  |  | Required: \{\} <br /> |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  | \{ observedGeneration:-1 \} |  |


#### NetworkResourceSpec



NetworkResourceSpec defines the desired state of NetworkResource.



_Appears in:_
- [NetworkResource](#networkresource)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `networkRouterRef` _[CrossNamespaceReference](#crossnamespacereference)_ | NetworkRouterRef is a reference to the network and router where the resource will be created. |  |  |
| `serviceRef` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#localobjectreference-v1-core)_ | ServiceRef is a reference to the service to expose in the Network. |  |  |
| `groups` _[GroupReference](#groupreference) array_ | Groups are references to groups that the resource will be a part of. |  | Optional: \{\} <br /> |


#### NetworkResourceStatus



NetworkResourceStatus defines the observed state of NetworkResource.



_Appears in:_
- [NetworkResource](#networkresource)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last reconciled generation. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Conditions holds the conditions for the NetworkResource. |  | Optional: \{\} <br /> |
| `networkID` _string_ | NetworkID is the id of the network the resource is created in. |  | Optional: \{\} <br /> |
| `resourceID` _string_ | ResourceID is the id of the created resource. |  | Optional: \{\} <br /> |
| `dnsZoneID` _string_ | DNSZoneID is the id of the zone the DNS record is created in. |  | Optional: \{\} <br /> |
| `dnsRecordID` _string_ | DNSRecordID is the id of the created DNS record. |  | Optional: \{\} <br /> |


#### NetworkRouter



NetworkRouter is the Schema for the networkrouters API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `netbird.io/v1alpha1` | | |
| `kind` _string_ | `NetworkRouter` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  | Optional: \{\} <br /> |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  | Optional: \{\} <br /> |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkRouterSpec](#networkrouterspec)_ |  |  | Required: \{\} <br /> |
| `status` _[NetworkRouterStatus](#networkrouterstatus)_ |  | \{ observedGeneration:-1 \} |  |


#### NetworkRouterSpec



NetworkRouterSpec defines the desired state of NetworkRouter.



_Appears in:_
- [NetworkRouter](#networkrouter)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `dnsZoneRef` _[DNSZoneReference](#dnszonereference)_ | DNSZoneRef is a reference to the DNS zone used to create records for resources. |  | Required: \{\} <br /> |
| `image` _string_ | Netbird client image. |  | Optional: \{\} <br /> |
| `logLevel` _string_ | Log level for Netbird client. |  | Optional: \{\} <br /> |
| `workloadOverride` _[WorkloadOverride](#workloadoverride)_ | WorkloadOverride contains configuration that will override the default workload. |  | Optional: \{\} <br /> |


#### NetworkRouterStatus



NetworkRouterStatus defines the observed state of NetworkRouter.



_Appears in:_
- [NetworkRouter](#networkrouter)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last reconciled generation. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Conditions holds the conditions for the NetworkRouter. |  | Optional: \{\} <br /> |
| `routingPeerID` _string_ | RoutingPeerID is the id of the created routing peer. |  | Optional: \{\} <br /> |
| `networkID` _string_ | NetworkID is the id of the network the routing peer was created in. |  | Optional: \{\} <br /> |


#### SetupKey



SetupKey is the Schema for the setupkeys API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `netbird.io/v1alpha1` | | |
| `kind` _string_ | `SetupKey` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  | Optional: \{\} <br /> |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  | Optional: \{\} <br /> |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SetupKeySpec](#setupkeyspec)_ |  |  | Required: \{\} <br /> |
| `status` _[SetupKeyStatus](#setupkeystatus)_ |  | \{ observedGeneration:-1 \} |  |


#### SetupKeySpec



SetupKeySpec defines the desired state of SetupKey.



_Appears in:_
- [SetupKey](#setupkey)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the setup key. |  | MinLength: 1 <br /> |
| `ephemeral` _boolean_ | Ephemeral decides if peers added with the key are ephemeral or not. |  |  |
| `duration` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#duration-v1-meta)_ | Duration sets how long the setup key is valid for. |  | Pattern: `^([0-9]+(\.[0-9]+)?(m\|h))+$` <br />Type: string <br />Optional: \{\} <br /> |
| `autoGroups` _[GroupReference](#groupreference) array_ | AutoGroups are groups that will be automatically assigned to peers using setup key. |  | Optional: \{\} <br /> |


#### SetupKeyStatus



SetupKeyStatus defines the observed state of SetupKey.



_Appears in:_
- [SetupKey](#setupkey)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last reconciled generation. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Conditions holds the conditions for the SetupKey. |  | Optional: \{\} <br /> |
| `setupKeyID` _string_ | SetupKeyID is the id of the created setup key. |  |  |


#### SidecarProfile



SidecarProfile is the Schema for the sidecarprofiles API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `netbird.io/v1alpha1` | | |
| `kind` _string_ | `SidecarProfile` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  | Optional: \{\} <br /> |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  | Optional: \{\} <br /> |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SidecarProfileSpec](#sidecarprofilespec)_ |  |  | Required: \{\} <br /> |
| `status` _[SidecarProfileStatus](#sidecarprofilestatus)_ |  | \{  \} |  |


#### SidecarProfileSpec



SidecarProfileSpec defines the desired state of SidecarProfile.



_Appears in:_
- [SidecarProfile](#sidecarprofile)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `setupKeyRef` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#localobjectreference-v1-core)_ | SetupKeyRef is the reference to the setup key used in the client. |  | Required: \{\} <br /> |
| `podSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#labelselector-v1-meta)_ | PodSelector determines which pods the profile should apply to.<br />An empty slector means the profile will apply to all pods in the namespace. |  | Optional: \{\} <br /> |
| `injectionMode` _[InjectionMode](#injectionmode)_ | InjectionMode defines whether the sidecar is injected as a native Kubernetes sidecar container or as a regular container. | Sidecar | Enum: [Sidecar Container] <br />Optional: \{\} <br /> |
| `extraDNSLabels` _string array_ | ExtraDNSLabels assigns additional DNS names to peers beyond their default hostname. |  | Optional: \{\} <br /> |
| `containerOverride` _[ContainerOverride](#containeroverride)_ |  |  | Optional: \{\} <br /> |


#### SidecarProfileStatus



SidecarProfileStatus defines the observed state of SidecarProfile.



_Appears in:_
- [SidecarProfile](#sidecarprofile)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Conditions holds the conditions for the SidecarProfile. |  | Optional: \{\} <br /> |


#### WorkloadOverride







_Appears in:_
- [NetworkRouterSpec](#networkrouterspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `labels` _object (keys:string, values:string)_ | Labels that will be added. |  | Optional: \{\} <br /> |
| `annotations` _object (keys:string, values:string)_ | Annotations that will be added. |  | Optional: \{\} <br /> |
| `replicas` _integer_ | Replicas sets the amount of client replicas. | 3 | Minimum: 1 <br />Optional: \{\} <br /> |
| `podTemplate` _[PodTemplateSpec](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#podtemplatespec-v1-core)_ | PodTemplate overrides the pod template. |  | Schemaless: \{\} <br />Optional: \{\} <br /> |


