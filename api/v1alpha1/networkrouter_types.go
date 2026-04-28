package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkRouterSpec defines the desired state of NetworkRouter.
type NetworkRouterSpec struct {
	// DNSZoneRef is a reference to the DNS zone used to create records for resources.
	// +required
	DNSZoneRef DNSZoneReference `json:"dnsZoneRef"`

	// Netbird client image.
	// +optional
	Image string `json:"image,omitempty"`

	// Log level for Netbird client.
	// +optional
	LogLevel string `json:"logLevel,omitempty"`

	// WorkloadOverride contains configuration that will override the default workload.
	// +optional
	WorkloadOverride *WorkloadOverride `json:"workloadOverride,omitempty"`
}

// DNSZoneReference references a Netbird DNS zone by domain name.
type DNSZoneReference struct {
	// Name is the domain name of an existing Netbird DNS zone, e.g. "example.com".
	// +required
	Name string `json:"name"`
}

type WorkloadOverride struct {
	// Labels that will be added.
	// +optional
	Labels map[string]string `json:"labels"`

	// Annotations that will be added.
	// +optional
	Annotations map[string]string `json:"annotations"`

	// Replicas sets the amount of client replicas.
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	Replicas *int32 `json:"replicas"`

	// PodTemplate overrides the pod template.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	PodTemplate *corev1.PodTemplateSpec `json:"podTemplate"`
}

// NetworkRouterStatus defines the observed state of NetworkRouter.
type NetworkRouterStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the NetworkRouter.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RoutingPeerID is the id of the created routing peer.
	// +optional
	RoutingPeerID string `json:"routingPeerID,omitempty"`

	// NetworkID is the id of the network the routing peer was created in.
	// +optional
	NetworkID string `json:"networkID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// NetworkRouter is the Schema for the networkrouters API.
type NetworkRouter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec NetworkRouterSpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status NetworkRouterStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (n *NetworkRouter) GetConditions() []metav1.Condition {
	return n.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (n *NetworkRouter) SetConditions(conditions []metav1.Condition) {
	n.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// NetworkRouterList contains a list of NetworkRouter.
type NetworkRouterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NetworkRouter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkRouter{}, &NetworkRouterList{})
}
