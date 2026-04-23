package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkResourceSpec defines the desired state of NetworkResource.
type NetworkResourceSpec struct {
	// NetworkRouterRef is a reference to the network and router where the resource will be created.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	NetworkRouterRef CrossNamespaceReference `json:"networkRouterRef"`

	// ServiceRef is a reference to the service to expose in the Network.
	ServiceRef corev1.LocalObjectReference `json:"serviceRef"`

	// Groups are references to groups that the resource will be a part of.
	// +optional
	Groups []ResourceReference `json:"groups,omitempty"`
}

// NetworkResourceStatus defines the observed state of NetworkResource.
type NetworkResourceStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the NetworkResource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// NetworkID is the id of the network the resource is created in.
	// +optional
	NetworkID string `json:"networkID,omitempty"`

	// ResourceID is the id of the created resource.
	// +optional
	ResourceID string `json:"resourceID,omitempty"`

	// DNSZoneID is the id of the zone the DNS record is created in.
	// +optional
	DNSZoneID string `json:"dnsZoneID,omitempty"`

	// DNSRecordID is the id of the created DNS record.
	// +optional
	DNSRecordID string `json:"dnsRecordID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// NetworkResource is the Schema for the networkresources API.
type NetworkResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec NetworkResourceSpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (n *NetworkResource) GetConditions() []metav1.Condition {
	return n.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (n *NetworkResource) SetConditions(conditions []metav1.Condition) {
	n.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// NetworkResourceList contains a list of NetworkResource.
type NetworkResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NetworkResource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkResource{}, &NetworkResourceList{})
}
