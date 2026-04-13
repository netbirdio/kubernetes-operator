package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RoutingPeerSpec defines the desired state of RoutingPeer
type RoutingPeerSpec struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf", message="networkRef is immutable once set"
	NetworkRef ResourceReference `json:"networkRef"`

	// +optional
	DeploymentOverride *DeploymentOverride `json:"deploymentOverride,omitempty"`
}

type DeploymentOverride struct {
	// +optional
	Labels map[string]string `json:"labels"`

	// +optional
	Annotations map[string]string `json:"annotations"`

	// +optional
	Replicas *int32 `json:"replicas"`

	// +optional
	PodTemplate *corev1.PodTemplateSpec `json:"podTemplate"`
}

// RoutingPeerStatus defines the observed state of RoutingPeer.
type RoutingPeerStatus struct {
	// routingpeerID is the id of the created routing peer.
	RoutingPeerID *string `json:"routingPeerID,omitempty"`

	// networkID is the id of the network the routing peer was created in.
	NetworkID *string `json:"networkID,omitempty"`

	// The status of each condition is one of True, False, or Unknown.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// RoutingPeer is the Schema for the routingpeers API
type RoutingPeer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of RoutingPeer
	// +required
	Spec RoutingPeerSpec `json:"spec"`

	// status defines the observed state of RoutingPeer
	// +optional
	// +kubebuilder:default={conditions: {{type: "Ready", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	Status RoutingPeerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// RoutingPeerList contains a list of RoutingPeer
type RoutingPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []RoutingPeer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RoutingPeer{}, &RoutingPeerList{})
}
