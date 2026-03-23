package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ResourcePolicySpec defines the desired state of ResourcePolicy
type ResourcePolicySpec struct {
	// Resources the policy should apply to.
	TargetRefs []gatewayv1.LocalObjectReference `json:"targetRefs"`

	// Groups to apply to the resource.
	Groups []string `json:"groups"`
}

// ResourcePolicyStatus defines the observed state of ResourcePolicy.
type ResourcePolicyStatus struct {
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ResourcePolicy is the Schema for the resourcepolicies API
type ResourcePolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ResourcePolicy
	// +required
	Spec ResourcePolicySpec `json:"spec"`

	// status defines the observed state of ResourcePolicy
	// +optional
	Status ResourcePolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ResourcePolicyList contains a list of ResourcePolicy
type ResourcePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ResourcePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourcePolicy{}, &ResourcePolicyList{})
}
