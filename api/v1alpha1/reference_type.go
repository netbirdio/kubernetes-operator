package v1alpha1

import corev1 "k8s.io/api/core/v1"

// +kubebuilder:validation:XValidation:rule="(has(self.id) && !has(self.localRef)) || (!has(self.id) && has(self.localRef))",message="exactly one of id or localRef must be set"
type ResourceReference struct {
	// id of the resource in the Netbird API.
	// +optional
	ID *string `json:"id,omitempty"`

	// local reference to the object in the same namespace.
	// +optional
	LocalRef *corev1.LocalObjectReference `json:"localRef,omitempty"`
}
