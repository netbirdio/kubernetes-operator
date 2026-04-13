package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetupKeySpec defines the desired state of SetupKey
type SetupKeySpec struct {
	// name of the setup key.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Ephemeral decides if peers added with the key are ephemeral or not.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="ephemeral is immutable"
	Ephemeral bool `json:"ephemeral"`

	// Duration sets how long the setup key is valid for.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="duration is immutable"
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// Groups that will be automatically assigned to resources using setup key.
	// +optional
	AutoGroups []ResourceReference `json:"autoGroups,omitempty"`
}

// SetupKeyStatus defines the observed state of SetupKey.
type SetupKeyStatus struct {
	// SetupKeyID of the setup key.
	SetupKeyID *string `json:"setupKeyID,omitempty"`

	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource

// SetupKey is the Schema for the setupkeys API
type SetupKey struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SetupKey
	// +required
	Spec SetupKeySpec `json:"spec"`

	// status defines the observed state of SetupKey
	// +optional
	Status SetupKeyStatus `json:"status,omitzero"`
}

func (sk SetupKey) SecretName() string {
	return "setup-key-" + sk.Name
}

// +kubebuilder:object:root=true

// SetupKeyList contains a list of SetupKey
type SetupKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SetupKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SetupKey{}, &SetupKeyList{})
}
