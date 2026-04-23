package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetupKeySpec defines the desired state of SetupKey.
type SetupKeySpec struct {
	// Name of the setup key.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Ephemeral decides if peers added with the key are ephemeral or not.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="ephemeral is immutable"
	Ephemeral bool `json:"ephemeral"`

	// Duration sets how long the setup key is valid for.
	// +optional
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(m|h))+$"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="duration is immutable"
	Duration *metav1.Duration `json:"duration,omitempty"`

	// AutoGroups are groups that will be automatically assigned to peers using setup key.
	// +optional
	AutoGroups []ResourceReference `json:"autoGroups,omitempty"`
}

// SetupKeyStatus defines the observed state of SetupKey.
type SetupKeyStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the SetupKey.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SetupKeyID is the id of the created setup key.
	SetupKeyID string `json:"setupKeyID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// SetupKey is the Schema for the setupkeys API.
type SetupKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec SetupKeySpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status SetupKeyStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (sk *SetupKey) GetConditions() []metav1.Condition {
	return sk.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (sk *SetupKey) SetConditions(conditions []metav1.Condition) {
	sk.Status.Conditions = conditions
}

func (sk SetupKey) SecretName() string {
	return "setup-key-" + sk.Name
}

// +kubebuilder:object:root=true

// SetupKeyList contains a list of SetupKey.
type SetupKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SetupKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SetupKey{}, &SetupKeyList{})
}
