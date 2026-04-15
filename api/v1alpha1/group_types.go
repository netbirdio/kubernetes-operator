package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GroupSpec defines the desired state of Group
type GroupSpec struct {
	// name of the group.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// GroupStatus defines the observed state of Group.
type GroupStatus struct {
	// +optional
	GroupID *string `json:"groupID,omitempty"`

	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource

// Group is the Schema for the groups API
type Group struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Group
	// +required
	Spec GroupSpec `json:"spec"`

	// status defines the observed state of Group
	// +optional
	Status GroupStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GroupList contains a list of Group
type GroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Group `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Group{}, &GroupList{})
}
