package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NBGroupSpec defines the desired state of NBGroup.
type NBGroupSpec struct {
	Name string `json:"name"`
}

// NBGroupStatus defines the observed state of NBGroup.
type NBGroupStatus struct {
	// +optional
	GroupID *string `json:"groupID"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NBGroup is the Schema for the nbgroups API.
type NBGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NBGroupSpec   `json:"spec,omitempty"`
	Status NBGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NBGroupList contains a list of NBGroup.
type NBGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NBGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NBGroup{}, &NBGroupList{})
}
