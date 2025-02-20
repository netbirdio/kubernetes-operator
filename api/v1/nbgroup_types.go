package v1

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBGroupSpec defines the desired state of NBGroup.
type NBGroupSpec struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// NBGroupStatus defines the observed state of NBGroup.
type NBGroupStatus struct {
	// +optional
	GroupID *string `json:"groupID"`
	// +optional
	Conditions []NBCondition `json:"conditions,omitempty"`
}

// Equal returns if NBGroupStatus is equal to this one
func (a NBGroupStatus) Equal(b NBGroupStatus) bool {
	return a.GroupID == b.GroupID && slices.Equal(a.Conditions, b.Conditions)
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
