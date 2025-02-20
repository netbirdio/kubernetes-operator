package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBResourceSpec defines the desired state of NBResource.
type NBResourceSpec struct {
	Name      string   `json:"name"`
	NetworkID string   `json:"networkID"`
	Address   string   `json:"address"`
	Groups    []string `json:"groups"`
}

// NBResourceStatus defines the observed state of NBResource.
type NBResourceStatus struct {
	// +optional
	NetworkResourceID *string `json:"networkResourceID"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NBResource is the Schema for the nbresources API.
type NBResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NBResourceSpec   `json:"spec,omitempty"`
	Status NBResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NBResourceList contains a list of NBResource.
type NBResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NBResource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NBResource{}, &NBResourceList{})
}
