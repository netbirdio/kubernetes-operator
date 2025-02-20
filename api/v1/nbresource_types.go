package v1

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBResourceSpec defines the desired state of NBResource.
type NBResourceSpec struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	NetworkID string `json:"networkID"`
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`
	// +kubebuilder:validation:items:MinLength=1
	Groups []string `json:"groups"`
	// +optional
	PolicyName string `json:"policyName,omitempty"`
	// +optional
	TCPPorts []int32 `json:"tcpPorts,omitempty"`
	// +optional
	UDPPorts []int32 `json:"udpPorts,omitempty"`
}

// NBResourceStatus defines the observed state of NBResource.
type NBResourceStatus struct {
	// +optional
	NetworkResourceID *string `json:"networkResourceID,omitempty"`
	// +optional
	PolicyName *string `json:"policyName,omitempty"`
	// +optional
	TCPPorts []int32 `json:"tcpPorts,omitempty"`
	// +optional
	UDPPorts []int32 `json:"udpPorts,omitempty"`
	// +optional
	Groups []string `json:"groups,omitempty"`
	// +optional
	Conditions []NBCondition `json:"conditions,omitempty"`
}

// Equal returns if NBResourceStatus is equal to this one
func (a NBResourceStatus) Equal(b NBResourceStatus) bool {
	return a.NetworkResourceID == b.NetworkResourceID &&
		a.PolicyName == b.PolicyName &&
		slices.Equal(a.TCPPorts, b.TCPPorts) &&
		slices.Equal(a.UDPPorts, b.UDPPorts) &&
		slices.Equal(a.Groups, b.Groups) &&
		slices.Equal(a.Conditions, b.Conditions)
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
