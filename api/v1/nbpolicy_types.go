package v1

import (
	"github.com/netbirdio/kubernetes-operator/internal/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBPolicySpec defines the desired state of NBPolicy.
type NBPolicySpec struct {
	// Name Policy name
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +optional
	Description string `json:"description,omitempty"`
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	SourceGroups []string `json:"sourceGroups,omitempty"`
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	DestinationGroups []string `json:"destinationGroups,omitempty"`
	// +optional
	// +kubebuilder:validation:items:Enum=tcp;udp
	Protocols []string `json:"protocols,omitempty"`
	// +optional
	// +kubebuilder:validation:items:Minimum=0
	// +kubebuilder:validation:items:Maximum=65535
	Ports []int32 `json:"ports,omitempty"`
	// +optional
	// +default:value=true
	Bidirectional bool `json:"bidirectional"`
}

// NBPolicyStatus defines the observed state of NBPolicy.
type NBPolicyStatus struct {
	// +optional
	TCPPolicyID *string `json:"tcpPolicyID"`
	// +optional
	UDPPolicyID *string `json:"udpPolicyID"`
	// +optional
	LastUpdatedAt *metav1.Time `json:"lastUpdatedAt"`
	// +optional
	ManagedServiceList []string `json:"managedServiceList"`
	// +optional
	Conditions []NBCondition `json:"conditions,omitempty"`
}

// Equal returns if NBPolicyStatus is equal to this one
func (a NBPolicyStatus) Equal(b NBPolicyStatus) bool {
	return a.TCPPolicyID == b.TCPPolicyID &&
		a.UDPPolicyID == b.UDPPolicyID &&
		a.LastUpdatedAt == b.LastUpdatedAt &&
		util.Equivalent(a.ManagedServiceList, b.ManagedServiceList) &&
		util.Equivalent(a.Conditions, b.Conditions)
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// NBPolicy is the Schema for the nbpolicies API.
type NBPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NBPolicySpec   `json:"spec,omitempty"`
	Status NBPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NBPolicyList contains a list of NBPolicy.
type NBPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NBPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NBPolicy{}, &NBPolicyList{})
}
