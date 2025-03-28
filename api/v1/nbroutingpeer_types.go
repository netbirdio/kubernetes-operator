package v1

import (
	"github.com/netbirdio/kubernetes-operator/internal/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBRoutingPeerSpec defines the desired state of NBRoutingPeer.
type NBRoutingPeerSpec struct {
	// +optional
	Replicas *int32 `json:"replicas"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources"`
	// +optional
	Labels map[string]string `json:"labels"`
	// +optional
	Annotations map[string]string `json:"annotations"`
	// +optional
	NodeSelector map[string]string `json:"nodeSelector"`
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations"`
}

// NBRoutingPeerStatus defines the observed state of NBRoutingPeer.
type NBRoutingPeerStatus struct {
	// +optional
	NetworkID *string `json:"networkID"`
	// +optional
	SetupKeyID *string `json:"setupKeyID"`
	// +optional
	RouterID *string `json:"routerID"`
	// +optional
	Conditions []NBCondition `json:"conditions,omitempty"`
}

// Equal returns if NBRoutingPeerStatus is equal to this one
func (a NBRoutingPeerStatus) Equal(b NBRoutingPeerStatus) bool {
	return a.NetworkID == b.NetworkID &&
		a.SetupKeyID == b.SetupKeyID &&
		a.RouterID == b.RouterID &&
		util.Equivalent(a.Conditions, b.Conditions)
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NBRoutingPeer is the Schema for the nbroutingpeers API.
type NBRoutingPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NBRoutingPeerSpec   `json:"spec,omitempty"`
	Status NBRoutingPeerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NBRoutingPeerList contains a list of NBRoutingPeer.
type NBRoutingPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NBRoutingPeer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NBRoutingPeer{}, &NBRoutingPeerList{})
}
