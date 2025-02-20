package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBRoutingPeerConditionType is a valid value for NBRoutingPeerCondition.Type
type NBRoutingPeerConditionType string

const (
	// RoutingPeerReady indicates whether NBRoutingPeer is valid and ready to use.
	RoutingPeerReady NBRoutingPeerConditionType = "Ready"
	// RoutingPeerNetworkReady indicates whether NetBird network is ready and found.
	RoutingPeerNetworkReady NBRoutingPeerConditionType = "NetworkReady"
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
	Conditions []NBRoutingPeerCondition `json:"conditions"`
	// +optional
	NetworkID *string `json:"networkID"`
	// +optional
	SetupKeyID *string `json:"setupKeyID"`
	// +optional
	RouterID *string `json:"routerID"`
}

// NBRoutingPeerCondition defines a condition in NBRoutingPeer status.
type NBRoutingPeerCondition struct {
	// Type is the type of the condition.
	Type NBRoutingPeerConditionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=NBRoutingPeerConditionType"`
	// Status is the status of the condition.
	// Can be True, False, Unknown.
	Status corev1.ConditionStatus `json:"status" protobuf:"bytes,2,opt,name=status,casttype=ConditionStatus"`
	// Last time we probed the condition.
	// +optional
	LastProbeTime metav1.Time `json:"lastProbeTime,omitempty" protobuf:"bytes,3,opt,name=lastProbeTime"`
	// Last time the condition transitioned from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty" protobuf:"bytes,4,opt,name=lastTransitionTime"`
	// Unique, one-word, CamelCase reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty" protobuf:"bytes,5,opt,name=reason"`
	// Human-readable message indicating details about last transition.
	// +optional
	Message string `json:"message,omitempty" protobuf:"bytes,6,opt,name=message"`
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
