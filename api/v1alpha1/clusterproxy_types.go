// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterProxySpec defines the desired state of ClusterProxy.
type ClusterProxySpec struct {
	// ClusterName is the name of the Kubernetes cluster.
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	ClusterName string `json:"clusterName"`

	// APIServer is the URL of the Kubernetes API server to proxy requests to.
	// +required
	// +kubebuilder:default="https://kubernetes.default.svc.cluster.local/"
	APIServer string `json:"apiServer"`

	// ServiceAccountName is a reference to the service account used for impersonation.
	// +required
	ServiceAccountName string `json:"serviceAccountName"`

	// Groups are references to groups that the peer will be a part of.
	// +optional
	Groups []GroupReference `json:"groups,omitempty"`
}

// ClusterProxyStatus defines the observed state of ClusterProxy.
type ClusterProxyStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the ClusterProxy.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// ClusterProxy is the Schema for the clusterproxies API
type ClusterProxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ClusterProxySpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status ClusterProxyStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (n *ClusterProxy) GetConditions() []metav1.Condition {
	return n.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (n *ClusterProxy) SetConditions(conditions []metav1.Condition) {
	n.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// ClusterProxyList contains a list of ClusterProxy
type ClusterProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterProxy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterProxy{}, &ClusterProxyList{})
}
