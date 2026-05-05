// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:XValidation:rule="(has(self.id)?1:0)+(has(self.name)?1:0)+(has(self.localRef)?1:0)==1",message="Exactly one of id, name, or localRef must be set"
type GroupReference struct {
	// Name is the name of the group.
	// +optional
	Name *string `json:"name,omitempty"`

	// ID is the id of the group.
	// +optional
	ID *string `json:"id,omitempty"`

	// LocalReference is a reference to a group in the same namespace.
	// +optional
	LocalRef *corev1.LocalObjectReference `json:"localRef,omitempty"`
}

// GroupSpec defines the desired state of Group.
type GroupSpec struct {
	// Name of the group.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// GroupStatus defines the observed state of Group.
type GroupStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the Group.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// GroupID is the id of the created group.
	// +optional
	GroupID string `json:"groupID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// Group is the Schema for the groups API.
type Group struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec GroupSpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status GroupStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (g *Group) GetConditions() []metav1.Condition {
	return g.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (g *Group) SetConditions(conditions []metav1.Condition) {
	g.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// GroupList contains a list of Group.
type GroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Group `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Group{}, &GroupList{})
}
