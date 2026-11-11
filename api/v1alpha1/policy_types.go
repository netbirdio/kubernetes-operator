// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicySpec defines the desired state of Policy. A policy holds one rule that lets the
// peers of the source groups reach the peers and network resources of the destination
// groups.
// +kubebuilder:validation:XValidation:rule="!(has(self.ports) || has(self.portRanges)) || self.protocol in ['tcp', 'udp']",message="ports and portRanges require protocol tcp or udp"
type PolicySpec struct {
	// Name of the policy.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Description of the policy.
	// +optional
	Description string `json:"description,omitempty"`

	// Enabled sets whether the policy is applied.
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// Action accepts or drops the traffic the rule matches.
	// +optional
	// +kubebuilder:validation:Enum=accept;drop
	// +kubebuilder:default=accept
	Action string `json:"action,omitempty"`

	// SourceGroups are the groups whose peers the rule applies to.
	// +kubebuilder:validation:MinItems=1
	SourceGroups []GroupReference `json:"sourceGroups"`

	// DestinationGroups are the groups whose peers and resources the source peers reach.
	// +kubebuilder:validation:MinItems=1
	DestinationGroups []GroupReference `json:"destinationGroups"`

	// Protocol of the traffic the rule matches.
	// +optional
	// +kubebuilder:validation:Enum=all;tcp;udp;icmp
	// +kubebuilder:default=all
	Protocol string `json:"protocol,omitempty"`

	// Ports the rule matches. Requires protocol tcp or udp; without ports or port ranges,
	// every port matches.
	// +optional
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	Ports []int32 `json:"ports,omitempty"`

	// PortRanges the rule matches. Requires protocol tcp or udp.
	// +optional
	PortRanges []PortRange `json:"portRanges,omitempty"`

	// Bidirectional lets the destination peers also reach the source peers.
	// +optional
	Bidirectional bool `json:"bidirectional,omitempty"`
}

// PortRange is an inclusive range of ports.
// +kubebuilder:validation:XValidation:rule="self.start <= self.end",message="start must not be greater than end"
type PortRange struct {
	// Start is the first port of the range.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`

	// End is the last port of the range.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// PolicyStatus defines the observed state of Policy.
type PolicyStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the Policy.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// PolicyID is the id of the created policy.
	// +optional
	PolicyID string `json:"policyID,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// Policy is the Schema for the policies API.
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec PolicySpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status PolicyStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (p *Policy) GetConditions() []metav1.Condition {
	return p.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (p *Policy) SetConditions(conditions []metav1.Condition) {
	p.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// PolicyList contains a list of Policy.
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
}
