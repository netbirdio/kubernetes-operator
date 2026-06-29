// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkEgressSpec defines the desired state of NetworkEgress.
type NetworkEgressSpec struct {
	// NetworkRouterRef is a reference to the network and router where the resource will be created.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	NetworkRouterRef CrossNamespaceReference `json:"networkRouterRef"`

	// Target for egress traffic.
	Target NetworkEgressTarget `json:"target"`

	// Ports to the resource to route.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:Required
	Ports []NetworkEgressPort `json:"ports"`
}

// NetworkEgressTarget describes a single allowed egress destination.
// Exactly one of IP or FQDN must be set.
// +kubebuilder:validation:XValidation:rule="(has(self.ip) ? 1 : 0) + (has(self.fqdn) ? 1 : 0) == 1",message="exactly one of ip or fqdn must be set"
type NetworkEgressTarget struct {
	// IP targets a single specific IP address (not a CIDR range).
	// +optional
	IP *NetworkEgressIPTarget `json:"ip,omitempty"`

	// FQDN targets an exact domain name (no wildcards).
	// +optional
	FQDN *NetworkEgressFQDNTarget `json:"fqdn,omitempty"`
}

// NetworkEgressIPTarget is a single IPv4 or IPv6 address.
type NetworkEgressIPTarget struct {
	// Address is a single IP address.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="address must be a valid IPv4 or IPv6 address"
	Address string `json:"address"`
}

// NetworkEgressFQDNTarget matches traffic by an exact domain name (no wildcards).
type NetworkEgressFQDNTarget struct {
	// Hostname is a fully qualified domain name to match exactly.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	Hostname string `json:"hostname"`
}

type NetworkEgressPort struct {
	// Name of the port.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// The port that will be exposed by this service.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// NetworkEgressStatus defines the observed state of NetworkEgress.
type NetworkEgressStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the NetworkEgress.
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

// NetworkEgress is the Schema for the networkegresses API.
type NetworkEgress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec NetworkEgressSpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status NetworkEgressStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (n *NetworkEgress) GetConditions() []metav1.Condition {
	return n.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (n *NetworkEgress) SetConditions(conditions []metav1.Condition) {
	n.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// NetworkEgressList contains a list of NetworkEgress
type NetworkEgressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NetworkEgress `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkEgress{}, &NetworkEgressList{})
}
