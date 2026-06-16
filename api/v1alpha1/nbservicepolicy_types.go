// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// CrowdsecMode selects how the proxy cluster's CrowdSec IP-reputation check is
// applied. Only effective when the proxy cluster supports CrowdSec.
// +kubebuilder:validation:Enum=off;observe;enforce
type CrowdsecMode string

const (
	CrowdsecModeOff     CrowdsecMode = "off"
	CrowdsecModeObserve CrowdsecMode = "observe"
	CrowdsecModeEnforce CrowdsecMode = "enforce"
)

// AccessRestrictions are connection-level restrictions based on IP address or
// geography, applied to the reverse-proxy service.
type AccessRestrictions struct {
	// AllowedCidrs is a CIDR allowlist. If non-empty, only matching source IPs
	// are allowed. Evaluated before BlockedCidrs.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(c, isCIDR(c))",message="allowedCidrs entries must be valid CIDRs"
	AllowedCidrs []string `json:"allowedCidrs,omitempty"`

	// BlockedCidrs is a CIDR blocklist. Matching source IPs are rejected.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:XValidation:rule="self.all(c, isCIDR(c))",message="blockedCidrs entries must be valid CIDRs"
	BlockedCidrs []string `json:"blockedCidrs,omitempty"`

	// AllowedCountries is an ISO 3166-1 alpha-2 country-code allowlist. If
	// non-empty, only these countries are permitted.
	// +optional
	// +kubebuilder:validation:MaxItems=250
	// +kubebuilder:validation:items:MaxLength=2
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.matches('^[A-Za-z]{2}$'))",message="allowedCountries entries must be ISO 3166-1 alpha-2 codes"
	AllowedCountries []string `json:"allowedCountries,omitempty"`

	// BlockedCountries is an ISO 3166-1 alpha-2 country-code blocklist.
	// +optional
	// +kubebuilder:validation:MaxItems=250
	// +kubebuilder:validation:items:MaxLength=2
	// +kubebuilder:validation:XValidation:rule="self.all(c, c.matches('^[A-Za-z]{2}$'))",message="blockedCountries entries must be ISO 3166-1 alpha-2 codes"
	BlockedCountries []string `json:"blockedCountries,omitempty"`
}

// NBServicePolicySpec defines the desired state of NBServicePolicy.
type NBServicePolicySpec struct {
	// TargetRefs identify the HTTPRoute(s) this policy attaches to, following
	// the Gateway API direct policy-attachment pattern (GEP-713). Each target
	// must be an HTTPRoute in the same namespace as the policy.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(t, t.kind == 'HTTPRoute' && (t.group == 'gateway.networking.k8s.io'))",message="targetRefs must reference HTTPRoute in group gateway.networking.k8s.io"
	TargetRefs []gwv1.LocalPolicyTargetReference `json:"targetRefs"`

	// Private, when true, makes the service NetBird-only: inbound peers
	// authenticate via their tunnel identity (no OIDC) and an ACL policy is
	// auto-generated from AccessGroups. Requires an HTTP service.
	// +optional
	Private *bool `json:"private,omitempty"`

	// AccessGroups are the NetBird group IDs whose peers may reach a private
	// service over the tunnel. Required when Private is true; ignored otherwise.
	// +optional
	AccessGroups []string `json:"accessGroups,omitempty"`

	// CrowdsecMode sets the CrowdSec IP-reputation handling for the service.
	// +optional
	CrowdsecMode *CrowdsecMode `json:"crowdsecMode,omitempty"`

	// AccessRestrictions sets IP/geo connection-level restrictions.
	// +optional
	AccessRestrictions *AccessRestrictions `json:"accessRestrictions,omitempty"`

	// PassHostHeader, when true, forwards the original client Host header to
	// the backend instead of rewriting it to the backend address.
	// +optional
	PassHostHeader *bool `json:"passHostHeader,omitempty"`

	// RewriteRedirects, when true, rewrites Location headers in backend
	// responses to replace the backend address with the public domain.
	// +optional
	RewriteRedirects *bool `json:"rewriteRedirects,omitempty"`
}

// NBServicePolicyStatus defines the observed state of NBServicePolicy.
type NBServicePolicyStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the NBServicePolicy.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Private",type="boolean",JSONPath=".spec.private",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// NBServicePolicy configures the NetBird reverse-proxy service backing the
// HTTPRoute(s) it targets.
type NBServicePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec NBServicePolicySpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status NBServicePolicyStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (n *NBServicePolicy) GetConditions() []metav1.Condition {
	return n.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (n *NBServicePolicy) SetConditions(conditions []metav1.Condition) {
	n.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// NBServicePolicyList contains a list of NBServicePolicy.
type NBServicePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NBServicePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NBServicePolicy{}, &NBServicePolicyList{})
}
