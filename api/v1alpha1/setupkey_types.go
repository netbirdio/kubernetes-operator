// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetupKeySpec defines the desired state of SetupKey.
// +kubebuilder:validation:XValidation:rule="!has(self.renewBefore) || has(self.duration)",message="renewBefore requires duration"
// +kubebuilder:validation:XValidation:rule="!has(self.renewBefore) || !has(self.duration) || duration(self.duration) - duration(self.renewBefore) >= duration('1m')",message="renewBefore must be at least 1m shorter than duration"
// +kubebuilder:validation:XValidation:rule="!has(self.renewBefore) || !has(self.duration) || duration(self.renewBefore).getMilliseconds() * 10 <= duration(self.duration).getMilliseconds() * 9",message="renewBefore must be at most nine tenths of duration"
type SetupKeySpec struct {
	// Name of the setup key.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Ephemeral decides if peers added with the key are ephemeral or not.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="ephemeral is immutable"
	Ephemeral bool `json:"ephemeral"`

	// AllowExtraDnsLabels decides if peers added with the key can have extra DNS labels.
	// +kubebuilder:default=false
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="allowExtraDnsLabels is immutable"
	AllowExtraDnsLabels bool `json:"allowExtraDnsLabels"`

	// Duration sets how long the setup key is valid for.
	// +optional
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(s|m|h))+$"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="duration is immutable"
	Duration *metav1.Duration `json:"duration,omitempty"`

	// RenewBefore is how long before the setup key expires a new key replaces it.
	// The Secret then holds the new key, while the replaced key stays valid until
	// it expires, so whatever still holds it has that long to pick up the new one.
	// Without it, a key is only replaced once it has expired. Requires duration
	// and must be at least a minute and a tenth of duration shorter than it, so
	// that a new key is not due for renewal as soon as it is created and no more
	// than ten replaced keys are kept at once.
	// +optional
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(s|m|h))+$"
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`

	// AutoGroups are groups that will be automatically assigned to peers using setup key.
	// +optional
	AutoGroups []GroupReference `json:"autoGroups,omitempty"`
}

// SetupKeyStatus defines the observed state of SetupKey.
type SetupKeyStatus struct {
	// ObservedGeneration is the last reconciled generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the conditions for the SetupKey.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SetupKeyID is the id of the created setup key.
	SetupKeyID string `json:"setupKeyID,omitempty"`

	// ExpiresAt is when the setup key expires. It is empty for a key that does
	// not expire.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// PreviousSetupKeys are setup keys replaced by a renewal. They keep
	// receiving the auto groups and are deleted once NetBird reports them
	// expired or revoked.
	// +listType=atomic
	// +optional
	PreviousSetupKeys []PreviousSetupKey `json:"previousSetupKeys,omitempty"`
}

// PreviousSetupKey is a setup key that a renewal replaced.
type PreviousSetupKey struct {
	// SetupKeyID is the id of the setup key.
	SetupKeyID string `json:"setupKeyID"`

	// ExpiresAt is when the setup key expires.
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status",description=""
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description=""

// SetupKey is the Schema for the setupkeys API.
type SetupKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec SetupKeySpec `json:"spec"`

	// +kubebuilder:default={"observedGeneration":-1}
	Status SetupKeyStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (sk *SetupKey) GetConditions() []metav1.Condition {
	return sk.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (sk *SetupKey) SetConditions(conditions []metav1.Condition) {
	sk.Status.Conditions = conditions
}

func (sk SetupKey) SecretName() string {
	return "setup-key-" + sk.Name
}

// +kubebuilder:object:root=true

// SetupKeyList contains a list of SetupKey.
type SetupKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SetupKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SetupKey{}, &SetupKeyList{})
}
