// SPDX-License-Identifier: BSD-3-Clause

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InjectionMode defines how the sidecar is injected into the pod.
// +kubebuilder:validation:Enum=Sidecar;Container
type InjectionMode string

const (
	// InjectionModeSidecar injects the client as a sidecar container.
	InjectionModeSidecar InjectionMode = "Sidecar"

	// InjectionModeContainer injects the client as a regular container.
	InjectionModeContainer InjectionMode = "Container"
)

// SidecarProfileSpec defines the desired state of SidecarProfile.
type SidecarProfileSpec struct {
	// SetupKeyRef is the reference to the setup key used in the client.
	// +required
	SetupKeyRef corev1.LocalObjectReference `json:"setupKeyRef"`

	// PodSelector determines which pods the profile should apply to.
	// An empty slector means the profile will apply to all pods in the namespace.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// InjectionMode defines whether the sidecar is injected as a native Kubernetes sidecar container or as a regular container.
	// +kubebuilder:default=Sidecar
	// +optional
	InjectionMode InjectionMode `json:"injectionMode,omitempty"`

	// ExtraDNSLabels assigns additional DNS names to peers beyond their default hostname.
	// +optional
	ExtraDNSLabels []string `json:"extraDNSLabels,omitempty"`

	// +optional
	ContainerOverride *ContainerOverride `json:"containerOverride,omitempty"`
}

type ContainerOverride struct {
	// Image overrides the image used by the client.
	// +optional
	Image string `json:"image,omitempty"`

	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// +optional
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
}

// SidecarProfileStatus defines the observed state of SidecarProfile.
type SidecarProfileStatus struct {
	// Conditions holds the conditions for the SidecarProfile.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource

// SidecarProfile is the Schema for the sidecarprofiles API.
type SidecarProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec SidecarProfileSpec `json:"spec"`

	// +kubebuilder:default={}
	Status SidecarProfileStatus `json:"status,omitempty"`
}

// GetConditions returns the status conditions of the object.
func (s *SidecarProfile) GetConditions() []metav1.Condition {
	return s.Status.Conditions
}

// SetConditions sets the status conditions on the object.
func (s *SidecarProfile) SetConditions(conditions []metav1.Condition) {
	s.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// SidecarProfileList contains a list of SidecarProfile
type SidecarProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SidecarProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SidecarProfile{}, &SidecarProfileList{})
}
