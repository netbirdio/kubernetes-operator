/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NBSetupKeySpec defines the desired state of NBSetupKey.
type NBSetupKeySpec struct {
	// SecretKeyRef is a reference to the secret containing the setup key
	SecretKeyRef corev1.SecretKeySelector `json:"secretKeyRef"`
	// ManagementURL optional, override operator management URL
	ManagementURL string `json:"managementURL,omitempty"`
	// Volumes optional, additional volumes for NetBird container
	// +optional
	Volumes []corev1.Volume `json:"volumes,omitempty"`
	// VolumeMounts optional, additional volumeMounts for NetBird container
	// +optional
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts,omitempty"`
}

// NBSetupKeyStatus defines the observed state of NBSetupKey.
type NBSetupKeyStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// NBSetupKey is the Schema for the nbsetupkeys API.
type NBSetupKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NBSetupKeySpec   `json:"spec,omitempty"`
	Status NBSetupKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NBSetupKeyList contains a list of NBSetupKey.
type NBSetupKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NBSetupKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NBSetupKey{}, &NBSetupKeyList{})
}
