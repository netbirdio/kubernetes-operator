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

// NBSetupKeyConditionType is a valid value for PodCondition.Type
type NBSetupKeyConditionType string

// These are built-in conditions of pod. An application may use a custom condition not listed here.
const (
	// Ready indicates whether NBSetupKey is valid and ready to use.
	Ready NBSetupKeyConditionType = "Ready"
)

// NBSetupKeySpec defines the desired state of NBSetupKey.
type NBSetupKeySpec struct {
	// SecretKeyRef is a reference to the secret containing the setup key
	SecretKeyRef corev1.SecretKeySelector `json:"secretKeyRef"`
	// ManagementURL optional, override operator management URL
	ManagementURL string `json:"managementURL,omitempty"`
}

// NBSetupKeyStatus defines the observed state of NBSetupKey.
type NBSetupKeyStatus struct {
	Conditions []NBSetupKeyCondition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,2,rep,name=conditions"`
}

// NBSetupKeyCondition defines a condition in NBSetupKey status.
type NBSetupKeyCondition struct {
	// Type is the type of the condition.
	Type NBSetupKeyConditionType `json:"type" protobuf:"bytes,1,opt,name=type,casttype=NBSetupKeyConditionType"`
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
