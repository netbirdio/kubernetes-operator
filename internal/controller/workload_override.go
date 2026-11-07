// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
)

// mergePodTemplateOverride strategically merges override into base and returns the result
// as a new apply configuration. base is left unchanged.
func mergePodTemplateOverride(base *corev1ac.PodTemplateSpecApplyConfiguration, override *corev1.PodTemplateSpec) (*corev1ac.PodTemplateSpecApplyConfiguration, error) {
	baseJSON, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("marshal pod template: %w", err)
	}
	overrideJSON, err := json.Marshal(override)
	if err != nil {
		return nil, fmt.Errorf("marshal pod template override: %w", err)
	}
	mergedJSON, err := strategicpatch.StrategicMergePatch(baseJSON, overrideJSON, corev1.PodTemplateSpec{})
	if err != nil {
		return nil, fmt.Errorf("merge pod template override: %w", err)
	}
	// Decode into a fresh value: encoding/json reuses existing slice elements, so decoding
	// into base would leak fields between list entries the merge reordered, such as env vars.
	merged := corev1ac.PodTemplateSpec()
	if err := json.Unmarshal(mergedJSON, merged); err != nil {
		return nil, fmt.Errorf("unmarshal merged pod template: %w", err)
	}
	return merged, nil
}
