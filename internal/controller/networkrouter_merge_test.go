// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"testing"

	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
)

// basePT mirrors the operator's router base env: a valueFrom secret ref mixed
// with plain value vars, the same shape as production.
func basePT() *corev1ac.PodTemplateSpecApplyConfiguration {
	return corev1ac.PodTemplateSpec().WithSpec(corev1ac.PodSpec().WithContainers(
		corev1ac.Container().WithName("netbird").WithEnv(
			corev1ac.EnvVar().WithName("NB_SETUP_KEY").
				WithValueFrom(corev1ac.EnvVarSource().
					WithSecretKeyRef(corev1ac.SecretKeySelector().WithName("setup-key").WithKey("setup-key"))),
			corev1ac.EnvVar().WithName("NB_MANAGEMENT_URL").WithValue("https://api.netbird.io"),
			corev1ac.EnvVar().WithName("NB_LOG_LEVEL").WithValue("info"),
		),
	))
}

// TestWorkloadOverrideEnvMerge verifies that appending env vars via a workload
// override does not corrupt the base vars or leave both value and valueFrom set.
func TestWorkloadOverrideEnvMerge(t *testing.T) {
	t.Parallel()

	override := &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "netbird",
					Env: []corev1.EnvVar{
						{Name: "NB_ENABLE_ROSENPASS", Value: "true"},
						{Name: "NB_ROSENPASS_PERMISSIVE", Value: "true"},
					},
				},
			},
		},
	}

	merged, err := mergePodTemplate(basePT(), override)
	require.NoError(t, err)
	require.Len(t, merged.Spec.Containers, 1)

	// No env var may carry both value and valueFrom (the API server rejects it).
	for _, e := range merged.Spec.Containers[0].Env {
		require.True(t, e.Value == nil || e.ValueFrom == nil,
			"env %s has both value and valueFrom", *e.Name)
	}
	// The base secret ref must survive the merge.
	var setupKey *corev1ac.EnvVarApplyConfiguration
	for i := range merged.Spec.Containers[0].Env {
		if *merged.Spec.Containers[0].Env[i].Name == "NB_SETUP_KEY" {
			setupKey = &merged.Spec.Containers[0].Env[i]
		}
	}
	require.NotNil(t, setupKey, "NB_SETUP_KEY dropped by merge")
	require.NotNil(t, setupKey.ValueFrom, "NB_SETUP_KEY lost its valueFrom")
}

// TestWorkloadOverrideEnvMergeRetypes verifies that an override changing a base
// var's source (value <-> valueFrom) leaves only the override's source set.
func TestWorkloadOverrideEnvMergeRetypes(t *testing.T) {
	t.Parallel()

	// valueFrom -> value
	override := &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "netbird",
				Env:  []corev1.EnvVar{{Name: "NB_SETUP_KEY", Value: "inline"}},
			}},
		},
	}
	merged, err := mergePodTemplate(basePT(), override)
	require.NoError(t, err)
	require.Len(t, merged.Spec.Containers, 1)

	for _, e := range merged.Spec.Containers[0].Env {
		if *e.Name == "NB_SETUP_KEY" {
			require.Nil(t, e.ValueFrom, "NB_SETUP_KEY kept its base valueFrom")
			require.Equal(t, "inline", *e.Value)
		}
	}

	// value -> valueFrom
	base := corev1ac.PodTemplateSpec().WithSpec(corev1ac.PodSpec().WithContainers(
		corev1ac.Container().WithName("netbird").WithEnv(
			corev1ac.EnvVar().WithName("NB_LOG_LEVEL").WithValue("info"),
		),
	))
	override = &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "netbird",
				Env: []corev1.EnvVar{{Name: "NB_LOG_LEVEL", ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "log-level"}, Key: "level"},
				}}},
			}},
		},
	}
	merged, err = mergePodTemplate(base, override)
	require.NoError(t, err)

	for _, e := range merged.Spec.Containers[0].Env {
		if *e.Name == "NB_LOG_LEVEL" {
			require.Nil(t, e.Value, "NB_LOG_LEVEL kept its base value")
			require.NotNil(t, e.ValueFrom)
		}
	}
}

// A sidecar container added by the override must not retype env vars of the
// base container that share a name.
func TestWorkloadOverrideEnvMergeSidecarScoping(t *testing.T) {
	t.Parallel()

	override := &corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "netbird", Env: []corev1.EnvVar{{Name: "NB_ENABLE_ROSENPASS", Value: "true"}}},
				{Name: "sidecar", Env: []corev1.EnvVar{{Name: "NB_LOG_LEVEL", Value: "debug"}}},
			},
		},
	}
	merged, err := mergePodTemplate(basePT(), override)
	require.NoError(t, err)
	require.Len(t, merged.Spec.Containers, 2)

	envByContainer := map[string]map[string]*corev1ac.EnvVarApplyConfiguration{}
	for _, c := range merged.Spec.Containers {
		envByContainer[*c.Name] = map[string]*corev1ac.EnvVarApplyConfiguration{}
		for i := range c.Env {
			envByContainer[*c.Name][*c.Env[i].Name] = &c.Env[i]
		}
	}

	// Base container keeps its own NB_LOG_LEVEL and gains the rosenpass var.
	require.Equal(t, "info", *envByContainer["netbird"]["NB_LOG_LEVEL"].Value)
	require.Equal(t, "true", *envByContainer["netbird"]["NB_ENABLE_ROSENPASS"].Value)
	// Sidecar gets its own.
	require.Equal(t, "debug", *envByContainer["sidecar"]["NB_LOG_LEVEL"].Value)
}

// An override that omits containers (e.g. metadata-only) must not drop the
// base containers.
func TestWorkloadOverrideMergePreservesContainers(t *testing.T) {
	t.Parallel()

	override := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"x": "y"}},
		Spec:       corev1.PodSpec{NodeSelector: map[string]string{"z": "w"}},
	}

	merged, err := mergePodTemplate(basePT(), override)
	require.NoError(t, err)
	require.Len(t, merged.Spec.Containers, 1)
	require.Equal(t, "netbird", *merged.Spec.Containers[0].Name)
	require.Equal(t, map[string]string{"x": "y"}, merged.Labels)
	require.Equal(t, map[string]string{"z": "w"}, merged.Spec.NodeSelector)
}
