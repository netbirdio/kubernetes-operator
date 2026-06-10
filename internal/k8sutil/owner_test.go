// SPDX-License-Identifier: BSD-3-Clause

package k8sutil

import (
	"testing"

	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
)

func TestControllerReference(t *testing.T) {
	t.Parallel()

	scheme := kruntime.NewScheme()
	err := corev1.AddToScheme(scheme)
	require.NoError(t, err)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
	}

	ownerRef, err := ControllerReference(&pod, scheme)
	require.NoError(t, err)
	require.EqualT(t, "v1", *ownerRef.APIVersion)
	require.EqualT(t, "Pod", *ownerRef.Kind)
	require.EqualT(t, "foo", *ownerRef.Name)
	require.EqualT(t, pod.UID, *ownerRef.UID)
	require.EqualT(t, true, *ownerRef.Controller)
	require.EqualT(t, true, *ownerRef.BlockOwnerDeletion)
}

func TestOwnerReference(t *testing.T) {
	t.Parallel()

	scheme := kruntime.NewScheme()
	err := corev1.AddToScheme(scheme)
	require.NoError(t, err)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
	}

	ownerRef, err := OwnerReference(&pod, scheme)
	require.NoError(t, err)
	require.EqualT(t, "v1", *ownerRef.APIVersion)
	require.EqualT(t, "Pod", *ownerRef.Kind)
	require.EqualT(t, "foo", *ownerRef.Name)
	require.EqualT(t, pod.UID, *ownerRef.UID)
	require.EqualT(t, false, *ownerRef.Controller)
	require.EqualT(t, false, *ownerRef.BlockOwnerDeletion)
}
