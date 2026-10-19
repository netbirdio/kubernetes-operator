// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	sidecarContainerName     = "netbird"
	sidecarProfileAnnotation = "netbird.io/sidecar-profile"
	// netbirdDNSDomain is the domain management gives peers when none is
	// configured, as in the harness deployment.
	netbirdDNSDomain = "netbird.selfhosted"
)

// TestSidecar injects the NetBird client into pods through SidecarProfiles, in
// both injection modes, and reaches an injected pod from the peer outside the
// cluster, by its NetBird IP and by the extra DNS label the profile gives it.
// The webhook runs with the chart's default failure policy, so a webhook that
// fails also fails the pod creation here.
func TestSidecar(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "sidecar")

	// The pods join the group the outside peer may reach.
	setupKey := &nbv1alpha1.SetupKey{
		ObjectMeta: metav1.ObjectMeta{Name: "sidecar", Namespace: ns},
		Spec: nbv1alpha1.SetupKeySpec{
			Name:                "e2e-sidecar-" + rand.String(6),
			Ephemeral:           true,
			AllowExtraDnsLabels: true,
			AutoGroups:          []nbv1alpha1.GroupReference{{Name: new(resourcesGroup)}},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), setupKey))
	e.waitReady(t, setupKey)

	label := "sidecar-" + rand.String(6)
	for _, profile := range []*nbv1alpha1.SidecarProfile{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "sidecar", Namespace: ns},
			Spec: nbv1alpha1.SidecarProfileSpec{
				SetupKeyRef:    corev1.LocalObjectReference{Name: setupKey.Name},
				PodSelector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "sidecar"}},
				ExtraDNSLabels: []string{label},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "container", Namespace: ns},
			Spec: nbv1alpha1.SidecarProfileSpec{
				SetupKeyRef:   corev1.LocalObjectReference{Name: setupKey.Name},
				PodSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{"app": "container"}},
				InjectionMode: nbv1alpha1.InjectionModeContainer,
			},
		},
	} {
		require.NoError(t, e.k8s.Create(t.Context(), profile))
	}

	t.Run("sidecar mode", func(t *testing.T) {
		e.createBackend(t, ns, "sidecar")
		pod := e.onlyPod(t, ns, "sidecar")
		assert.EqualT(t, "sidecar", pod.Annotations[sidecarProfileAnnotation], "profile annotation")
		idx := slices.IndexFunc(pod.Spec.InitContainers, func(c corev1.Container) bool { return c.Name == sidecarContainerName })
		require.NotEqual(t, -1, idx, "no %s init container was injected", sidecarContainerName)
		require.NotNil(t, pod.Spec.InitContainers[idx].RestartPolicy, "the sidecar has no restart policy")
		assert.EqualT(t, corev1.ContainerRestartPolicyAlways, *pod.Spec.InitContainers[idx].RestartPolicy,
			"a native sidecar restarts always")

		peer := e.waitPeerWithLabel(t, label)
		assert.TrueT(t, slices.Contains(groupIDs(peer.Groups), fx.resourcesGroupID), "the pod joined the setup key's auto-group")
		requireReachable(t, fx.laptop, fmt.Sprintf("http://%s:%d/hostname", peer.Ip, backendPort), pod.Name)
		requireReachable(t, fx.laptop, fmt.Sprintf("http://%s.%s:%d/hostname", label, netbirdDNSDomain, backendPort), pod.Name)
	})

	t.Run("container mode", func(t *testing.T) {
		e.createBackend(t, ns, "container")
		pod := e.onlyPod(t, ns, "container")
		assert.EqualT(t, "container", pod.Annotations[sidecarProfileAnnotation], "profile annotation")
		assert.TrueT(t, slices.ContainsFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == sidecarContainerName }),
			"no %s container was injected", sidecarContainerName)
	})

	t.Run("no matching profile", func(t *testing.T) {
		e.createBackend(t, ns, "plain")
		pod := e.onlyPod(t, ns, "plain")
		assert.Empty(t, pod.Annotations[sidecarProfileAnnotation], "profile annotation on a pod no profile selects")
		containers := slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers)
		assert.FalseT(t, slices.ContainsFunc(containers, func(c corev1.Container) bool { return c.Name == sidecarContainerName }),
			"a pod no profile selects was injected")
	})
}

// onlyPod returns the single pod of a backend created by createBackend.
func (e *environment) onlyPod(t *testing.T, namespace, app string) corev1.Pod {
	t.Helper()
	pods := &corev1.PodList{}
	require.NoError(t, e.k8s.List(t.Context(), pods, client.InNamespace(namespace), client.MatchingLabels{"app": app}))
	require.Len(t, pods.Items, 1, "pods of %s", app)
	return pods.Items[0]
}

// waitPeerWithLabel waits for a connected peer carrying the extra DNS label.
func (e *environment) waitPeerWithLabel(t *testing.T, label string) api.Peer {
	t.Helper()
	var peer api.Peer
	require.Eventually(t, func(ctx context.Context) error {
		peers, err := e.nb.Peers.List(ctx)
		if err != nil {
			return err
		}
		idx := slices.IndexFunc(peers, func(p api.Peer) bool { return slices.Contains(p.ExtraDnsLabels, label) })
		if idx == -1 {
			return fmt.Errorf("no peer carries the label %s", label)
		}
		if !peers[idx].Connected {
			return fmt.Errorf("peer %s with the label %s is not connected", peers[idx].Name, label)
		}
		peer = peers[idx]
		return nil
	}, readyTimeout, 2*time.Second)
	return peer
}
