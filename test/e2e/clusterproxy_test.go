// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

func TestClusterProxy(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "clusterproxy-prod",
			Namespace: netbirdNamespace,
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), serviceAccount))
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clusterproxy-prod",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"users", "groups"},
				Verbs:     []string{"impersonate"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"userextras/*", "uids"},
				Verbs:     []string{"impersonate"},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), clusterRole))
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clusterproxy-prod",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      serviceAccount.Name,
				Namespace: serviceAccount.Namespace,
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), clusterRoleBinding))
	clusterProxy := &nbv1alpha1.ClusterProxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prod",
			Namespace: netbirdNamespace,
		},
		Spec: nbv1alpha1.ClusterProxySpec{
			ClusterName:        "prod",
			ServiceAccountName: serviceAccount.Name,
			APIServer:          "https://kubernetes.default.svc.cluster.local/",
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), clusterProxy))

	require.Eventually(t, func(ctx context.Context) error {
		return e.workloadCurrent(ctx, "Deployment", clusterProxy.Namespace, "clusterproxy-"+clusterProxy.Name)
	}, 3*time.Minute, 2*time.Second)

	// Every proxy replica registers as its own peer carrying the cluster's
	// label. The account is shared with the other tests, so only the peers
	// carrying this label are counted.
	const dnsLabel = "prod.netbird-kubeapi-proxy.netbird.selfhosted"
	require.Eventually(t, func(ctx context.Context) error {
		peers, err := e.nb.Peers.List(ctx)
		if err != nil {
			return err
		}
		labelled := 0
		for _, peer := range peers {
			if slices.Equal(peer.ExtraDnsLabels, []string{dnsLabel}) {
				labelled++
			}
		}
		if labelled != 3 {
			return fmt.Errorf("%d of 3 proxy peers registered with the label %s", labelled, dnsLabel)
		}
		return nil
	}, 2*time.Minute, 2*time.Second)
}

// TestClusterProxyTolerations covers a cluster where only tainted nodes are left,
// such as the control plane after every worker went down: a ClusterProxy that
// tolerates the taint through its workload override still rolls out and joins.
//
// The test taints the cluster's only node, which would leave every other test's
// new pods unschedulable, so it does not call t.Parallel: parallel tests resume
// only after every sequential test has finished, and the taint is gone by then.
func TestClusterProxyTolerations(t *testing.T) {
	e := requireEnv(t)
	ns := e.createNamespace(t, "clusterproxy-tolerations")

	controlPlaneTaint := corev1.Taint{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}
	e.taintNodes(t, controlPlaneTaint)

	// A pod without the toleration has to stay unscheduled, or the taint proves
	// nothing about the proxy's toleration.
	untolerated := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "untolerated", Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.10"}},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), untolerated))
	require.Eventually(t, func(ctx context.Context) error {
		return podUnschedulable(ctx, e.k8s, client.ObjectKeyFromObject(untolerated))
	}, time.Minute, 2*time.Second)

	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "clusterproxy", Namespace: ns}}
	require.NoError(t, e.k8s.Create(t.Context(), serviceAccount))
	toleration := corev1.Toleration{
		Key:      controlPlaneTaint.Key,
		Operator: corev1.TolerationOpExists,
		Effect:   controlPlaneTaint.Effect,
	}
	clusterProxy := &nbv1alpha1.ClusterProxy{
		ObjectMeta: metav1.ObjectMeta{Name: "tainted", Namespace: ns},
		Spec: nbv1alpha1.ClusterProxySpec{
			ClusterName:        "tainted",
			ServiceAccountName: serviceAccount.Name,
			APIServer:          "https://kubernetes.default.svc.cluster.local/",
			WorkloadOverride: &nbv1alpha1.WorkloadOverride{
				Replicas: new(int32(1)),
				PodTemplate: &corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{Tolerations: []corev1.Toleration{toleration}},
				},
			},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), clusterProxy))

	require.Eventually(t, func(ctx context.Context) error {
		return e.workloadCurrent(ctx, "Deployment", ns, "clusterproxy-"+clusterProxy.Name)
	}, 3*time.Minute, 2*time.Second)

	pods := &corev1.PodList{}
	require.NoError(t, e.k8s.List(t.Context(), pods, client.InNamespace(ns),
		client.MatchingLabels{"app.kubernetes.io/name": "clusterproxy", "app.kubernetes.io/instance": clusterProxy.Name}))
	require.Len(t, pods.Items, 1, "the override sets one replica")
	assert.Contains(t, pods.Items[0].Spec.Tolerations, toleration, "the proxy pod carries the override's toleration")

	const dnsLabel = "tainted.netbird-kubeapi-proxy.netbird.selfhosted"
	require.Eventually(t, func(ctx context.Context) error {
		peers, err := e.nb.Peers.List(ctx)
		if err != nil {
			return err
		}
		for _, peer := range peers {
			if slices.Equal(peer.ExtraDnsLabels, []string{dnsLabel}) && peer.Connected {
				return nil
			}
		}
		return fmt.Errorf("no connected proxy peer with the label %s", dnsLabel)
	}, 2*time.Minute, 2*time.Second)
}

// taintNodes adds taint to every node that lacks it and removes it again when
// the test ends, leaving taints the nodes already had in place.
func (e *environment) taintNodes(t *testing.T, taint corev1.Taint) {
	t.Helper()
	matches := func(other corev1.Taint) bool { return taint.MatchTaint(&other) }
	nodes := &corev1.NodeList{}
	require.NoError(t, e.k8s.List(t.Context(), nodes))
	require.NotEmpty(t, nodes.Items, "the cluster has no nodes")
	for _, node := range nodes.Items {
		if slices.ContainsFunc(node.Spec.Taints, matches) {
			continue
		}
		require.NoError(t, e.updateNodeTaints(t.Context(), node.Name, func(taints []corev1.Taint) []corev1.Taint {
			return append(taints, taint)
		}))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			err := e.updateNodeTaints(ctx, node.Name, func(taints []corev1.Taint) []corev1.Taint {
				return slices.DeleteFunc(taints, matches)
			})
			if err != nil {
				t.Errorf("remove taint %s from node %s, later tests cannot schedule: %v", taint.Key, node.Name, err)
			}
		})
	}
}

// updateNodeTaints replaces a node's taints with what edit returns, retrying when
// the node changed underneath, which the node's own kubelet does all the time.
func (e *environment) updateNodeTaints(ctx context.Context, name string, edit func([]corev1.Taint) []corev1.Taint) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node := &corev1.Node{}
		if err := e.k8s.Get(ctx, client.ObjectKey{Name: name}, node); err != nil {
			return err
		}
		node.Spec.Taints = edit(node.Spec.Taints)
		return e.k8s.Update(ctx, node)
	})
}

// podUnschedulable reports whether the scheduler has given up placing a pod.
func podUnschedulable(ctx context.Context, c client.Client, key client.ObjectKey) error {
	pod := &corev1.Pod{}
	if err := c.Get(ctx, key, pod); err != nil {
		return err
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse && cond.Reason == corev1.PodReasonUnschedulable {
			return nil
		}
	}
	return fmt.Errorf("pod %s is not reported unschedulable, node %q", key, pod.Spec.NodeName)
}

// workloadCurrent reports whether a workload has rolled out, as kstatus
// computes it.
func (e *environment) workloadCurrent(ctx context.Context, kind, namespace, name string) error {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: kind})
	if err := e.k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, u); err != nil {
		return err
	}
	res, err := status.Compute(u)
	if err != nil {
		return err
	}
	if res.Status != status.CurrentStatus {
		return errors.New(res.Message)
	}
	return nil
}
