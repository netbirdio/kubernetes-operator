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
	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
