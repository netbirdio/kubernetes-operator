// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

// Drift: what happens when something other than the operator changes what it
// manages. Somebody deletes a resource in the dashboard, a script removes a DNS
// record, a cleanup job drops a network. The operator is meant to put each one
// back, and a controller that only ever creates passes every other test here
// and fails these.
//
// Each case removes an object behind the operator's back, makes the operator
// reconcile, and requires the object back on the server and the traffic it
// carries flowing again.

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nbv1alpha1 "github.com/netbirdio/kubernetes-operator/api/v1alpha1"
)

func TestNetworkDrift(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)
	fx := e.requireNetworkFixtures(t)
	ns := e.createNamespace(t, "drift")

	router := e.createRouter(t, ns, "router", 1)
	svc := e.createBackend(t, ns, "web")
	res := &nbv1alpha1.NetworkResource{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec: nbv1alpha1.NetworkResourceSpec{
			NetworkRouterRef: nbv1alpha1.CrossNamespaceReference{Name: router.Name, Namespace: ns},
			ServiceRef:       corev1.LocalObjectReference{Name: svc.Name},
			Groups:           []nbv1alpha1.GroupReference{{Name: new(resourcesGroup)}},
		},
	}
	require.NoError(t, e.k8s.Create(t.Context(), res))
	e.waitReady(t, res)
	url := fmt.Sprintf("http://%s.%s.%s:%d/hostname", svc.Name, ns, dnsZone, backendPort)
	requireReachable(t, fx.laptop, url, svc.Name+"-")

	t.Run("network resource deleted", func(t *testing.T) {
		old := res.Status.ResourceID
		require.NoError(t, e.nb.Networks.Resources(res.Status.NetworkID).Delete(t.Context(), old))
		e.touch(t, res)
		e.waitStatusChange(t, res, func() string { return res.Status.ResourceID }, old)
		_, err := e.nb.Networks.Resources(res.Status.NetworkID).Get(t.Context(), res.Status.ResourceID)
		require.NoError(t, err)
		requireReachable(t, fx.laptop, url, svc.Name+"-")
	})

	t.Run("DNS record deleted", func(t *testing.T) {
		old := res.Status.DNSRecordID
		require.NoError(t, e.nb.DNSZones.DeleteRecord(t.Context(), res.Status.DNSZoneID, old))
		requireUnreachable(t, fx.laptop, url)
		e.touch(t, res)
		e.waitStatusChange(t, res, func() string { return res.Status.DNSRecordID }, old)
		requireReachable(t, fx.laptop, url, svc.Name+"-")
	})

	t.Run("router deleted", func(t *testing.T) {
		old := router.Status.RoutingPeerID
		require.NoError(t, e.nb.Networks.Routers(router.Status.NetworkID).Delete(t.Context(), old))
		e.touch(t, router)
		e.waitStatusChange(t, router, func() string { return router.Status.RoutingPeerID }, old)
		requireReachable(t, fx.laptop, url, svc.Name+"-")
	})

	// Deleting a network takes its routers and resources with it, so putting it
	// back takes the router recreating the network and the resource following
	// the router into it.
	t.Run("network deleted", func(t *testing.T) {
		old := router.Status.NetworkID
		require.NoError(t, e.nb.Networks.Delete(t.Context(), old))
		requireUnreachable(t, fx.laptop, url)
		e.touch(t, router)
		e.waitStatusChange(t, router, func() string { return router.Status.NetworkID }, old)
		e.waitStatusChange(t, res, func() string { return res.Status.NetworkID }, old)
		requireReachable(t, fx.laptop, url, svc.Name+"-")
	})
}

// waitStatusChange waits until a status field read through field differs from
// old and is set, and leaves obj holding that state.
func (e *environment) waitStatusChange(t *testing.T, obj client.Object, field func() string, old string) {
	t.Helper()
	require.Eventually(t, func(ctx context.Context) error {
		if err := e.k8s.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		if v := field(); v == "" || v == old {
			return fmt.Errorf("%s still reports %q", obj.GetName(), old)
		}
		return nil
	}, readyTimeout, 2*time.Second)
}
