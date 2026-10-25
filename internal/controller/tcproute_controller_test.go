// SPDX-License-Identifier: BSD-3-Clause

package controller

import (
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// The envtest suite only installs the standard Gateway API channel, which has
// no TCPRoute, so the fake client stands in for the API server here.
func TestTCPRouteRoutesForGateway(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, gwv1.Install(scheme))
	require.NoError(t, gwv1alpha2.Install(scheme))

	gw := &gwv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "private", Namespace: "netbird"}}
	route := func(namespace, name string, parent gwv1.ParentReference) *gwv1alpha2.TCPRoute {
		return &gwv1alpha2.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: gwv1alpha2.TCPRouteSpec{
				CommonRouteSpec: gwv1.CommonRouteSpec{ParentRefs: []gwv1.ParentReference{parent}},
			},
		}
	}
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		gw,
		route("netbird", "same-namespace", gwv1.ParentReference{Name: "private"}),
		route("default", "cross-namespace", gwv1.ParentReference{Name: "private", Namespace: new(gwv1.Namespace("netbird"))}),
		// Names a Gateway of the same name in its own namespace, not this one.
		route("default", "own-namespace", gwv1.ParentReference{Name: "private"}),
		route("netbird", "other-gateway", gwv1.ParentReference{Name: "public"}),
	).Build()
	rec := &TCPRouteReconciler{Client: k8sClient}

	got := rec.routesForGateway(t.Context(), gw)
	assert.ElementsMatch(t, []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "netbird", Name: "same-namespace"}},
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "cross-namespace"}},
	}, got, "routes reconciled for a change to Gateway netbird/private")
}
